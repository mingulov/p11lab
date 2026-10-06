/* SPDX-License-Identifier: Apache-2.0
 * P11Lab original provisioning and Linux child supervision for the tpm2
 * provider. Upstream swtpm, dbus-daemon, tpm2-abrmd, tpm2-tools, the
 * tpm2-pkcs11 module and tpm2_ptool are invoked unmodified with pinned
 * arguments; their return values and errors are preserved, never
 * normalized. No PKCS#11 login happens here: readiness proves the full
 * TPM path with a pre-login C_GenerateRandom round-trip.
 */
#define _GNU_SOURCE
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SWTPM "/usr/bin/swtpm"
#define DBUS_DAEMON "/usr/bin/dbus-daemon"
#define ABRMD "/usr/sbin/tpm2-abrmd"
#define DBUS_SEND "/usr/bin/dbus-send"
#define PYTHON "/usr/bin/python3"
#define WRAPPER "/usr/local/bin/p11lab-tpm2-ptool"
#define TPM2_MULTICALL "/usr/bin/tpm2"
/* Dictionary-attack budget: worst-case measured suite spend is one DA try
 * per operation that performs PKCS#11 authentication (the first Load after
 * each daemon bring-up draws TPM_RC_RETRY, silently resubmitted by libtss2
 * but counted by swtpm) plus one per wrong-PIN attempt. 64 covers the
 * acceptance suite with headroom while keeping lockout reachable. The two
 * recovery values are the observed swtpm defaults, passed explicitly. */
#define DA_MAX_TRIES "64"
#define DA_RECOVERY_TIME "1000"
#define DA_LOCKOUT_RECOVERY "1000"
#define CONTROL "/run/p11lab/tpm2"
#define CONF "/etc/p11lab/tpm2/dbus.conf"
#define BUSDIR CONTROL "/bus"
#define SOCKET BUSDIR "/system_bus_socket"
/* Canonical bus address, guidless and static: the daemon config pins the
 * socket path, so the per-boot guid printed for readiness is discarded.
 * This is also the provider-declared checker-grandchild transport. */
#define BUS_ADDRESS "unix:path=" SOCKET
#define LOGDIR CONTROL "/logs"
#define OWNED "/var/lib/p11lab/tpm2"
#define LEASE OWNED "/lease"
#define STORE OWNED "/store"
#define TPMSTATE OWNED "/tpmstate"
#define TCTI "tabrmd:bus_type=system"
#define LOG_BOUND 65536
static volatile sig_atomic_t stopping;

static void on_signal(int sig) { stopping = sig; }
static void pause_poll(void)
{
    struct timespec delay = {0, 50000000};
    (void)nanosleep(&delay, NULL);
}
static int report(const char *op, CK_RV rv)
{
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", op, rv);
    return 1;
}
static void erase(unsigned char *p, size_t length)
{
    volatile unsigned char *v = p;
    while (length--) *v++ = 0;
}
/* Bounded stdin record: user LF so, each 1..4096 bytes, no CR/NUL/LF inside. */
static int secrets(unsigned char *user, size_t *ulen, unsigned char *so, size_t *slen)
{
    static unsigned char input[8193];
    size_t length = 0;
    ssize_t n = 0;
    unsigned char *separator;
    int bad = 1;
    memset(input, 0, sizeof(input));
    while ((n = read(STDIN_FILENO, input + length, sizeof(input) - length)) > 0) {
        length += (size_t)n;
        if (length == sizeof(input)) break;
    }
    close(STDIN_FILENO);
    separator = memchr(input, '\n', length);
    if (n >= 0 && length < sizeof(input) && separator && !memchr(separator + 1, '\n', length - (size_t)(separator + 1 - input))) {
        *ulen = (size_t)(separator - input);
        *slen = length - *ulen - 1;
        if (*ulen >= 1 && *ulen <= 4096 && *slen >= 1 && *slen <= 4096 &&
            !memchr(input, '\r', length) && !memchr(input, '\0', length)) {
            memcpy(user, input, *ulen); memcpy(so, separator + 1, *slen);
            bad = 0;
        }
    }
    erase(input, sizeof(input));
    return bad;
}

static int native(int quiet, int *slot_id, int *present_index, unsigned *objects)
{
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slots[16], found = 0;
    CK_ULONG count = 0, n = 16, mechanisms = 0;
    CK_TOKEN_INFO info;
    CK_MECHANISM_TYPE list[64];
    CK_BYTE padded[32], random_bytes[16];
    CK_OBJECT_HANDLE handles[64];
    CK_ULONG got = 0;
    const char *module = getenv("P11LAB_MODULE"), *label = getenv("P11LAB_LABEL");
    void *handle = NULL, *symbol;
    CK_RV rv;
    int initialized = 0, status = 1, have = 0;
    unsigned have_ec = 0, have_ecgen = 0, have_rsa = 0;
    if (!module || !label || strlen(label) > sizeof(padded)) return 2;
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, label, strlen(label));
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-tpm2: cannot load module\n", stderr); goto out; }
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get), "function pointer ABI");
    memcpy(&get, &symbol, sizeof(get));
    if (!get) goto out;
    rv = get(&f);
    if (rv || !f) { report("C_GetFunctionList", rv); goto out; }
    rv = f->C_Initialize(NULL);
    if (rv) { report("C_Initialize", rv); goto out; }
    initialized = 1;
    rv = f->C_GetSlotList(CK_TRUE, NULL, &count);
    if (rv) { report("C_GetSlotList", rv); goto out; }
    if (count > 16) { fputs("p11lab-tpm2: slot list exceeds bound\n", stderr); goto out; }
    n = count;
    rv = f->C_GetSlotList(CK_TRUE, slots, &n);
    if (rv) { report("C_GetSlotList", rv); goto out; }
    for (CK_ULONG i = 0; i < n; i++) {
        rv = f->C_GetTokenInfo(slots[i], &info);
        if (rv) { report("C_GetTokenInfo", rv); goto out; }
        if (!memcmp(info.label, padded, sizeof(padded))) {
            found = slots[i];
            *present_index = (int)i;
            have = 1;
            break;
        }
    }
    if (!have) { fputs("p11lab-tpm2: labelled token not present\n", stderr); goto out; }
    *slot_id = (int)found;
    if (info.flags != 0x40d) {
        fprintf(stderr, "p11lab-tpm2: token flags=0x%lx, want 0x40d\n", (unsigned long)info.flags);
        goto out;
    }
    mechanisms = 64;
    rv = f->C_GetMechanismList(found, list, &mechanisms);
    if (rv) { report("C_GetMechanismList", rv); goto out; }
    for (CK_ULONG i = 0; i < mechanisms; i++) {
        CK_MECHANISM_INFO details;
        if (list[i] != 0x1041 && list[i] != 0x1040 && list[i] != 0x0) continue;
        rv = f->C_GetMechanismInfo(found, list[i], &details);
        if (rv) { report("C_GetMechanismInfo", rv); goto out; }
        if (list[i] == 0x1041 && (details.flags & 0x800)) have_ec = 1;
        if (list[i] == 0x1040 && (details.flags & 0x10000)) have_ecgen = 1;
        if (list[i] == 0x0) have_rsa = 1;
    }
    if (!have_ec || !have_ecgen || !have_rsa) {
        fputs("p11lab-tpm2: required mechanisms unavailable\n", stderr);
        goto out;
    }
    rv = f->C_OpenSession(found, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv) { report("C_OpenSession", rv); goto out; }
    /* Pre-login TPM round-trip through the supervised tabrmd path. */
    rv = f->C_GenerateRandom(session, random_bytes, sizeof(random_bytes));
    if (rv) { report("C_GenerateRandom", rv); goto out; }
    erase(random_bytes, sizeof(random_bytes));
    rv = f->C_FindObjectsInit(session, NULL, 0);
    if (rv) { report("C_FindObjectsInit", rv); goto out; }
    *objects = 0;
    for (;;) {
        CK_RV step = f->C_FindObjects(session, handles, 64, &got);
        /* A mid-enumeration error is a native failure, never
         * end-of-data: report it instead of hiding it. */
        if (step != CKR_OK) {
            report("C_FindObjects", step);
            rv = f->C_FindObjectsFinal(session);
            if (rv) report("C_FindObjectsFinal", rv);
            goto out;
        }
        if (got == 0) break;
        if (got > 64) { report("C_FindObjects", CKR_GENERAL_ERROR); goto out; }
        *objects += (unsigned)got;
    }
    rv = f->C_FindObjectsFinal(session);
    if (rv) { report("C_FindObjectsFinal", rv); goto out; }
    if (!quiet)
        printf("ready: native_slot=%d token_present_index=%d label=%s objects=%u\n",
               *slot_id, *present_index, label, *objects);
    status = 0;
out:
    if (session != CK_INVALID_HANDLE) {
        rv = f->C_CloseSession(session);
        if (rv) status = report("C_CloseSession", rv);
    }
    if (initialized) {
        rv = f->C_Finalize(NULL);
        if (rv) status = report("C_Finalize", rv);
    }
    if (handle) dlclose(handle);
    return status;
}

static int child_code(int status)
{
    return WIFEXITED(status) ? WEXITSTATUS(status) :
           WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
}
static int protected_file(int fd)
{
    struct stat s;
    return fd >= 0 && !fstat(fd, &s) && S_ISREG(s.st_mode) &&
           s.st_uid == getuid() && s.st_nlink == 1 && (s.st_mode & 0777) == 0600;
}
static int log_bounded(const char *path)
{
    struct stat s;
    return !lstat(path, &s) && (!S_ISREG(s.st_mode) || s.st_size > LOG_BOUND);
}
static void show_log(const char *path)
{
    char buf[4096];
    ssize_t n;
    size_t left = LOG_BOUND;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    while (left && (n = read(fd, buf, left < sizeof(buf) ? left : sizeof(buf))) > 0) {
        (void)fwrite(buf, 1, (size_t)n, stderr);
        left -= (size_t)n;
    }
    close(fd);
}
static int finish_child(pid_t pid, int group)
{
    int status;
    if (pid <= 0) return 0;
    if (waitpid(pid, &status, WNOHANG) == pid) return 0;
    (void)kill(group ? -pid : pid, SIGTERM);
    for (int i = 0; i < 100; i++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid || (r < 0 && errno == ECHILD)) return 0;
        pause_poll();
    }
    fputs("p11lab-tpm2: shutdown grace expired; killing owned child\n", stderr);
    (void)kill(group ? -pid : pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 1;
}
/* Spawn a service with stdout/stderr appended to its bounded log file. */
static pid_t spawn_service(char *const argv[], const char *logpath, const char *pidpath, int addr_fd)
{
    int log = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    pid_t child;
    if (log < 0) return -1;
    child = fork();
    if (child < 0) { close(log); return -1; }
    if (child == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (addr_fd >= 0 && addr_fd != 3) {
            if (dup2(addr_fd, 3) < 0) _exit(127);
            close(addr_fd);
        }
        if (devnull >= 0) { (void)dup2(devnull, STDIN_FILENO); close(devnull); }
        if (dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0) _exit(127);
        close(log);
        execv(argv[0], argv);
        _exit(127);
    }
    close(log);
    if (pidpath) {
        char text[32];
        int fd, length = snprintf(text, sizeof(text), "%ld\n", (long)child);
        fd = open(pidpath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0 || write(fd, text, (size_t)length) != length) {
            if (fd >= 0) close(fd);
            (void)finish_child(child, 0);
            return -1;
        }
        close(fd);
    }
    return child;
}
static int tcp_accept(int port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int done = 0;
    if (fd < 0) return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((in_port_t)port);
    addr.sin_addr.s_addr = 0x0100007f;
    if (!connect(fd, (struct sockaddr *)&addr, sizeof(addr))) done = 1;
    close(fd);
    return done;
}
/* Short-lived dbus-send ListNames probe; proves abrmd owns its bus name. */
static int bus_roundtrip(void)
{
    int out[2], status = 1;
    pid_t child;
    char buf[4096];
    size_t total = 0;
    ssize_t n;
    if (pipe(out)) return 0;
    child = fork();
    if (child < 0) { close(out[0]); close(out[1]); return 0; }
    if (child == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { (void)dup2(devnull, STDIN_FILENO); close(devnull); }
        if (dup2(out[1], STDOUT_FILENO) < 0) _exit(127);
        close(out[0]); close(out[1]);
        execl(DBUS_SEND, DBUS_SEND, "--system", "--print-reply",
              "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
              "org.freedesktop.DBus.ListNames", (char *)NULL);
        _exit(127);
    }
    close(out[1]);
    for (;;) {
        struct pollfd watched = {out[0], POLLIN, 0};
        int ready = poll(&watched, 1, 10000);
        if (stopping) break;
        if (ready <= 0) break;
        n = read(out[0], buf + total, sizeof(buf) - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
        if (total >= sizeof(buf) - 1) break;
    }
    close(out[0]);
    buf[total] = 0;
    if (waitpid(child, &status, 0) < 0) return 0;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) return 0;
    return strstr(buf, "com.intel.tss2.Tabrmd") != NULL;
}
/* Run the argv-free p11lab-tpm2-ptool driver. Secrets travel on a private
 * stdin pipe for addtoken; init takes none. Bounded at 300 seconds. */
static int run_wrapper(const char *op, const char *label, const unsigned char *record, size_t record_len)
{
    int out = open(LOGDIR "/provision.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    int in[2] = {-1, -1};
    pid_t child;
    int status = 1;
    if (out < 0) return 1;
    if (record && pipe(in)) { close(out); return 1; }
    child = fork();
    if (child < 0) {
        close(out);
        if (in[0] >= 0) { close(in[0]); close(in[1]); }
        return 1;
    }
    if (child == 0) {
        if (record) {
            close(in[1]);
            if (dup2(in[0], STDIN_FILENO) < 0) _exit(127);
            close(in[0]);
        } else {
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) { (void)dup2(devnull, STDIN_FILENO); close(devnull); }
        }
        if (dup2(out, STDOUT_FILENO) < 0 || dup2(out, STDERR_FILENO) < 0) _exit(127);
        close(out);
        if (!strcmp(op, "init"))
            execl(PYTHON, PYTHON, WRAPPER, "init", STORE, (char *)NULL);
        else
            execl(PYTHON, PYTHON, WRAPPER, "addtoken", STORE, label, (char *)NULL);
        _exit(127);
    }
    close(out);
    if (record) {
        size_t written = 0;
        close(in[0]);
        while (written < record_len) {
            ssize_t n = write(in[1], record + written, record_len - written);
            if (n <= 0) break;
            written += (size_t)n;
        }
        close(in[1]);
        if (written != record_len) { (void)finish_child(child, 0); return 1; }
    }
    for (int i = 0; i < 6000 && !stopping; i++) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) return child_code(status);
        if (r < 0 && errno == ECHILD) return 1;
        pause_poll();
    }
    fputs("p11lab-tpm2: provisioning bound expired\n", stderr);
    (void)finish_child(child, 0);
    return 1;
}
/* Set the dictionary-attack parameters once per token lifetime through the
 * frozen tpm2 multicall. No secrets involved; output joins provision.log.
 * Bounded at 120 seconds; any failure fails init. */
static int run_da_setup(void)
{
    int out = open(LOGDIR "/provision.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    pid_t child;
    int status = 1;
    if (out < 0) return 1;
    child = fork();
    if (child < 0) { close(out); return 1; }
    if (child == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { (void)dup2(devnull, STDIN_FILENO); close(devnull); }
        if (dup2(out, STDOUT_FILENO) < 0 || dup2(out, STDERR_FILENO) < 0) _exit(127);
        close(out);
        execl(TPM2_MULTICALL, TPM2_MULTICALL, "dictionarylockout", "--setup-parameters",
              "--max-tries=" DA_MAX_TRIES, "--recovery-time=" DA_RECOVERY_TIME,
              "--lockout-recovery=" DA_LOCKOUT_RECOVERY, (char *)NULL);
        _exit(127);
    }
    close(out);
    for (int i = 0; i < 2400 && !stopping; i++) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) return child_code(status);
        if (r < 0 && errno == ECHILD) return 1;
        pause_poll();
    }
    fputs("p11lab-tpm2: DA provisioning bound expired\n", stderr);
    (void)finish_child(child, 0);
    return 1;
}
static pid_t fork_native(int quiet)
{
    pid_t child = fork();
    if (child == 0) {
        int slot_id = 0, present = 0;
        unsigned objects = 0;
        int status;
        (void)setpgid(0, 0);
        if (quiet && !freopen("/dev/null", "w", stdout)) _exit(1);
        status = native(quiet, &slot_id, &present, &objects);
        exit(status);
    }
    if (child > 0) (void)setpgid(child, child);
    return child;
}
static int monitor(pid_t child, pid_t *services, const char *const *names, int count)
{
    int status;
    for (;;) {
        for (int i = 0; i < count; i++) {
            if (services[i] <= 0) continue;
            if (waitpid(services[i], &status, WNOHANG) == services[i]) {
                fprintf(stderr, "p11lab-tpm2: required %s exited during operation\n", names[i]);
                services[i] = -1;
                (void)finish_child(child, 1);
                return 1;
            }
        }
        if (stopping || log_bounded(LOGDIR "/swtpm.log") || log_bounded(LOGDIR "/dbus.log") ||
            log_bounded(LOGDIR "/abrmd.log") || log_bounded(LOGDIR "/provision.log")) {
            if (!stopping) fputs("p11lab-tpm2: service log exceeded bound\n", stderr);
            (void)finish_child(child, 1);
            return stopping ? 128 + stopping : 1;
        }
        if (waitpid(child, &status, WNOHANG) == child) return child_code(status);
        pause_poll();
    }
}
static int finish_adopted(void)
{
    char path[100];
    FILE *file;
    long pid;
    int result = 0;
    snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    file = fopen(path, "r");
    if (!file) return 1;
    while (fscanf(file, "%ld", &pid) == 1)
        if (pid > 1 && finish_child((pid_t)pid, 0)) result = 1;
    fclose(file);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    return result;
}
static int read_address(int fd, pid_t dbus, char *text, size_t capacity)
{
    /* dbus-daemon --nofork --print-address=3 keeps fd 3 open for life, so
     * EOF never arrives: poll for the first line, bounded at 20 seconds,
     * failing fast when the daemon exits before printing its address. */
    size_t total = 0;
    ssize_t n;
    for (int i = 0; i < 200 && !stopping; i++) {
        struct pollfd watched = {fd, POLLIN, 0};
        int ready = poll(&watched, 1, 100);
        if (ready < 0) return 0;
        if (!ready) {
            if (waitpid(dbus, NULL, WNOHANG) == dbus) return 0;
            continue;
        }
        n = read(fd, text + total, capacity - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
        if (memchr(text, '\n', total) || total >= capacity - 1) break;
    }
    text[total] = 0;
    {
        char *end = strchr(text, '\n');
        if (end) *end = 0;
    }
    return total > 0 && !strncmp(text, "unix:path=", 10);
}

int main(int argc, char **argv)
{
    static unsigned char user[4097], so[4097], record[8193];
    static char address[4096];
    size_t ulen = 0, slen = 0, record_len = 0;
    pid_t services[3] = {-1, -1, -1};
    const char *names[3] = {"swtpm", "dbus-daemon", "tpm2-abrmd"};
    char state_arg[4096], ctrl_arg[64], server_arg[64];
    char *swtpm_argv[14], *dbus_argv[7], *abrmd_argv[6];
    pid_t child = -1;
    int status = 1, lease = -1, service = -1, addr_pipe[2] = {-1, -1};
    struct stat s;
    struct sigaction action;
    const char *mode, *label;
    if (argc < 2 || (strcmp(argv[1], "init") && strcmp(argv[1], "health") && strcmp(argv[1], "exec")) ||
        (!strcmp(argv[1], "exec") ? argc < 3 : argc != 2)) return 2;
    mode = argv[1];
    umask(077);
    label = getenv("P11LAB_LABEL");
    if (!label || !label[0] || strlen(label) > 32) return 2;
    if (!strcmp(mode, "init")) {
        if (secrets(user, &ulen, so, &slen)) goto out;
        memcpy(record, user, ulen);
        record[ulen] = '\n';
        memcpy(record + ulen + 1, so, slen);
        record_len = ulen + 1 + slen;
        erase(user, sizeof(user)); erase(so, sizeof(so));
    }
    lease = open(LEASE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (!protected_file(lease) || flock(lease, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-tpm2: state is unsafe or already in use\n", stderr); goto out;
    }
    service = open(CONTROL "/service-lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (!protected_file(service) || flock(service, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-tpm2: control directory is unsafe or already in use\n", stderr); goto out;
    }
    if (!lstat(CONTROL "/swtpm.pid", &s) || !lstat(CONTROL "/dbus.pid", &s) ||
        !lstat(CONTROL "/abrmd.pid", &s) || !lstat(SOCKET, &s)) {
        fputs("p11lab-tpm2: occupied daemon control state\n", stderr); goto out;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) goto out;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) goto out;
    if (pipe(addr_pipe)) goto out;
    snprintf(state_arg, sizeof(state_arg), "dir=%s", TPMSTATE);
    /* Loopback-bind both swtpm TCP listeners (verified against the shipped
     * swtpm 0.7.x --ctrl/--server type=tcp bindaddr sub-option): only the
     * co-resident abrmd reaches the TPM; bridge neighbors cannot. */
    snprintf(ctrl_arg, sizeof(ctrl_arg), "type=tcp,port=2322,bindaddr=127.0.0.1");
    snprintf(server_arg, sizeof(server_arg), "type=tcp,port=2321,bindaddr=127.0.0.1");
    swtpm_argv[0] = SWTPM; swtpm_argv[1] = "socket"; swtpm_argv[2] = "--tpm2";
    swtpm_argv[3] = "--tpmstate"; swtpm_argv[4] = state_arg;
    swtpm_argv[5] = "--ctrl"; swtpm_argv[6] = ctrl_arg;
    swtpm_argv[7] = "--server"; swtpm_argv[8] = server_arg;
    swtpm_argv[9] = "--flags"; swtpm_argv[10] = "startup-clear";
    swtpm_argv[11] = "--log"; swtpm_argv[12] = "level=0";
    swtpm_argv[13] = NULL;
    services[0] = spawn_service(swtpm_argv, LOGDIR "/swtpm.log", CONTROL "/swtpm.pid", -1);
    if (services[0] <= 0) goto cleanup;
    dbus_argv[0] = DBUS_DAEMON; dbus_argv[1] = "--config-file"; dbus_argv[2] = CONF;
    dbus_argv[3] = "--nopidfile"; dbus_argv[4] = "--nofork"; dbus_argv[5] = "--print-address=3";
    dbus_argv[6] = NULL;
    services[1] = spawn_service(dbus_argv, LOGDIR "/dbus.log", CONTROL "/dbus.pid", addr_pipe[1]);
    close(addr_pipe[1]);
    addr_pipe[1] = -1;
    if (services[1] <= 0) goto cleanup;
    if (!read_address(addr_pipe[0], services[1], address, sizeof(address))) {
        fputs("p11lab-tpm2: dbus address not ready\n", stderr);
        if (waitpid(services[1], NULL, WNOHANG) != 0) services[1] = -1;
        goto cleanup;
    }
    close(addr_pipe[0]);
    addr_pipe[0] = -1;
    if (strncmp(address, BUS_ADDRESS, sizeof(BUS_ADDRESS) - 1)) {
        fputs("p11lab-tpm2: dbus address does not match the pinned socket\n", stderr);
        goto cleanup;
    }
    erase((unsigned char *)address, sizeof(address));
    if (setenv("DBUS_SYSTEM_BUS_ADDRESS", BUS_ADDRESS, 1) || setenv("TPM2_PKCS11_TCTI", TCTI, 1) ||
        setenv("TPM2TOOLS_TCTI", TCTI, 1) || setenv("TPM2_PKCS11_STORE", STORE, 1)) goto cleanup;
    abrmd_argv[0] = ABRMD; abrmd_argv[1] = "--tcti=swtpm:host=127.0.0.1,port=2321";
    abrmd_argv[2] = "--max-transients=100"; abrmd_argv[3] = "--max-sessions=4";
    abrmd_argv[4] = "--allow-root"; abrmd_argv[5] = NULL;
    services[2] = spawn_service(abrmd_argv, LOGDIR "/abrmd.log", CONTROL "/abrmd.pid", -1);
    if (services[2] <= 0) goto cleanup;
    /* Readiness ladder: TCP accept, then bus round-trip proving abrmd owns
     * its name, then the native pre-login TPM round-trip. Bounded. */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !stopping; i++) {
            int code;
            pid_t r;
            for (int k = 0; k < 3; k++) {
                r = waitpid(services[k], &code, WNOHANG);
                if (r == services[k]) {
                    fprintf(stderr, "p11lab-tpm2: required %s exited during startup\n", names[k]);
                    services[k] = -1;
                    goto cleanup;
                }
            }
            if (tcp_accept(2321) && tcp_accept(2322) && bus_roundtrip()) {
                ready = 1;
                break;
            }
            pause_poll();
        }
        if (!ready || stopping) {
            if (!stopping) fputs("p11lab-tpm2: service startup not ready\n", stderr);
            goto cleanup;
        }
    }
    if (!strcmp(mode, "init")) {
        if (run_wrapper("init", label, NULL, 0)) {
            fputs("p11lab-tpm2: native store init failed\n", stderr); goto cleanup;
        }
        if (run_wrapper("addtoken", label, record, record_len)) {
            fputs("p11lab-tpm2: native token provisioning failed\n", stderr); goto cleanup;
        }
        erase(record, sizeof(record));
        record_len = 0;
        if (run_da_setup()) {
            fputs("p11lab-tpm2: DA provisioning failed\n", stderr); goto cleanup;
        }
    }
    child = fork_native(!strcmp(mode, "exec"));
    if (child < 0) goto cleanup;
    status = monitor(child, services, names, 3);
    if (status || strcmp(mode, "exec")) goto cleanup;
    child = fork();
    if (child < 0) { status = 1; goto cleanup; }
    if (child == 0) {
        (void)setpgid(0, 0);
        execvp(argv[2], &argv[2]);
        perror("p11lab-tpm2: application exec");
        _exit(127);
    }
    (void)setpgid(child, child);
    status = monitor(child, services, names, 3);
cleanup:
    erase(record, sizeof(record));
    erase(user, sizeof(user)); erase(so, sizeof(so));
    if (addr_pipe[0] >= 0) close(addr_pipe[0]);
    if (addr_pipe[1] >= 0) close(addr_pipe[1]);
    /* Reverse-order shutdown: resource manager, bus, emulator. */
    if (services[2] > 0 && finish_child(services[2], 0)) status = 1;
    if (services[1] > 0 && finish_child(services[1], 0)) status = 1;
    if (services[0] > 0 && finish_child(services[0], 0)) status = 1;
    if (finish_adopted()) status = 1;
    (void)unlink(CONTROL "/swtpm.pid"); (void)unlink(CONTROL "/dbus.pid");
    (void)unlink(CONTROL "/abrmd.pid"); (void)unlink(SOCKET);
    if (status) {
        show_log(LOGDIR "/swtpm.log"); show_log(LOGDIR "/dbus.log");
        show_log(LOGDIR "/abrmd.log"); show_log(LOGDIR "/provision.log");
    }
out:
    erase(record, sizeof(record));
    erase(user, sizeof(user)); erase(so, sizeof(so));
    if (service >= 0) close(service);
    if (lease >= 0) close(lease);
    return stopping ? 128 + stopping : status;
}
