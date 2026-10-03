/* SPDX-License-Identifier: Apache-2.0
 * P11Lab original provisioning and Linux child supervision. OpenCryptoki's
 * native daemon fork, return values and token format are left intact.
 * The build-only p11-kit header has its own permissive copying notice.
 */
#define _GNU_SOURCE
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DAEMON "/usr/local/sbin/pkcsslotd"
#define CONTROL "/run/p11lab/opencryptoki"
#define PIDFILE CONTROL "/pkcsslotd.pid"
#define SOCKET CONTROL "/pkcsslotd.socket"
#define LOGFILE CONTROL "/logs/pkcsslotd.log"
#define LEASE "/var/lib/p11lab/opencryptoki/lease"
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
static int secrets(unsigned char *pin, size_t *plen, unsigned char *so, size_t *slen)
{
    unsigned char input[18] = {0}, *separator;
    size_t length = 0;
    ssize_t n = 0;
    int bad = 1;
    while ((n = read(STDIN_FILENO, input + length, sizeof(input) - length)) > 0) {
        length += (size_t)n;
        if (length == sizeof(input)) break;
    }
    close(STDIN_FILENO);
    separator = memchr(input, '\n', length);
    if (n >= 0 && length < sizeof(input) && separator) {
        *plen = (size_t)(separator - input);
        *slen = length - *plen - 1;
        if (*plen >= 4 && *plen <= 8 && *slen >= 4 && *slen <= 8) {
            memcpy(pin, input, *plen); memcpy(so, separator + 1, *slen);
            bad = 0;
        }
    }
    erase(input, sizeof(input));
    return bad;
}

static int native(const char *mode, unsigned char *pin, size_t plen,
                  unsigned char *so, size_t slen)
{
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slot = 0;
    CK_ULONG count = 1;
    CK_TOKEN_INFO info;
    CK_BYTE padded[32], factory[] = "87654321";
    const char *module = getenv("P11LAB_MODULE"), *label = getenv("P11LAB_LABEL");
    void *handle = NULL, *symbol;
    CK_RV rv;
    int initialized = 0, status = 1;
    if (!module || !label || strlen(label) > sizeof(padded)) return 2;
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, label, strlen(label));
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-opencryptoki: cannot load module\n", stderr); goto out; }
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
    if (rv || count != 1) { report("C_GetSlotList", rv); goto out; }
    rv = f->C_GetSlotList(CK_TRUE, &slot, &count);
    if (rv || count != 1 || slot != 0) { report("C_GetSlotList", rv); goto out; }
    rv = f->C_GetTokenInfo(slot, &info);
    if (rv) { report("C_GetTokenInfo", rv); goto out; }
    if (!strcmp(mode, "init")) {
        if (info.flags & CKF_TOKEN_INITIALIZED) {
            fputs("p11lab-opencryptoki: refusing to reset initialized token\n", stderr);
            goto out;
        }
        /* Fresh SWToken authenticates C_InitToken against its factory SO PIN;
         * C_SetPIN subsequently replaces it with the caller-selected value.
         * This is the native provisioning sequence, not a failed-call retry.
         */
        rv = f->C_InitToken(slot, factory, 8, padded);
        if (rv) { report("C_InitToken", rv); goto out; }
        rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
        if (rv) { report("C_OpenSession", rv); goto out; }
        rv = f->C_Login(session, CKU_SO, factory, 8);
        if (rv) { report("C_Login(SO)", rv); goto out; }
        rv = f->C_SetPIN(session, factory, 8, so, (CK_ULONG)slen);
        if (rv) { report("C_SetPIN(SO)", rv); goto out; }
        rv = f->C_InitPIN(session, pin, (CK_ULONG)plen);
        if (rv) { report("C_InitPIN", rv); goto out; }
        rv = f->C_Logout(session);
        if (rv) { report("C_Logout", rv); goto out; }
        rv = f->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
        if (rv) { report("C_CloseSession", rv); goto out; }
        rv = f->C_GetTokenInfo(slot, &info);
        if (rv) { report("C_GetTokenInfo", rv); goto out; }
    }
    if ((info.flags & (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED)) !=
        (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED) ||
        (info.flags & (CKF_SO_PIN_TO_BE_CHANGED | CKF_USER_PIN_TO_BE_CHANGED)) ||
        memcmp(info.label, padded, sizeof(padded))) {
        fputs("p11lab-opencryptoki: initialized SWToken is not ready\n", stderr);
        goto out;
    }
    printf("ready: native_slot=0 token_present_index=0 label=%s\n", label);
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
static pid_t daemon_pid(void)
{
    char text[40], path[80], line[100], extra;
    long number, parent = -1;
    int fd = open(PIDFILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat s;
    ssize_t n;
    FILE *file;
    if (fd < 0) return -1;
    if (fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_uid != getuid()) { close(fd); return -1; }
    n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0) return -1;
    text[n] = 0;
    if (sscanf(text, "%ld %c", &number, &extra) != 1 || number <= 1) return -1;
    snprintf(path, sizeof(path), "/proc/%ld/status", number);
    file = fopen(path, "r");
    if (!file) return -1;
    while (fgets(line, sizeof(line), file))
        if (sscanf(line, "PPid: %ld", &parent) == 1) break;
    fclose(file);
    /* The native fork is adopted by this subreaper. Never signal a PID merely
     * because an untrusted or stale pid file names it.
     */
    return parent == (long)getpid() ? (pid_t)number : -1;
}
static int log_bounded(void)
{
    struct stat s;
    return !lstat(LOGFILE, &s) && (!S_ISREG(s.st_mode) || s.st_size > 65536);
}
static void show_log(void)
{
    char buf[4096];
    ssize_t n;
    size_t left = 65536;
    int fd = open(LOGFILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
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
    fputs("p11lab-opencryptoki: shutdown grace expired; killing owned child\n", stderr);
    (void)kill(group ? -pid : pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 1;
}
static int monitor(pid_t child, pid_t *daemon)
{
    int status;
    for (;;) {
        if (waitpid(*daemon, &status, WNOHANG) == *daemon) {
            *daemon = -1;
            fputs("p11lab-opencryptoki: required pkcsslotd exited during operation\n", stderr);
            (void)finish_child(child, 1);
            return 1;
        }
        if (stopping || log_bounded()) {
            if (!stopping) fputs("p11lab-opencryptoki: native daemon log exceeded bound\n", stderr);
            (void)finish_child(child, 1);
            return stopping ? 128 + stopping : 1;
        }
        if (waitpid(child, &status, WNOHANG) == child) return child_code(status);
        pause_poll();
    }
}
static pid_t fork_native(const char *mode, unsigned char *pin, size_t plen,
                         unsigned char *so, size_t slen, int quiet)
{
    pid_t child = fork();
    if (child == 0) {
        int status;
        (void)setpgid(0, 0);
        if (quiet && !freopen("/dev/null", "w", stdout)) _exit(1);
        status = native(mode, pin, plen, so, slen);
        erase(pin, 9); erase(so, 9);
        exit(status);
    }
    if (child > 0) (void)setpgid(child, child);
    return child;
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

int main(int argc, char **argv)
{
    unsigned char pin[9] = {0}, so[9] = {0};
    size_t plen = 0, slen = 0;
    pid_t launcher = -1, daemon = -1, child;
    int status = 1, wait_status, lease = -1, service = -1, shmid = -1;
    struct stat s;
    struct sigaction action;
    const char *mode;
    if (argc < 2 || (strcmp(argv[1], "init") && strcmp(argv[1], "health") && strcmp(argv[1], "exec")) ||
        (!strcmp(argv[1], "exec") ? argc < 3 : argc != 2)) return 2;
    mode = argv[1];
    if (!strcmp(mode, "init")) {
        if (secrets(pin, &plen, so, &slen)) goto out;
    } else { close(3); close(4); }
    lease = open(LEASE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (!protected_file(lease) || flock(lease, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-opencryptoki: state is unsafe or already in use\n", stderr); goto out;
    }
    service = open(CONTROL "/service-lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (!protected_file(service) || flock(service, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-opencryptoki: control directory is unsafe or already in use\n", stderr); goto out;
    }
    if (!lstat(PIDFILE, &s) || !lstat(SOCKET, &s)) {
        fputs("p11lab-opencryptoki: occupied daemon control state\n", stderr); goto out;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) goto out;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) goto out;
    launcher = fork();
    if (launcher < 0) goto out;
    if (launcher == 0) { execl(DAEMON, DAEMON, (char *)NULL); _exit(127); }
    for (int i = 0; i < 200 && !stopping; i++) {
        pid_t r = waitpid(launcher, &wait_status, WNOHANG);
        if (r == launcher) {
            launcher = -1;
            if (child_code(wait_status)) goto cleanup;
            break;
        }
        pause_poll();
    }
    if (launcher > 0 || stopping) goto cleanup;
    daemon = daemon_pid();
    if (daemon <= 0 || lstat(SOCKET, &s) || !S_ISSOCK(s.st_mode)) {
        fputs("p11lab-opencryptoki: pkcsslotd startup not ready\n", stderr); goto cleanup;
    }
    shmid = shmget(ftok(DAEMON, 'b'), 0, 0);
    child = fork_native(!strcmp(mode, "init") ? "init" : "health", pin, plen, so, slen, !strcmp(mode, "exec"));
    erase(pin, sizeof(pin)); erase(so, sizeof(so));
    if (child < 0) goto cleanup;
    status = monitor(child, &daemon);
    if (status || strcmp(mode, "exec")) goto cleanup;
    child = fork();
    if (child < 0) { status = 1; goto cleanup; }
    if (child == 0) {
        (void)setpgid(0, 0);
        execvp(argv[2], &argv[2]);
        perror("p11lab-opencryptoki: application exec");
        _exit(127);
    }
    (void)setpgid(child, child);
    status = monitor(child, &daemon);
cleanup:
    if (launcher > 0 && finish_child(launcher, 0)) status = 1;
    if (daemon > 0 && finish_child(daemon, 0)) status = 1;
    if (finish_adopted()) status = 1;
    /* Remove only this invocation's native IPC and ephemeral endpoints. The
     * volume lease and private container IPC namespace remain required.
     */
    if (shmid >= 0) (void)shmctl(shmid, IPC_RMID, NULL);
    if (daemon > 0 || shmid >= 0) {
        (void)unlink(PIDFILE); (void)unlink(SOCKET);
        (void)unlink(CONTROL "/pkcsslotd.admin.socket");
    }
    if (status) show_log();
out:
    erase(pin, sizeof(pin)); erase(so, sizeof(so));
    if (service >= 0) close(service);
    if (lease >= 0) close(lease);
    return stopping ? 128 + stopping : status;
}
