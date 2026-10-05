/* SPDX-License-Identifier: Apache-2.0
 * P11Lab original provisioning and Linux child supervision for the ykcs11
 * provider. Upstream pcscd, the CanoKey virt-card IFD handler, yubico-piv-tool
 * and the libykcs11 module are invoked unmodified with pinned arguments;
 * their return values and errors are preserved, never normalized. The card
 * is ephemeral per daemon instance, so every operation re-personalizes a
 * factory-fresh card with the caller PIN/PUK and re-imports the
 * first-init key and certificate. No PKCS#11 login happens here:
 * readiness proves the full card path with a pre-login census.
 */
#define _GNU_SOURCE
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
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
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <PCSC/winscard.h>

#define PCSCD "/usr/sbin/pcscd"
#define TOOL "/usr/local/bin/yubico-piv-tool"
#define OPENSSL "/usr/bin/openssl"
/* Factory PIV defaults. Public Yubico/CanoKey constants, not caller
 * secrets: every operation starts from a factory-fresh card and moves
 * it to the caller PIN/PUK. Recorded here and in the descriptor. */
#define FACTORY_PIN "123456"
#define FACTORY_PUK "12345678"
/* Native PIV bounds, proven: change-pin/change-puk enforce 6..8 bytes. */
#define PIN_MIN 6
#define PIN_MAX 8
#define CONTROL "/run/p11lab/ykcs11"
#define LOGDIR CONTROL "/logs"
#define PROVDIR CONTROL "/provisioning"
#define SOCKETDIR "/run/pcscd"
#define SOCKET SOCKETDIR "/pcscd.comm"
#define OWNED "/var/lib/p11lab/ykcs11"
#define LEASE OWNED "/lease"
#define KEYFILE OWNED "/key9a.pem"
#define CERTFILE OWNED "/cert9a.pem"
#define LABEL "YubiKey PIV #0"
#define SLOT_ID 0
#define TOKEN_FLAGS 0x40d
#define OBJECT_TOTAL 6
#define LOG_BOUND 65536
#define SELF_SIGN_SUBJECT "/CN=P11Lab ykcs11 9a/"
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
/* Bounded stdin record: user LF so, each PIN_MIN..PIN_MAX bytes, no CR/NUL/LF. */
static int secrets(unsigned char *user, size_t *ulen, unsigned char *so, size_t *slen)
{
    static unsigned char input[19];
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
        if (*ulen >= PIN_MIN && *ulen <= PIN_MAX && *slen >= PIN_MIN && *slen <= PIN_MAX &&
            !memchr(input, '\r', length) && !memchr(input, '\0', length)) {
            memcpy(user, input, *ulen); memcpy(so, separator + 1, *slen);
            bad = 0;
        }
    }
    erase(input, sizeof(input));
    return bad;
}

static int count_objects(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE session,
                         CK_OBJECT_CLASS class, unsigned *total)
{
    CK_ATTRIBUTE filter[1];
    CK_OBJECT_HANDLE handles[64];
    CK_ULONG got = 0;
    CK_RV rv;
    *total = 0;
    if (class == (CK_OBJECT_CLASS)~0UL) {
        rv = f->C_FindObjectsInit(session, NULL, 0);
    } else {
        filter[0].type = CKA_CLASS;
        filter[0].pValue = &class;
        filter[0].ulValueLen = sizeof(class);
        rv = f->C_FindObjectsInit(session, filter, 1);
    }
    if (rv) return report("C_FindObjectsInit", rv);
    for (;;) {
        CK_RV step = f->C_FindObjects(session, handles, 64, &got);
        /* A mid-enumeration error is a native failure, never
         * end-of-data: report it instead of hiding it. */
        if (step != CKR_OK) {
            report("C_FindObjects", step);
            rv = f->C_FindObjectsFinal(session);
            if (rv) return report("C_FindObjectsFinal", rv);
            return 1;
        }
        if (got == 0) break;
        if (got > 64) return report("C_FindObjects", CKR_GENERAL_ERROR);
        *total += (unsigned)got;
    }
    rv = f->C_FindObjectsFinal(session);
    if (rv) return report("C_FindObjectsFinal", rv);
    return 0;
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
    CK_BYTE padded[32];
    const char *module = getenv("P11LAB_MODULE");
    void *handle = NULL, *symbol;
    CK_RV rv;
    int initialized = 0, status = 1, have = 0;
    unsigned have_ec = 0, have_ecgen = 0, have_rsa = 0;
    unsigned certs = 0, pubkeys = 0;
    if (!module || strlen(LABEL) > sizeof(padded)) return 2;
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, LABEL, strlen(LABEL));
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-ykcs11: cannot load module\n", stderr); goto out; }
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
    if (count > 16) { fputs("p11lab-ykcs11: slot list exceeds bound\n", stderr); goto out; }
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
    if (!have) { fputs("p11lab-ykcs11: labelled token not present\n", stderr); goto out; }
    *slot_id = (int)found;
    if (*slot_id != SLOT_ID) {
        fprintf(stderr, "p11lab-ykcs11: native_slot=%d, want %d\n", *slot_id, SLOT_ID);
        goto out;
    }
    if (info.flags != TOKEN_FLAGS) {
        fprintf(stderr, "p11lab-ykcs11: token flags=0x%lx, want 0x%x\n",
                (unsigned long)info.flags, TOKEN_FLAGS);
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
        fputs("p11lab-ykcs11: required mechanisms unavailable\n", stderr);
        goto out;
    }
    rv = f->C_OpenSession(found, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv) { report("C_OpenSession", rv); goto out; }
    /* Pre-login census: the provisioned slot-9a key and certificate are
     * visible without authentication; the private key is not. */
    if (count_objects(f, session, CKO_CERTIFICATE, &certs) ||
        count_objects(f, session, CKO_PUBLIC_KEY, &pubkeys) ||
        count_objects(f, session, (CK_OBJECT_CLASS)~0UL, objects)) goto out;
    if (certs != 1 || pubkeys != 1 || *objects != OBJECT_TOTAL) {
        fprintf(stderr, "p11lab-ykcs11: census certs=%u pubkeys=%u total=%u, want 1/1/%d\n",
                certs, pubkeys, *objects, OBJECT_TOTAL);
        goto out;
    }
    if (!quiet)
        printf("ready: native_slot=%d token_present_index=%d label=%s objects=%u\n",
               *slot_id, *present_index, LABEL, *objects);
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
    if (kill(pid, 0) && errno == ESRCH) return 0;
    (void)kill(group ? -pid : pid, SIGTERM);
    for (int i = 0; i < 100; i++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid || (r < 0 && errno == ECHILD)) return 0;
        pause_poll();
    }
    fputs("p11lab-ykcs11: shutdown grace expired; killing owned child\n", stderr);
    (void)kill(group ? -pid : pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 1;
}
/* Spawn a service with stdout/stderr appended to its bounded log file. */
static pid_t spawn_service(char *const argv[], const char *logpath, const char *pidpath)
{
    int log = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    pid_t child;
    if (log < 0) return -1;
    child = fork();
    if (child < 0) { close(log); return -1; }
    if (child == 0) {
        int devnull = open("/dev/null", O_RDONLY);
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
/* Reader discovery: exactly one PC/SC reader, and it must be the CanoKey
 * virtual card. Any other topology (none, several, foreign) fails closed. */
static int discover_reader(char *name, size_t capacity)
{
    SCARDCONTEXT context = 0;
    LONG rc;
    DWORD length = 0;
    char *list = NULL;
    unsigned entries = 0;
    const char *only = NULL;
    size_t off = 0;
    int status = 0;
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context);
    if (rc != SCARD_S_SUCCESS) return 0;
    rc = SCardListReaders(context, NULL, NULL, &length);
    if (rc != SCARD_S_SUCCESS || length < 2 || length > 65536) {
        SCardReleaseContext(context);
        return 0;
    }
    list = malloc(length);
    if (!list) { SCardReleaseContext(context); return 0; }
    rc = SCardListReaders(context, NULL, list, &length);
    if (rc != SCARD_S_SUCCESS) { free(list); SCardReleaseContext(context); return 0; }
    while (off < length && list[off]) {
        only = list + off;
        entries++;
        off += strlen(list + off) + 1;
    }
    if (entries == 1 && only && strlen(only) < capacity && strstr(only, "Canokey")) {
        int printable = 1;
        for (const char *p = only; *p; p++)
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e) printable = 0;
        if (printable) {
            memcpy(name, only, strlen(only) + 1);
            status = 1;
        }
    }
    free(list);
    SCardReleaseContext(context);
    return status;
}
/* Run a provisioning step. Secrets arrive on a private stdin pipe; output
 * joins provision.log, which carries no secret values (the tool echoes
 * only prompt names). Bounded at 120 seconds per step. */
static int run_step(char *const argv[], const unsigned char *record, size_t record_len)
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
        execv(argv[0], argv);
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
    for (int i = 0; i < 2400 && !stopping; i++) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) return child_code(status);
        if (r < 0 && errno == ECHILD) return 1;
        pause_poll();
    }
    fputs("p11lab-ykcs11: provisioning step bound expired\n", stderr);
    (void)finish_child(child, 0);
    return 1;
}
/* Copy a provisioning artifact (public key or certificate, never secrets)
 * into owned state with strict ownership. Bounded at 64 KiB. */
static int store_copy(const char *from, const char *to)
{
    char buf[4096];
    ssize_t n;
    size_t total = 0;
    int in = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int out;
    struct stat s;
    if (in < 0) return 1;
    if (fstat(in, &s) || !S_ISREG(s.st_mode) || s.st_uid != getuid() ||
        s.st_nlink != 1 || s.st_size <= 0 || s.st_size > 65536) {
        close(in);
        return 1;
    }
    out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) { close(in); return 1; }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        total += (size_t)n;
        if (total > 65536 || write(out, buf, (size_t)n) != n) {
            close(in); close(out);
            return 1;
        }
    }
    close(in);
    if (n < 0 || total == 0) { close(out); return 1; }
    if (close(out)) return 1;
    return 0;
}
/* Personalize the factory-fresh card and import the slot-9a identity.
 * First init generates the key and self-signed certificate and stores
 * them; every operation (including first init) moves the fresh card to
 * the caller PIN/PUK and imports the stored identity. Native tool
 * errors fail the operation unchanged. */
static int provision(const char *reader, const unsigned char *user, size_t ulen,
                     const unsigned char *so, size_t slen, int first)
{
    static unsigned char record[32];
    size_t record_len;
    char *status_argv[6];
    /* GET VERSION handshake: the module hard-requires the proprietary
     * Yubico dialect, so a card that cannot answer status is refused
     * here with a clear message instead of a later C_Initialize error. */
    status_argv[0] = TOOL; status_argv[1] = "-r"; status_argv[2] = (char *)reader;
    status_argv[3] = "-a"; status_argv[4] = "status"; status_argv[5] = NULL;
    if (run_step(status_argv, NULL, 0)) {
        fputs("p11lab-ykcs11: card did not answer the Yubico handshake\n", stderr);
        return 1;
    }
    if (first) {
        struct stat s;
        {
            char *full[9];
            full[0] = OPENSSL; full[1] = "genpkey"; full[2] = "-algorithm"; full[3] = "EC";
            full[4] = "-pkeyopt"; full[5] = "ec_paramgen_curve:P-256"; full[6] = "-out";
            full[7] = KEYFILE; full[8] = NULL;
            if (run_step(full, NULL, 0)) {
                fputs("p11lab-ykcs11: slot-9a key generation failed\n", stderr);
                return 1;
            }
        }
        if (stat(KEYFILE, &s) || !S_ISREG(s.st_mode) || s.st_uid != getuid() ||
            s.st_nlink != 1 || (s.st_mode & 0777) != 0600 || s.st_size <= 0 ||
            s.st_size > 65536) {
            fputs("p11lab-ykcs11: generated key file is unsafe\n", stderr);
            return 1;
        }
    }
    memcpy(record, FACTORY_PIN, strlen(FACTORY_PIN));
    record[strlen(FACTORY_PIN)] = '\n';
    memcpy(record + strlen(FACTORY_PIN) + 1, user, ulen);
    record_len = strlen(FACTORY_PIN) + 1 + ulen;
    {
        char *full[7];
        full[0] = TOOL; full[1] = "--stdin-input"; full[2] = "-r"; full[3] = (char *)reader;
        full[4] = "-a"; full[5] = "change-pin"; full[6] = NULL;
        if (run_step(full, record, record_len)) {
            erase(record, sizeof(record));
            fputs("p11lab-ykcs11: caller PIN personalization failed\n", stderr);
            return 1;
        }
    }
    erase(record, sizeof(record));
    memcpy(record, FACTORY_PUK, strlen(FACTORY_PUK));
    record[strlen(FACTORY_PUK)] = '\n';
    memcpy(record + strlen(FACTORY_PUK) + 1, so, slen);
    record_len = strlen(FACTORY_PUK) + 1 + slen;
    {
        char *full[7];
        full[0] = TOOL; full[1] = "--stdin-input"; full[2] = "-r"; full[3] = (char *)reader;
        full[4] = "-a"; full[5] = "change-puk"; full[6] = NULL;
        if (run_step(full, record, record_len)) {
            erase(record, sizeof(record));
            fputs("p11lab-ykcs11: caller PUK personalization failed\n", stderr);
            return 1;
        }
    }
    erase(record, sizeof(record));
    {
        char *full[10];
        full[0] = TOOL; full[1] = "-r"; full[2] = (char *)reader; full[3] = "-a";
        full[4] = "import-key"; full[5] = "-s"; full[6] = "9a"; full[7] = "-i";
        full[8] = KEYFILE; full[9] = NULL;
        if (run_step(full, NULL, 0)) {
            fputs("p11lab-ykcs11: slot-9a key import failed\n", stderr);
            return 1;
        }
    }
    if (first) {
        {
            char *full[8];
            full[0] = OPENSSL; full[1] = "pkey"; full[2] = "-in"; full[3] = KEYFILE;
            full[4] = "-pubout"; full[5] = "-out";
            full[6] = PROVDIR "/key9a-pub.pem"; full[7] = NULL;
            if (run_step(full, NULL, 0)) {
                fputs("p11lab-ykcs11: public key export failed\n", stderr);
                return 1;
            }
        }
        memcpy(record, user, ulen);
        record_len = ulen;
        {
            char *full[17];
            full[0] = TOOL; full[1] = "--stdin-input"; full[2] = "-r"; full[3] = (char *)reader;
            full[4] = "-a"; full[5] = "verify-pin"; full[6] = "-a"; full[7] = "selfsign-certificate";
            full[8] = "-s"; full[9] = "9a"; full[10] = "-S"; full[11] = SELF_SIGN_SUBJECT;
            full[12] = "-i"; full[13] = PROVDIR "/key9a-pub.pem"; full[14] = "-o";
            full[15] = PROVDIR "/cert9a.pem"; full[16] = NULL;
            if (run_step(full, record, record_len)) {
                erase(record, sizeof(record));
                fputs("p11lab-ykcs11: slot-9a self-signed certificate failed\n", stderr);
                return 1;
            }
        }
        erase(record, sizeof(record));
        if (store_copy(PROVDIR "/cert9a.pem", CERTFILE)) {
            fputs("p11lab-ykcs11: certificate store failed\n", stderr);
            return 1;
        }
    }
    {
        char *full[10];
        full[0] = TOOL; full[1] = "-r"; full[2] = (char *)reader; full[3] = "-a";
        full[4] = "import-certificate"; full[5] = "-s"; full[6] = "9a"; full[7] = "-i";
        full[8] = CERTFILE; full[9] = NULL;
        if (run_step(full, NULL, 0)) {
            fputs("p11lab-ykcs11: slot-9a certificate import failed\n", stderr);
            return 1;
        }
    }
    erase(record, sizeof(record));
    return 0;
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
static int monitor(pid_t child, pid_t service, const char *name)
{
    int status;
    for (;;) {
        if (service > 0 && waitpid(service, &status, WNOHANG) == service) {
            fprintf(stderr, "p11lab-ykcs11: required %s exited during operation\n", name);
            (void)finish_child(child, 1);
            return 1;
        }
        if (stopping || log_bounded(LOGDIR "/pcscd.log") || log_bounded(LOGDIR "/provision.log")) {
            if (!stopping) fputs("p11lab-ykcs11: service log exceeded bound\n", stderr);
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
/* Wait for the pcscd socket to accept a connection, proving the daemon
 * reached its serving loop rather than merely staying alive. Bounded. */
static int socket_accept(pid_t pcscd)
{
    int fd, done = 0;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, SOCKET, strlen(SOCKET));
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    if (!connect(fd, (struct sockaddr *)&addr, sizeof(addr))) done = 1;
    close(fd);
    (void)pcscd;
    return done;
}

int main(int argc, char **argv)
{
    static unsigned char user[9], so[9];
    static char reader[256];
    size_t ulen = 0, slen = 0;
    pid_t pcscd = -1;
    char *pcscd_argv[4];
    pid_t child = -1;
    int status = 1, lease = -1, service = -1, first = 0;
    struct stat s;
    struct sigaction action;
    const char *mode;
    if (argc < 2 || (strcmp(argv[1], "init") && strcmp(argv[1], "reprovision") && strcmp(argv[1], "exec")) ||
        (!strcmp(argv[1], "exec") ? argc < 3 : argc != 2)) return 2;
    mode = argv[1];
    first = !strcmp(mode, "init");
    umask(077);
    if (secrets(user, &ulen, so, &slen)) {
        fputs("p11lab-ykcs11: credential record refused\n", stderr);
        goto out;
    }
    lease = open(LEASE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (!protected_file(lease) || flock(lease, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-ykcs11: state is unsafe or already in use\n", stderr); goto out;
    }
    service = open(CONTROL "/service-lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (!protected_file(service) || flock(service, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-ykcs11: control directory is unsafe or already in use\n", stderr); goto out;
    }
    if (!lstat(CONTROL "/pcscd.pid", &s) || !lstat(SOCKET, &s) || !lstat(SOCKETDIR "/pcscd.pid", &s)) {
        fputs("p11lab-ykcs11: occupied daemon control state\n", stderr); goto out;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) goto out;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) goto out;
    pcscd_argv[0] = PCSCD; pcscd_argv[1] = "--foreground"; pcscd_argv[2] = "--disable-polkit";
    pcscd_argv[3] = NULL;
    pcscd = spawn_service(pcscd_argv, LOGDIR "/pcscd.log", CONTROL "/pcscd.pid");
    if (pcscd <= 0) goto cleanup;
    /* Readiness ladder: socket accept, then exactly-one-CanoKey reader
     * discovery, then the provisioned native pre-login round-trip.
     * Bounded; a dead daemon fails fast with its logs. */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !stopping; i++) {
            int code;
            pid_t r = waitpid(pcscd, &code, WNOHANG);
            if (r == pcscd) {
                fputs("p11lab-ykcs11: required pcscd exited during startup\n", stderr);
                pcscd = -1;
                goto cleanup;
            }
            if (socket_accept(pcscd) && discover_reader(reader, sizeof(reader))) {
                ready = 1;
                break;
            }
            pause_poll();
        }
        if (!ready || stopping) {
            if (!stopping) fputs("p11lab-ykcs11: pcscd/card not ready\n", stderr);
            goto cleanup;
        }
    }
    if (provision(reader, user, ulen, so, slen, first)) goto cleanup;
    erase(user, sizeof(user)); erase(so, sizeof(so));
    child = fork_native(!strcmp(mode, "exec"));
    if (child < 0) goto cleanup;
    status = monitor(child, pcscd, "pcscd");
    if (status || strcmp(mode, "exec")) goto cleanup;
    child = fork();
    if (child < 0) { status = 1; goto cleanup; }
    if (child == 0) {
        (void)setpgid(0, 0);
        execvp(argv[2], &argv[2]);
        perror("p11lab-ykcs11: application exec");
        _exit(127);
    }
    (void)setpgid(child, child);
    status = monitor(child, pcscd, "pcscd");
cleanup:
    erase(user, sizeof(user)); erase(so, sizeof(so));
    if (pcscd > 0 && finish_child(pcscd, 0)) status = 1;
    if (finish_adopted()) status = 1;
    (void)unlink(CONTROL "/pcscd.pid");
    (void)unlink(SOCKET);
    (void)unlink(SOCKETDIR "/pcscd.pid");
    if (status) {
        show_log(LOGDIR "/pcscd.log"); show_log(LOGDIR "/provision.log");
    }
out:
    erase(user, sizeof(user)); erase(so, sizeof(so));
    if (service >= 0) close(service);
    if (lease >= 0) close(lease);
    return stopping ? 128 + stopping : status;
}
