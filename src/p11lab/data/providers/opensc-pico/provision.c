/* SPDX-License-Identifier: Apache-2.0
 * P11Lab original provisioning and Linux child supervision for the
 * opensc-pico provider. Upstream pcscd, the vsmartcard ifd-vpcd
 * handler, the pico-hsm emulator, sc-hsm-tool and the OpenSC module
 * run unmodified with pinned arguments; their return values and
 * errors are preserved, never normalized. First init fabricates a
 * fresh flash (the emulator self-creates it in its working
 * directory), initializes it with the caller PINs over a pty (the
 * tool requires a TTY for PIN entry and never takes them from a
 * pipe), and generates three on-card keys via PKCS#11; later
 * operations resume the persisted flash and prove it with a
 * pre-login census. INITIALIZE is never re-run: it is destructive
 * and would silently reset the token.
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
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <PCSC/winscard.h>

#define PCSCD "/usr/sbin/pcscd"
#define TOOL "/usr/local/bin/sc-hsm-tool"
#define EMULATOR "/usr/local/bin/pico_hsm"
/* Native SmartCard-HSM bounds, proven: the tool accepts a 6..16
 * character user PIN, but a 16-character PIN can never verify
 * (CKR_PIN_LEN_RANGE at login) while 6..15 verify and rotate
 * natively. The SO-PIN is exactly 16 hexadecimal characters. */
#define PIN_MIN 6
#define PIN_MAX 15
#define SO_PIN_LEN 16
#define CONTROL "/run/p11lab/opensc-pico"
#define LOGDIR CONTROL "/logs"
#define SOCKETDIR "/run/pcscd"
#define SOCKET SOCKETDIR "/pcscd.comm"
#define OWNED "/var/lib/p11lab/opensc-pico"
#define LEASE OWNED "/lease"
#define FLASH OWNED "/memory.flash"
#define FLASH_SIZE 8388608
#define LABEL "SmartCard-HSM"
#define SLOT_ID 0
#define TOKEN_FLAGS 0x40d
#define TOKEN_MIN_PIN 6
#define TOKEN_MAX_PIN 15
#define MECHANISM_COUNT 30
#define OBJECT_TOTAL 4
#define OBJECT_PUBKEYS 3
#define LOG_BOUND 65536
/* Frozen emulator ATR (SmartCard-HSM "HSM1" at bytes 13..16). */
static const unsigned char ATR[24] = {
    0x3b, 0xfe, 0x18, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x80, 0x31, 0x81,
    0x54, 0x48, 0x53, 0x4d, 0x31, 0x73, 0x80, 0x21, 0x40, 0x81, 0x07, 0xfa
};
static const unsigned char P256_PARAMS[10] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};
static const unsigned char P384_PARAMS[7] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};
static const unsigned char RSA_EXPONENT[3] = {0x01, 0x00, 0x01};
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
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* Bounded stdin record: user LF so. The user PIN is PIN_MIN..PIN_MAX
 * bytes single-line; the SO-PIN is exactly SO_PIN_LEN hexadecimal
 * characters. No CR/NUL/LF inside either secret. */
static int secrets(unsigned char *user, size_t *ulen, unsigned char *so, size_t *slen)
{
    static unsigned char input[PIN_MAX + 1 + SO_PIN_LEN + 1];
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
        if (*ulen >= PIN_MIN && *ulen <= PIN_MAX && *slen == SO_PIN_LEN &&
            !memchr(input, '\r', length) && !memchr(input, '\0', length)) {
            size_t i;
            bad = 0;
            for (i = 0; i < *slen; i++)
                if (hexval((separator + 1)[i]) < 0) bad = 1;
            if (!bad) { memcpy(user, input, *ulen); memcpy(so, separator + 1, *slen); }
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
    unsigned have_ec = 0, have_ecgen = 0, have_rsagen = 0;
    unsigned certs = 0, pubkeys = 0;
    if (!module || strlen(LABEL) > sizeof(padded)) return 2;
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, LABEL, strlen(LABEL));
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-opensc-pico: cannot load module\n", stderr); goto out; }
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
    if (count > 16) { fputs("p11lab-opensc-pico: slot list exceeds bound\n", stderr); goto out; }
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
    if (!have) { fputs("p11lab-opensc-pico: labelled token not present\n", stderr); goto out; }
    *slot_id = (int)found;
    if (*slot_id != SLOT_ID) {
        fprintf(stderr, "p11lab-opensc-pico: native_slot=%d, want %d\n", *slot_id, SLOT_ID);
        goto out;
    }
    /* The user-PIN-state bits are transient native counter state,
     * not token identity: OpenSC sets COUNT_LOW on any burned try,
     * FINAL_TRY at one try left, and LOCKED at zero, while a correct
     * VERIFY or SO C_InitPIN restores the whole budget. Refusing them
     * here would brick the adapter against ordinary wrong-PIN use and
     * against the unblock operation that restores a locked token, so
     * all three are masked before comparison. Any other deviation
     * (including SO lockout or a PIN-change demand) fails closed. */
    if ((info.flags & ~(CK_FLAGS)(CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY |
                                  CKF_USER_PIN_LOCKED)) != TOKEN_FLAGS) {
        fprintf(stderr, "p11lab-opensc-pico: token flags=0x%lx, want 0x%x (modulo user-pin-state)\n",
                (unsigned long)info.flags, TOKEN_FLAGS);
        goto out;
    }
    if (info.ulMinPinLen != TOKEN_MIN_PIN || info.ulMaxPinLen != TOKEN_MAX_PIN) {
        fprintf(stderr, "p11lab-opensc-pico: pin bounds=%lu/%lu, want %d/%d\n",
                info.ulMinPinLen, info.ulMaxPinLen, TOKEN_MIN_PIN, TOKEN_MAX_PIN);
        goto out;
    }
    mechanisms = 64;
    rv = f->C_GetMechanismList(found, list, &mechanisms);
    if (rv) { report("C_GetMechanismList", rv); goto out; }
    if (mechanisms != MECHANISM_COUNT) {
        fprintf(stderr, "p11lab-opensc-pico: mechanisms=%lu, want %d\n",
                mechanisms, MECHANISM_COUNT);
        goto out;
    }
    for (CK_ULONG i = 0; i < mechanisms; i++) {
        CK_MECHANISM_INFO details;
        if (list[i] != CKM_ECDSA && list[i] != CKM_EC_KEY_PAIR_GEN &&
            list[i] != CKM_RSA_PKCS_KEY_PAIR_GEN) continue;
        rv = f->C_GetMechanismInfo(found, list[i], &details);
        if (rv) { report("C_GetMechanismInfo", rv); goto out; }
        if (list[i] == CKM_ECDSA && (details.flags & CKF_SIGN)) have_ec = 1;
        if (list[i] == CKM_EC_KEY_PAIR_GEN && (details.flags & CKF_GENERATE_KEY_PAIR)) have_ecgen = 1;
        if (list[i] == CKM_RSA_PKCS_KEY_PAIR_GEN && (details.flags & CKF_GENERATE_KEY_PAIR)) have_rsagen = 1;
    }
    if (!have_ec || !have_ecgen || !have_rsagen) {
        fputs("p11lab-opensc-pico: required mechanisms unavailable\n", stderr);
        goto out;
    }
    rv = f->C_OpenSession(found, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv) { report("C_OpenSession", rv); goto out; }
    /* Pre-login census: the three provisioned public keys plus the
     * PKCS#11 profile object are visible without authentication; the
     * private keys are not. Each provisioned ID must select exactly
     * its public half (a deleted or replaced key fails); totals are
     * lower bounds because general-token applications may persist
     * their own keys, certificates, or data objects on the card. A
     * blank flash cannot pass: it reports an empty label with
     * different flags and PIN bounds, and no provisioned IDs. */
    if (count_objects(f, session, CKO_CERTIFICATE, &certs) ||
        count_objects(f, session, CKO_PUBLIC_KEY, &pubkeys) ||
        count_objects(f, session, (CK_OBJECT_CLASS)~0UL, objects)) goto out;
    if (pubkeys < OBJECT_PUBKEYS || *objects < OBJECT_TOTAL) {
        fprintf(stderr, "p11lab-opensc-pico: census certs=%u pubkeys=%u total=%u, want at least %d/%d\n",
                certs, pubkeys, *objects, OBJECT_PUBKEYS, OBJECT_TOTAL);
        goto out;
    }
    for (unsigned k = 0; k < 3; k++) {
        static const unsigned char ids[3] = {0x01, 0x02, 0x03};
        CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE filter[2];
        CK_OBJECT_HANDLE handles[4];
        CK_ULONG got = 0;
        filter[0].type = CKA_CLASS; filter[0].pValue = &class;
        filter[0].ulValueLen = sizeof(class);
        filter[1].type = CKA_ID; filter[1].pValue = (void *)&ids[k];
        filter[1].ulValueLen = 1;
        rv = f->C_FindObjectsInit(session, filter, 2);
        if (rv) { report("C_FindObjectsInit", rv); goto out; }
        rv = f->C_FindObjects(session, handles, 4, &got);
        if (rv) { report("C_FindObjects", rv); goto out; }
        rv = f->C_FindObjectsFinal(session);
        if (rv) { report("C_FindObjectsFinal", rv); goto out; }
        if (got != 1) {
            fprintf(stderr, "p11lab-opensc-pico: census id=0x%02x selects %lu public keys, want 1\n",
                    ids[k], (unsigned long)got);
            goto out;
        }
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
    fputs("p11lab-opensc-pico: shutdown grace expired; killing owned child\n", stderr);
    (void)kill(group ? -pid : pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 1;
}
/* Spawn a service with stdout/stderr appended to its bounded log file.
 * The emulator runs with its working directory at the owned state
 * directory: it self-fabricates and persists memory.flash there. */
static pid_t spawn_service(char *const argv[], const char *logpath, const char *pidpath, const char *cwd)
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
        if (cwd && chdir(cwd)) _exit(127);
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
/* vpcd presence: the handler's reader slots are listed once pcscd
 * has loaded the driver and opened its channels (which is also when
 * it starts listening). The emulator connects exactly once at
 * startup with no retry, so it must only spawn after this holds. */
static int vpcd_listed(void)
{
    SCARDCONTEXT context = 0;
    LONG rc;
    DWORD length = 0;
    char *list = NULL;
    size_t off = 0;
    int found = 0;
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
        if (strstr(list + off, "Virtual PCD")) found = 1;
        off += strlen(list + off) + 1;
    }
    free(list);
    SCardReleaseContext(context);
    return found;
}
/* Reader discovery: at least one PC/SC reader, exactly one with a
 * card present, named like the vpcd handler and presenting the
 * frozen SmartCard-HSM ATR. Any other topology fails closed. */
static int discover_reader(char *name, size_t capacity, char *atr_hex, size_t hex_capacity)
{
    SCARDCONTEXT context = 0;
    LONG rc;
    DWORD length = 0;
    char *list = NULL;
    unsigned with_card = 0;
    size_t off = 0;
    int status = 0;
    static const char hexdigits[] = "0123456789abcdef";
    if (hex_capacity < 2 * sizeof(ATR) + 1) return 0;
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
        const char *reader = list + off;
        SCARDHANDLE card = 0;
        DWORD active = 0;
        unsigned char atr[33];
        DWORD atr_len = sizeof(atr);
        off += strlen(reader) + 1;
        if (!strstr(reader, "Virtual PCD")) continue;
        rc = SCardConnect(context, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                          &card, &active);
        if (rc != SCARD_S_SUCCESS) continue;
        rc = SCardStatus(card, NULL, NULL, NULL, NULL, atr, &atr_len);
        SCardDisconnect(card, SCARD_LEAVE_CARD);
        if (rc != SCARD_S_SUCCESS) continue;
        with_card++;
        if (with_card == 1 && strlen(reader) < capacity && atr_len == sizeof(ATR) &&
            !memcmp(atr, ATR, sizeof(ATR))) {
            int printable = 1;
            for (const char *p = reader; *p; p++)
                if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e) printable = 0;
            if (printable) {
                memcpy(name, reader, strlen(reader) + 1);
                for (size_t i = 0; i < sizeof(ATR); i++) {
                    atr_hex[2 * i] = hexdigits[ATR[i] >> 4];
                    atr_hex[2 * i + 1] = hexdigits[ATR[i] & 0xf];
                }
                atr_hex[2 * sizeof(ATR)] = '\0';
                status = 1;
            }
        }
    }
    free(list);
    SCardReleaseContext(context);
    return status && with_card == 1;
}

/* First-init on-card key provisioning: log in with the caller user
 * PIN (which also proves it) and generate the three token keys with
 * fixed CKA_IDs, asserting every outcome. Native errors fail the
 * operation unchanged; nothing here is best-effort. */
static int keygen(const unsigned char *pin, size_t pin_len)
{
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slots[16];
    CK_ULONG n = 16;
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_ULONG rsa_bits = 2048;
    CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY, priv_class = CKO_PRIVATE_KEY;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    const char *module = getenv("P11LAB_MODULE");
    void *handle = NULL, *symbol;
    CK_RV rv;
    int initialized = 0, status = 1;
    static const struct {
        CK_MECHANISM_TYPE mech;
        unsigned char id;
        const char *label;
        const unsigned char *params;
        size_t params_len;
    } keys[3] = {
        {CKM_EC_KEY_PAIR_GEN, 0x01, "p11lab-p256", P256_PARAMS, sizeof(P256_PARAMS)},
        {CKM_RSA_PKCS_KEY_PAIR_GEN, 0x02, "p11lab-rsa2048", NULL, 0},
        {CKM_EC_KEY_PAIR_GEN, 0x03, "p11lab-p384", P384_PARAMS, sizeof(P384_PARAMS)},
    };
    if (!module) return 2;
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-opensc-pico: cannot load module\n", stderr); goto out; }
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get), "function pointer ABI");
    memcpy(&get, &symbol, sizeof(get));
    if (!get) goto out;
    rv = get(&f);
    if (rv || !f) { report("C_GetFunctionList", rv); goto out; }
    rv = f->C_Initialize(NULL);
    if (rv) { report("C_Initialize", rv); goto out; }
    initialized = 1;
    rv = f->C_GetSlotList(CK_TRUE, slots, &n);
    if (rv) { report("C_GetSlotList", rv); goto out; }
    if (n != 1 || slots[0] != SLOT_ID) {
        fputs("p11lab-opensc-pico: token-present slot roster is not exactly slot 0\n", stderr);
        goto out;
    }
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv) { report("C_OpenSession", rv); goto out; }
    rv = f->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)pin_len);
    if (rv) { report("C_Login", rv); goto out; }
    for (unsigned k = 0; k < 3; k++) {
        CK_MECHANISM mechanism;
        CK_ATTRIBUTE pub_attrs[10], priv_attrs[11];
        CK_KEY_TYPE key_type;
        unsigned char id = keys[k].id;
        CK_ULONG npub = 0, npriv = 0;
        memset(&mechanism, 0, sizeof(mechanism));
        mechanism.mechanism = keys[k].mech;
        /* Template mirrors pkcs11-tool(1) 0.27's working split: class,
         * token, key-type, id, label on both halves; private also
         * private+sensitive(+explicit non-extractable, the observed
         * on-card enforcement). EC usage is verify+derive/sign+
         * derive (never encrypt/decrypt); RSA usage is verify+
         * encrypt/sign+decrypt. Templates missing class/key-type are
         * rejected with GENERAL_ERROR. */
        key_type = keys[k].params ? CKK_EC : CKK_RSA;
        memset(pub_attrs, 0, sizeof(pub_attrs));
        memset(priv_attrs, 0, sizeof(priv_attrs));
        pub_attrs[npub].type = CKA_CLASS; pub_attrs[npub].pValue = &pub_class;
        pub_attrs[npub++].ulValueLen = sizeof(pub_class);
        pub_attrs[npub].type = CKA_TOKEN; pub_attrs[npub].pValue = &yes;
        pub_attrs[npub++].ulValueLen = sizeof(yes);
        pub_attrs[npub].type = CKA_KEY_TYPE; pub_attrs[npub].pValue = &key_type;
        pub_attrs[npub++].ulValueLen = sizeof(key_type);
        pub_attrs[npub].type = CKA_ID; pub_attrs[npub].pValue = &id;
        pub_attrs[npub++].ulValueLen = 1;
        pub_attrs[npub].type = CKA_LABEL; pub_attrs[npub].pValue = (void *)keys[k].label;
        pub_attrs[npub++].ulValueLen = (CK_ULONG)strlen(keys[k].label);
        pub_attrs[npub].type = CKA_VERIFY; pub_attrs[npub].pValue = &yes;
        pub_attrs[npub++].ulValueLen = sizeof(yes);
        priv_attrs[npriv].type = CKA_CLASS; priv_attrs[npriv].pValue = &priv_class;
        priv_attrs[npriv++].ulValueLen = sizeof(priv_class);
        priv_attrs[npriv].type = CKA_TOKEN; priv_attrs[npriv].pValue = &yes;
        priv_attrs[npriv++].ulValueLen = sizeof(yes);
        priv_attrs[npriv].type = CKA_PRIVATE; priv_attrs[npriv].pValue = &yes;
        priv_attrs[npriv++].ulValueLen = sizeof(yes);
        priv_attrs[npriv].type = CKA_KEY_TYPE; priv_attrs[npriv].pValue = &key_type;
        priv_attrs[npriv++].ulValueLen = sizeof(key_type);
        priv_attrs[npriv].type = CKA_ID; priv_attrs[npriv].pValue = &id;
        priv_attrs[npriv++].ulValueLen = 1;
        priv_attrs[npriv].type = CKA_LABEL; priv_attrs[npriv].pValue = (void *)keys[k].label;
        priv_attrs[npriv++].ulValueLen = (CK_ULONG)strlen(keys[k].label);
        priv_attrs[npriv].type = CKA_SIGN; priv_attrs[npriv].pValue = &yes;
        priv_attrs[npriv++].ulValueLen = sizeof(yes);
        priv_attrs[npriv].type = CKA_SENSITIVE; priv_attrs[npriv].pValue = &yes;
        priv_attrs[npriv++].ulValueLen = sizeof(yes);
        priv_attrs[npriv].type = CKA_EXTRACTABLE; priv_attrs[npriv].pValue = &no;
        priv_attrs[npriv++].ulValueLen = sizeof(no);
        if (keys[k].params) {
            pub_attrs[npub].type = CKA_DERIVE; pub_attrs[npub].pValue = &yes;
            pub_attrs[npub++].ulValueLen = sizeof(yes);
            pub_attrs[npub].type = CKA_EC_PARAMS; pub_attrs[npub].pValue = (void *)keys[k].params;
            pub_attrs[npub++].ulValueLen = (CK_ULONG)keys[k].params_len;
            priv_attrs[npriv].type = CKA_DERIVE; priv_attrs[npriv].pValue = &yes;
            priv_attrs[npriv++].ulValueLen = sizeof(yes);
        } else {
            pub_attrs[npub].type = CKA_ENCRYPT; pub_attrs[npub].pValue = &yes;
            pub_attrs[npub++].ulValueLen = sizeof(yes);
            pub_attrs[npub].type = CKA_MODULUS_BITS; pub_attrs[npub].pValue = &rsa_bits;
            pub_attrs[npub++].ulValueLen = sizeof(rsa_bits);
            pub_attrs[npub].type = CKA_PUBLIC_EXPONENT; pub_attrs[npub].pValue = (void *)RSA_EXPONENT;
            pub_attrs[npub++].ulValueLen = sizeof(RSA_EXPONENT);
            priv_attrs[npriv].type = CKA_DECRYPT; priv_attrs[npriv].pValue = &yes;
            priv_attrs[npriv++].ulValueLen = sizeof(yes);
        }
        rv = f->C_GenerateKeyPair(session, &mechanism, pub_attrs, npub,
                                 priv_attrs, npriv, &pub, &priv);
        if (rv) {
            fprintf(stderr, "p11lab-opensc-pico: keygen id=0x%02x %s: ", id, keys[k].label);
            report("C_GenerateKeyPair", rv);
            goto out;
        }
        /* The ID must select exactly the generated pair, nothing else. */
        for (int pass = 0; pass < 2; pass++) {
            CK_OBJECT_CLASS class = pass ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
            CK_ATTRIBUTE filter[2];
            CK_OBJECT_HANDLE handles[4];
            CK_ULONG got = 0;
            filter[0].type = CKA_CLASS; filter[0].pValue = &class; filter[0].ulValueLen = sizeof(class);
            filter[1].type = CKA_ID; filter[1].pValue = &id; filter[1].ulValueLen = 1;
            rv = f->C_FindObjectsInit(session, filter, 2);
            if (rv) { report("C_FindObjectsInit", rv); goto out; }
            rv = f->C_FindObjects(session, handles, 4, &got);
            if (rv) { report("C_FindObjects", rv); goto out; }
            f->C_FindObjectsFinal(session);
            if (got != 1) {
                fprintf(stderr, "p11lab-opensc-pico: key id=0x%02x selects %lu %s objects, want 1\n",
                        id, got, pass ? "private" : "public");
                goto out;
            }
        }
    }
    status = 0;
out:
    if (session != CK_INVALID_HANDLE) {
        f->C_Logout(session);
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

/* Drive sc-hsm-tool --initialize under a pty: the tool refuses PIN
 * entry unless stdout is a TTY, and argv would expose the caller
 * secrets in the process table. The pty is switched to raw mode
 * before the first secret is written, so PIN bytes (including
 * control bytes, which the card accepts) pass through exactly and
 * can never be echoed: echo is off from the first write on. The
 * transcript is bounded, scanned for native error markers (the tool
 * can report failure with a zero exit status), and erased on every
 * path; only fixed prompt-answered lines join provision.log. */
static int pty_initialize(const char *atr_hex, const unsigned char *user, size_t ulen,
                          const unsigned char *so, size_t slen)
{
    static unsigned char transcript[4096];
    size_t length = 0;
    int master = -1, status = 1, child_status = 0;
    pid_t child = -1;
#ifdef P11LAB_INIT_ASK_PIN
    char *tool_argv[7];
#else
    char *tool_argv[5];
#endif
    int sent_so = 0, sent_user = 0, raw = 0;
    int out = -1;
    memset(transcript, 0, sizeof(transcript));
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) return 1;
    if (grantpt(master) || unlockpt(master)) { close(master); return 1; }
    child = fork();
    if (child < 0) { close(master); return 1; }
    if (child == 0) {
        char *slave_name;
        int slave;
        if (setsid() < 0) _exit(127);
        slave_name = ptsname(master);
        if (!slave_name) _exit(127);
        slave = open(slave_name, O_RDWR);
        if (slave < 0) _exit(127);
        close(master);
        if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
            dup2(slave, STDERR_FILENO) < 0) _exit(127);
        if (slave > STDERR_FILENO) close(slave);
        tool_argv[0] = TOOL; tool_argv[1] = "--initialize"; tool_argv[2] = "-r";
        tool_argv[3] = (char *)atr_hex;
#ifdef P11LAB_INIT_ASK_PIN
        /* Frozen rolling sc-hsm-tool only prompts for the user PIN
         * with --pin ask:; without it the card initializes PIN-less.
         * (Release prompts unless --pin is given, so the flag is
         * baked per frozen OpenSC revision at image build.) */
        tool_argv[4] = "--pin"; tool_argv[5] = "ask:"; tool_argv[6] = NULL;
#else
        tool_argv[4] = NULL;
#endif
        /* Never --label: the post-initialize EF.TokenInfo write
         * corrupts this emulator (proven crash). The firmware-default
         * label is the token label. */
        execv(tool_argv[0], tool_argv);
        _exit(127);
    }
    out = open(LOGDIR "/provision.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) { (void)finish_child(child, 0); close(master); return 1; }
    for (int i = 0; i < 2400 && !stopping; i++) {
        struct pollfd watch;
        ssize_t n;
        pid_t r = waitpid(child, &child_status, WNOHANG);
        if (r == child) break;
        if (r < 0 && errno == ECHILD) break;
        watch.fd = master;
        watch.events = POLLIN;
        if (poll(&watch, 1, 50) <= 0) continue;
        if (!(watch.revents & POLLIN)) continue;
        n = read(master, transcript + length, sizeof(transcript) - length);
        if (n <= 0) {
            if (waitpid(child, &child_status, WNOHANG) == child) break;
            continue;
        }
        length += (size_t)n;
        if (!sent_so && memmem(transcript, length, "Enter SO-PIN", 12)) {
            struct termios raw_mode;
            if (tcgetattr(master, &raw_mode)) goto done;
            cfmakeraw(&raw_mode);
            if (tcsetattr(master, TCSANOW, &raw_mode)) goto done;
            raw = 1;
            if (write(master, so, slen) != (ssize_t)slen || write(master, "\n", 1) != 1) goto done;
            sent_so = 1;
            (void)write(out, "so-pin prompt answered\n", 23);
        } else if (sent_so && !sent_user && memmem(transcript, length, "Enter initial User-PIN", 22)) {
            if (!raw) goto done;
            if (write(master, user, ulen) != (ssize_t)ulen || write(master, "\n", 1) != 1) goto done;
            sent_user = 1;
            (void)write(out, "user-pin prompt answered\n", 25);
        }
        if (length == sizeof(transcript)) goto done;
    }
    if (stopping) goto done;
    if (waitpid(child, &child_status, 0) < 0 && errno != ECHILD) goto done;
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 || !sent_so || !sent_user) goto done;
    /* The tool can exit zero after a native failure; the transcript
     * must show both prompts and no error marker. */
    if (!memmem(transcript, length, "Enter SO-PIN", 12) ||
        !memmem(transcript, length, "Enter initial User-PIN", 22) ||
        memmem(transcript, length, "rror", 4) || memmem(transcript, length, "ailed", 5) ||
        memmem(transcript, length, "bort", 4)) goto done;
    status = 0;
done:
    erase(transcript, sizeof(transcript));
    if (out >= 0) close(out);
    if (master >= 0) close(master);
    if (child > 0 && waitpid(child, &child_status, WNOHANG) != child) (void)finish_child(child, 0);
    return status;
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
static int monitor(pid_t child, pid_t first, const char *first_name, pid_t second, const char *second_name)
{
    int status;
    for (;;) {
        if (first > 0) {
            int code;
            if (waitpid(first, &code, WNOHANG) == first) {
                fprintf(stderr, "p11lab-opensc-pico: required %s exited during operation\n", first_name);
                (void)finish_child(child, 1);
                return 1;
            }
        }
        if (second > 0) {
            int code;
            if (waitpid(second, &code, WNOHANG) == second) {
                fprintf(stderr, "p11lab-opensc-pico: required %s exited during operation\n", second_name);
                (void)finish_child(child, 1);
                return 1;
            }
        }
        if (stopping || log_bounded(LOGDIR "/pcscd.log") || log_bounded(LOGDIR "/emulator.log") ||
            log_bounded(LOGDIR "/provision.log")) {
            if (!stopping) fputs("p11lab-opensc-pico: service log exceeded bound\n", stderr);
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
    static unsigned char user[PIN_MAX + 1], so[SO_PIN_LEN + 1];
    static char reader[256], atr_hex[2 * sizeof(ATR) + 1];
    size_t ulen = 0, slen = 0;
    pid_t pcscd = -1, emulator = -1;
    char *pcscd_argv[4], *emulator_argv[2];
    pid_t child = -1;
    int status = 1, lease = -1, service = -1, first = 0;
    struct stat s;
    struct sigaction action;
    const char *mode;
    if (argc < 2 || (strcmp(argv[1], "init") && strcmp(argv[1], "health") && strcmp(argv[1], "exec")) ||
        (!strcmp(argv[1], "exec") ? argc < 3 : argc != 2)) return 2;
    mode = argv[1];
    first = !strcmp(mode, "init");
    umask(077);
    if (first && secrets(user, &ulen, so, &slen)) {
        fputs("p11lab-opensc-pico: credential record refused\n", stderr);
        goto out;
    }
    lease = open(LEASE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (!protected_file(lease) || flock(lease, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-opensc-pico: state is unsafe or already in use\n", stderr); goto out;
    }
    service = open(CONTROL "/service-lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (!protected_file(service) || flock(service, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-opensc-pico: control directory is unsafe or already in use\n", stderr); goto out;
    }
    if (!lstat(CONTROL "/pcscd.pid", &s) || !lstat(CONTROL "/emulator.pid", &s) ||
        !lstat(SOCKET, &s) || !lstat(SOCKETDIR "/pcscd.pid", &s)) {
        fputs("p11lab-opensc-pico: occupied daemon control state\n", stderr); goto out;
    }
    if (first) {
        /* INITIALIZE is destructive: never run it over an existing
         * flash. First init always starts from a fabricated flash. */
        if (!lstat(FLASH, &s)) {
            fputs("p11lab-opensc-pico: refusing to initialize over an existing flash\n", stderr);
            goto out;
        }
    } else if (stat(FLASH, &s) || !S_ISREG(s.st_mode) || s.st_uid != getuid() || s.st_nlink != 1 ||
               (s.st_mode & 0777) != 0600 || s.st_size != FLASH_SIZE) {
        fputs("p11lab-opensc-pico: provisioned flash is missing or unsafe\n", stderr);
        goto out;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) goto out;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) goto out;
    pcscd_argv[0] = PCSCD; pcscd_argv[1] = "--foreground"; pcscd_argv[2] = "--disable-polkit";
    pcscd_argv[3] = NULL;
    pcscd = spawn_service(pcscd_argv, LOGDIR "/pcscd.log", CONTROL "/pcscd.pid", NULL);
    if (pcscd <= 0) goto cleanup;
    /* Readiness ladder, phase 1: pcscd socket accept plus vpcd slots
     * listed (proving the handler is loaded and listening). The
     * emulator spawns only after this: its single startup connect
     * has no retry. Bounded; a dead daemon fails fast with its logs. */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !stopping; i++) {
            int code;
            pid_t r = waitpid(pcscd, &code, WNOHANG);
            if (r == pcscd) {
                fputs("p11lab-opensc-pico: required pcscd exited during startup\n", stderr);
                pcscd = -1;
                goto cleanup;
            }
            if (socket_accept(pcscd) && vpcd_listed()) {
                ready = 1;
                break;
            }
            pause_poll();
        }
        if (!ready || stopping) {
            if (!stopping) fputs("p11lab-opensc-pico: pcscd/vpcd not ready\n", stderr);
            goto cleanup;
        }
    }
    emulator_argv[0] = EMULATOR; emulator_argv[1] = NULL;
    emulator = spawn_service(emulator_argv, LOGDIR "/emulator.log", CONTROL "/emulator.pid", OWNED);
    if (emulator <= 0) goto cleanup;
    /* Phase 2: the emulator-backed reader with its ATR match, proving
     * the vpcd loopback path plus the live card, never process-alive
     * alone. Then first-init provisioning or the resuming native
     * census. Bounded; a dead service fails fast with its logs. */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !stopping; i++) {
            int code;
            pid_t r = waitpid(pcscd, &code, WNOHANG);
            if (r == pcscd) {
                fputs("p11lab-opensc-pico: required pcscd exited during startup\n", stderr);
                pcscd = -1;
                goto cleanup;
            }
            r = waitpid(emulator, &code, WNOHANG);
            if (r == emulator) {
                fputs("p11lab-opensc-pico: required emulator exited during startup\n", stderr);
                emulator = -1;
                goto cleanup;
            }
            if (discover_reader(reader, sizeof(reader), atr_hex, sizeof(atr_hex))) {
                ready = 1;
                break;
            }
            pause_poll();
        }
        if (!ready || stopping) {
            if (!stopping) fputs("p11lab-opensc-pico: emulator/card not ready\n", stderr);
            goto cleanup;
        }
    }
    if (first) {
        if (pty_initialize(atr_hex, user, ulen, so, slen)) {
            fputs("p11lab-opensc-pico: native initialization failed\n", stderr);
            goto cleanup;
        }
        if (keygen(user, ulen)) {
            fputs("p11lab-opensc-pico: native key provisioning failed\n", stderr);
            goto cleanup;
        }
    }
    erase(user, sizeof(user)); erase(so, sizeof(so));
    child = fork_native(!strcmp(mode, "exec"));
    if (child < 0) goto cleanup;
    status = monitor(child, pcscd, "pcscd", emulator, "emulator");
    if (status || strcmp(mode, "exec")) goto cleanup;
    child = fork();
    if (child < 0) { status = 1; goto cleanup; }
    if (child == 0) {
        (void)setpgid(0, 0);
        execvp(argv[2], &argv[2]);
        perror("p11lab-opensc-pico: application exec");
        _exit(127);
    }
    (void)setpgid(child, child);
    status = monitor(child, pcscd, "pcscd", emulator, "emulator");
cleanup:
    erase(user, sizeof(user)); erase(so, sizeof(so));
    if (emulator > 0 && finish_child(emulator, 0)) status = 1;
    if (pcscd > 0 && finish_child(pcscd, 0)) status = 1;
    if (finish_adopted()) status = 1;
    (void)unlink(CONTROL "/pcscd.pid");
    (void)unlink(CONTROL "/emulator.pid");
    (void)unlink(SOCKET);
    (void)unlink(SOCKETDIR "/pcscd.pid");
    if (status) {
        show_log(LOGDIR "/pcscd.log"); show_log(LOGDIR "/emulator.log"); show_log(LOGDIR "/provision.log");
    }
out:
    erase(user, sizeof(user)); erase(so, sizeof(so));
    if (service >= 0) close(service);
    if (lease >= 0) close(lease);
    return stopping ? 128 + stopping : status;
}
