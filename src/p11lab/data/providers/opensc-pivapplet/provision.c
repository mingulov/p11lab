/* SPDX-License-Identifier: Apache-2.0
 * P11Lab original provisioning and Linux child supervision for the
 * opensc-pivapplet provider. Upstream pcscd, the vsmartcard ifd-vpcd
 * handler, the jcardsim VSmartCard emulator (JVM), the PivApplet
 * classes, the patched yubico-piv-tool, and the OpenSC module run
 * with pinned arguments; their return values and errors are
 * preserved, never normalized.
 *
 * The emulator is RAM-only (proven: nothing survives a JVM
 * restart), so EVERY operation provisions a fresh card: spawn
 * pcscd plus the JVM, install the caller PIN/PUK over the
 * factory defaults, generate plus selfsign plus import one
 * identity per PIV slot with yubico-piv-tool (caller secrets on
 * stdin pipes via --stdin-input, public artifacts in control-tmpfs
 * files, never secrets on argv), and prove the result with a
 * post-login native census. No card state persists across
 * operations by emulator design; re-provisioning is explicit
 * documented semantics, never a silent reset of persisted state
 * (there is none).
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
#define JAVA "/usr/lib/jvm/java-21-openjdk-amd64/bin/java"
#define CP "/usr/local/lib/p11lab/pivapplet/wrapper:/usr/local/lib/p11lab/pivapplet/jcardsim.jar:/usr/local/lib/p11lab/pivapplet/classes"
/* Native PIV bounds, proven: the user PIN and the PUK (unblock code)
 * are each 6..8 ASCII digits (the tool refuses shorter/longer; the
 * applet refuses non-digits with 6A80). NUL, CR and LF bytes can
 * never be provisioned exactly (C-string handling plus line-based
 * stdin reads) and are refused. */
#define PIN_MIN 6
#define PIN_MAX 8
#define PUK_MIN 6
#define PUK_MAX 8
#define CONTROL "/run/p11lab/opensc-pivapplet"
#define LOGDIR CONTROL "/logs"
#define SOCKETDIR "/run/pcscd"
#define SOCKET SOCKETDIR "/pcscd.comm"
#define OWNED "/var/lib/p11lab/opensc-pivapplet"
#define LEASE OWNED "/lease"
#define LABEL "piv-9a"
#define SLOT_ID 0
#define TOKEN_FLAGS 0x40d
#define TOKEN_MIN_PIN 4
#define TOKEN_MAX_PIN 8
#define MECHANISM_COUNT 32
#define OBJECT_TOTAL 28
#define OBJECT_PRIVKEYS 4
#define OBJECT_PUBKEYS 4
#define OBJECT_CERTS 4
#define OBJECT_DATA 15
#define OBJECT_PROFILES 1
#define LOG_BOUND 65536
#define TOOL_OUTPUT_BOUND 65536
#define TOOL_TIMEOUT_POLLS 2400
#define ATR_HEX "3BFA1800008131FE454A434F5033315632333298"
/* Frozen emulator ATR (jcardsim JCOP default, set explicitly; 20 bytes).
 * This ATR matches no entry in either frozen OpenSC PIV ATR table, so
 * the card binds the quirk-free BASE type on both channels. The
 * applet's own test ATR (3B80800101) instead collides with a real
 * PIVKey product entry and inherits its no-EC quirks on release
 * (and the entry differs by channel), so it must not be used. */
static const unsigned char ATR[20] = {
    0x3b, 0xfa, 0x18, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x4a, 0x43,
    0x4f, 0x50, 0x33, 0x31, 0x56, 0x32, 0x33, 0x32, 0x98
};
static const unsigned char SLOT_IDS[4] = {0x01, 0x02, 0x03, 0x04};
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
static int all_digits(const unsigned char *p, size_t length)
{
    size_t i;
    if (!length) return 0;
    for (i = 0; i < length; i++)
        if (p[i] < '0' || p[i] > '9') return 0;
    return 1;
}
/* Bounded stdin record: user LF puk. Both secrets are PIN_MIN..PIN_MAX
 * / PUK_MIN..PUK_MAX ASCII digits. Neither secret may contain NUL
 * (C-string handling), CR or LF (entry terminators). */
static int secrets(unsigned char *user, size_t *ulen, unsigned char *puk, size_t *plen)
{
    static unsigned char input[PIN_MAX + 1 + PUK_MAX + 1];
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
        *plen = length - *ulen - 1;
        if (*ulen >= PIN_MIN && *ulen <= PIN_MAX && *plen >= PUK_MIN && *plen <= PUK_MAX &&
            !memchr(input, '\r', length) && !memchr(input, '\0', length) &&
            all_digits(input, *ulen) && all_digits(separator + 1, *plen)) {
            bad = 0;
            memcpy(user, input, *ulen);
            memcpy(puk, separator + 1, *plen);
        }
    }
    erase(input, sizeof(input));
    return bad;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* ATR_HEX must decode to exactly ATR: the hex form pins the JVM card
 * identity and the byte form gates PCSC discovery, so a skew
 * between the two would silently select a different card. */
static int atr_consistent(void)
{
    size_t hexlen = strlen(ATR_HEX);
    size_t i;
    if (hexlen != 2 * sizeof(ATR)) return 0;
    for (i = 0; i < sizeof(ATR); i++) {
        int hi = hexval((unsigned char)ATR_HEX[2 * i]);
        int lo = hexval((unsigned char)ATR_HEX[2 * i + 1]);
        if (hi < 0 || lo < 0 || ATR[i] != (unsigned char)((hi << 4) | lo)) return 0;
    }
    return 1;
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
    while (f->C_FindObjects(session, handles, 64, &got) == CKR_OK && got > 0) {
        if (got > 64) return report("C_FindObjects", CKR_GENERAL_ERROR);
        *total += (unsigned)got;
    }
    rv = f->C_FindObjectsFinal(session);
    if (rv) return report("C_FindObjectsFinal", rv);
    return 0;
}

/* Post-login census: log in with the caller user PIN (which also
 * proves it) and verify the freshly provisioned card exactly: slot
 * 0 with the fixed label at token-present index 0, exact token
 * flags (a fresh card always carries the full PIN/PUK budget, so
 * no transient-bit mask is needed or allowed), exact PIN bounds,
 * the exact 32-mechanism roster with the required sign/derive
 * mechanisms present and both keygen mechanisms absent (on-card
 * keygen is natively unsupported), and the exact object census
 * (4 private keys + 4 public keys + 4 certificates + 15 data
 * objects + 1 driver profile object). Each provisioned CKA_ID
 * must select exactly its
 * private half, its public half and its certificate. Totals are
 * exact because applications cannot persist token objects on this
 * card: the census runs before the application starts. */
static int native(int quiet, int *slot_id, int *present_index, unsigned *objects,
                  const unsigned char *pin, size_t pin_len)
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
    unsigned have_rsa = 0, have_rsa256 = 0, have_ecdsa = 0, have_ecdh = 0, have_keygen = 0;
    unsigned certs = 0, pubkeys = 0, privkeys = 0, data = 0, profiles = 0;
    if (!module || strlen(LABEL) > sizeof(padded)) return 2;
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, LABEL, strlen(LABEL));
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-opensc-pivapplet: cannot load module\n", stderr); goto out; }
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
    if (count > 16) { fputs("p11lab-opensc-pivapplet: slot list exceeds bound\n", stderr); goto out; }
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
    if (!have) { fputs("p11lab-opensc-pivapplet: labelled token not present\n", stderr); goto out; }
    *slot_id = (int)found;
    if (*slot_id != SLOT_ID) {
        fprintf(stderr, "p11lab-opensc-pivapplet: native_slot=%d, want %d\n", *slot_id, SLOT_ID);
        goto out;
    }
    if (info.flags != TOKEN_FLAGS) {
        fprintf(stderr, "p11lab-opensc-pivapplet: token flags=0x%lx, want 0x%x\n",
                (unsigned long)info.flags, TOKEN_FLAGS);
        goto out;
    }
    if (info.ulMinPinLen != TOKEN_MIN_PIN || info.ulMaxPinLen != TOKEN_MAX_PIN) {
        fprintf(stderr, "p11lab-opensc-pivapplet: pin bounds=%lu/%lu, want %d/%d\n",
                info.ulMinPinLen, info.ulMaxPinLen, TOKEN_MIN_PIN, TOKEN_MAX_PIN);
        goto out;
    }
    mechanisms = 64;
    rv = f->C_GetMechanismList(found, list, &mechanisms);
    if (rv) { report("C_GetMechanismList", rv); goto out; }
    if (mechanisms != MECHANISM_COUNT) {
        fprintf(stderr, "p11lab-opensc-pivapplet: mechanisms=%lu, want %d\n",
                mechanisms, MECHANISM_COUNT);
        goto out;
    }
    /* Profile boundary, proven natively on both frozen channels:
     * the card offers raw RSA-PKCS plus SHA256_RSA_PKCS sign, raw
     * CKM_ECDSA plus ECDSA-SHA256 sign, and ECDH1_DERIVE derive,
     * but NO on-card keygen (neither RSA nor EC roster entries
     * exist). The census gates on the RSA pair plus raw ECDSA sign
     * plus ECDH derive, and requires both keygen mechanisms to be
     * absent. Mechanism flags are presence-gated because this
     * driver reports ORed-across-algorithm flags, while actual
     * sign/derive behavior is proven by the suite with independent
     * oracles. */
    for (CK_ULONG i = 0; i < mechanisms; i++) {
        if (list[i] == CKM_RSA_PKCS_KEY_PAIR_GEN ||
            list[i] == CKM_EC_KEY_PAIR_GEN) have_keygen = 1;
        if (list[i] == CKM_RSA_PKCS) {
            CK_MECHANISM_INFO details;
            rv = f->C_GetMechanismInfo(found, list[i], &details);
            if (rv) { report("C_GetMechanismInfo", rv); goto out; }
            if (details.flags & CKF_SIGN) have_rsa = 1;
        }
        if (list[i] == CKM_SHA256_RSA_PKCS) have_rsa256 = 1;
        if (list[i] == CKM_ECDSA) {
            CK_MECHANISM_INFO details;
            rv = f->C_GetMechanismInfo(found, list[i], &details);
            if (rv) { report("C_GetMechanismInfo", rv); goto out; }
            if (details.flags & CKF_SIGN) have_ecdsa = 1;
        }
        if (list[i] == CKM_ECDH1_DERIVE) {
            CK_MECHANISM_INFO details;
            rv = f->C_GetMechanismInfo(found, list[i], &details);
            if (rv) { report("C_GetMechanismInfo", rv); goto out; }
            if (details.flags & CKF_DERIVE) have_ecdh = 1;
        }
    }
    if (!have_rsa || !have_rsa256 || !have_ecdsa || !have_ecdh || have_keygen) {
        fputs("p11lab-opensc-pivapplet: required mechanisms unavailable\n", stderr);
        goto out;
    }
    rv = f->C_OpenSession(found, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv) { report("C_OpenSession", rv); goto out; }
    rv = f->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)pin_len);
    if (rv) { report("C_Login", rv); goto out; }
    if (count_objects(f, session, CKO_CERTIFICATE, &certs) ||
        count_objects(f, session, CKO_PUBLIC_KEY, &pubkeys) ||
        count_objects(f, session, CKO_PRIVATE_KEY, &privkeys) ||
        count_objects(f, session, CKO_DATA, &data) ||
        count_objects(f, session, CKO_PROFILE, &profiles) ||
        count_objects(f, session, (CK_OBJECT_CLASS)~0UL, objects)) goto out;
    if (privkeys != OBJECT_PRIVKEYS || pubkeys != OBJECT_PUBKEYS ||
        certs != OBJECT_CERTS || data != OBJECT_DATA || profiles != OBJECT_PROFILES ||
        *objects != OBJECT_TOTAL) {
        fprintf(stderr, "p11lab-opensc-pivapplet: census priv=%u pub=%u certs=%u data=%u profiles=%u total=%u, want %d/%d/%d/%d/%d/%d\n",
                privkeys, pubkeys, certs, data, profiles, *objects,
                OBJECT_PRIVKEYS, OBJECT_PUBKEYS, OBJECT_CERTS, OBJECT_DATA,
                OBJECT_PROFILES, OBJECT_TOTAL);
        goto out;
    }
    for (unsigned k = 0; k < 4; k++) {
        static const CK_OBJECT_CLASS classes[3] = {CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE};
        for (unsigned pass = 0; pass < 3; pass++) {
            CK_OBJECT_CLASS class = classes[pass];
            CK_ATTRIBUTE filter[2];
            CK_OBJECT_HANDLE handles[4];
            CK_ULONG got = 0;
            filter[0].type = CKA_CLASS; filter[0].pValue = &class;
            filter[0].ulValueLen = sizeof(class);
            filter[1].type = CKA_ID; filter[1].pValue = (void *)&SLOT_IDS[k];
            filter[1].ulValueLen = 1;
            rv = f->C_FindObjectsInit(session, filter, 2);
            if (rv) { report("C_FindObjectsInit", rv); goto out; }
            rv = f->C_FindObjects(session, handles, 4, &got);
            if (rv) { report("C_FindObjects", rv); goto out; }
            rv = f->C_FindObjectsFinal(session);
            if (rv) { report("C_FindObjectsFinal", rv); goto out; }
            if (got != 1) {
                fprintf(stderr, "p11lab-opensc-pivapplet: census id=0x%02x class=%lu selects %lu objects, want 1\n",
                        SLOT_IDS[k], (unsigned long)class, (unsigned long)got);
                goto out;
            }
        }
    }
    if (!quiet)
        printf("ready: native_slot=%d token_present_index=%d label=%s objects=%u\n",
               *slot_id, *present_index, LABEL, *objects);
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
    fputs("p11lab-opensc-pivapplet: shutdown grace expired; killing owned child\n", stderr);
    (void)kill(group ? -pid : pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 1;
}
/* Spawn a service with stdout/stderr appended to its bounded log file.
 * The JVM runs with its working directory at the control directory
 * (writable tmpfs; it writes only /tmp/hsperfdata, proven). */
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
 * it starts listening). The JVM spawns only after this holds: its
 * single startup connect has no retry (the constructor throws when
 * vpcd is unreachable and the JVM exits nonzero). */
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
/* Reader discovery: exactly one vpcd reader with a card present
 * (vpcd exposes two slots; the JVM connects once), presenting the
 * frozen JCOP ATR. Any other topology fails closed. */
static int discover_reader(char *name, size_t capacity)
{
    SCARDCONTEXT context = 0;
    LONG rc;
    DWORD length = 0;
    char *list = NULL;
    unsigned with_card = 0;
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
                status = 1;
            }
        }
    }
    free(list);
    SCardReleaseContext(context);
    return status && with_card == 1;
}

/* Run one yubico-piv-tool provisioning invocation: secrets travel on
 * a stdin pipe (the tool's --stdin-input mode reads line-based PINs
 * there), public artifacts travel in control-tmpfs files named on
 * argv, and nothing secret ever appears on argv, in the environment
 * or on disk. The child's combined output is captured in a bounded
 * buffer, checked for the exact expected success markers, then
 * erased; only fixed stage-ok lines join provision.log. Exit code,
 * markers and (for selfsign) the certificate file size are all
 * asserted: any deviation fails the operation. Bounded; a stalled
 * child is TERM/KILL-reaped and fails loudly. */
static int run_ykpiv(char *const argv[], const unsigned char *stdin_data, size_t stdin_len,
                     const char *want1, const char *want2, const char *stagename)
{
    static unsigned char output[TOOL_OUTPUT_BOUND];
    int in_pipe[2] = {-1, -1}, out_pipe[2] = {-1, -1}, err_pipe[2] = {-1, -1};
    size_t length = 0, written = 0;
    int status = 1, child_status = 0, out = -1;
    pid_t child = -1;
    memset(output, 0, sizeof(output));
    if (pipe(in_pipe) || pipe(out_pipe) || pipe(err_pipe)) goto done;
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        if (dup2(in_pipe[0], STDIN_FILENO) < 0 || dup2(out_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(err_pipe[1], STDERR_FILENO) < 0) _exit(127);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(in_pipe[0]); in_pipe[0] = -1;
    close(out_pipe[1]); out_pipe[1] = -1;
    close(err_pipe[1]); err_pipe[1] = -1;
    out = open(LOGDIR "/provision.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) { (void)finish_child(child, 0); goto done; }
    for (int i = 0; i < TOOL_TIMEOUT_POLLS && !stopping; i++) {
        struct pollfd watch[2];
        pid_t r = waitpid(child, &child_status, WNOHANG);
        if (r == child) break;
        if (r < 0 && errno == ECHILD) break;
        if (written < stdin_len) {
            ssize_t n = write(in_pipe[1], stdin_data + written, stdin_len - written);
            if (n <= 0) goto done;
            written += (size_t)n;
            if (written == stdin_len) { close(in_pipe[1]); in_pipe[1] = -1; }
        } else if (in_pipe[1] >= 0) {
            close(in_pipe[1]); in_pipe[1] = -1;
        }
        watch[0].fd = out_pipe[0]; watch[0].events = POLLIN;
        watch[1].fd = err_pipe[0]; watch[1].events = POLLIN;
        if (poll(watch, 2, 50) <= 0) continue;
        for (int k = 0; k < 2; k++) {
            int fd = k ? err_pipe[0] : out_pipe[0];
            if (watch[k].revents & POLLIN) {
                ssize_t n = read(fd, output + length, sizeof(output) - length);
                if (n > 0) length += (size_t)n;
                if (length == sizeof(output)) goto done;
            }
        }
    }
    if (stopping) goto done;
    {
        pid_t settled = waitpid(child, &child_status, WNOHANG);
        if (settled == 0) {
            fputs("p11lab-opensc-pivapplet: provisioning tool stalled; failing bounded\n", stderr);
            (void)finish_child(child, 0);
            child = -1;
            goto done;
        }
        if (settled < 0 && errno != ECHILD) goto done;
    }
    /* Drain any output that arrived with the exit. */
    for (;;) {
        ssize_t n = read(out_pipe[0], output + length, sizeof(output) - length);
        if (n <= 0) break;
        length += (size_t)n;
        if (length == sizeof(output)) goto done;
    }
    for (;;) {
        ssize_t n = read(err_pipe[0], output + length, sizeof(output) - length);
        if (n <= 0) break;
        length += (size_t)n;
        if (length == sizeof(output)) goto done;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        fprintf(stderr, "p11lab-opensc-pivapplet: provision %s failed\n", stagename);
        goto done;
    }
    if (!memmem(output, length, want1, strlen(want1))) {
        fprintf(stderr, "p11lab-opensc-pivapplet: provision %s missing marker\n", stagename);
        goto done;
    }
    if (want2 && !memmem(output, length, want2, strlen(want2))) {
        fprintf(stderr, "p11lab-opensc-pivapplet: provision %s missing marker\n", stagename);
        goto done;
    }
    {
        char line[128];
        int line_len = snprintf(line, sizeof(line), "provision %s ok\n", stagename);
        if (line_len <= 0 || line_len >= (int)sizeof(line) ||
            write(out, line, (size_t)line_len) != line_len) goto done;
    }
    status = 0;
done:
    erase(output, sizeof(output));
    if (out >= 0) close(out);
    if (in_pipe[0] >= 0) close(in_pipe[0]);
    if (in_pipe[1] >= 0) close(in_pipe[1]);
    if (out_pipe[0] >= 0) close(out_pipe[0]);
    if (out_pipe[1] >= 0) close(out_pipe[1]);
    if (err_pipe[0] >= 0) close(err_pipe[0]);
    if (err_pipe[1] >= 0) close(err_pipe[1]);
    if (child > 0 && waitpid(child, &child_status, WNOHANG) != child) (void)finish_child(child, 0);
    return status;
}

static void unlink_tmp(const char *slot)
{
    char pub[64], cert[64];
    snprintf(pub, sizeof(pub), CONTROL "/prov-pub-%s", slot);
    snprintf(cert, sizeof(cert), CONTROL "/prov-cert-%s", slot);
    (void)unlink(pub);
    (void)unlink(cert);
}

static int seal_tmp(const char *slot)
{
    /* Pre-seal the per-slot artifact files at 0600 so no umask or
     * inherited ACL can widen them; the tool truncates in place. */
    char pub[64], cert[64];
    int fd;
    snprintf(pub, sizeof(pub), CONTROL "/prov-pub-%s", slot);
    snprintf(cert, sizeof(cert), CONTROL "/prov-cert-%s", slot);
    fd = open(pub, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 1;
    close(fd);
    fd = open(cert, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 1;
    close(fd);
    return 0;
}

/* Fresh-card PIV provisioning: install the caller PIN/PUK over the
 * factory defaults, then generate plus selfsign plus import one
 * identity per slot (9a ECCP256, 9c RSA2048, 9d ECCP256, 9e
 * ECCP384). The management key stays the tool-default 3DES key
 * (auto-applied by the tool, never a caller secret). Every stage
 * asserts its exact native success markers; the reader is the
 * ATR-pinned exact name (never the substring match). Secrets
 * travel on stdin pipes only. */
static int provision_piv(const unsigned char *user, size_t ulen,
                         const unsigned char *puk, size_t plen,
                         const char *reader)
{
    static const char *slots[4] = {"9a", "9c", "9d", "9e"};
    static const char *algos[4] = {"ECCP256", "RSA2048", "ECCP256", "ECCP384"};
    static const char *subjects[4] = {"/CN=piv-9a/", "/CN=piv-9c/", "/CN=piv-9d/", "/CN=piv-9e/"};
    static unsigned char stdin_buf[PIN_MAX + 1 + PIN_MAX + 1];
    char at_reader[280], pub[64], cert[64];
    char *argv[16];
    int status = 1;
    if (snprintf(at_reader, sizeof(at_reader), "@%s", reader) >= (int)sizeof(at_reader)) return 1;
    /* change-pin over the factory default (idempotent: re-setting
     * the default value succeeds natively, so no equality branch). */
    memcpy(stdin_buf, "123456\n", 7);
    memcpy(stdin_buf + 7, user, ulen);
    stdin_buf[7 + ulen] = '\n';
    argv[0] = TOOL; argv[1] = "-r"; argv[2] = at_reader; argv[3] = "--stdin-input";
    argv[4] = "-a"; argv[5] = "change-pin"; argv[6] = NULL;
    if (run_ykpiv(argv, stdin_buf, 7 + ulen + 1,
                  "Successfully changed the pin code.", NULL, "change-pin")) goto out;
    memcpy(stdin_buf, "12345678\n", 9);
    memcpy(stdin_buf + 9, puk, plen);
    stdin_buf[9 + plen] = '\n';
    argv[5] = "change-puk";
    if (run_ykpiv(argv, stdin_buf, 9 + plen + 1,
                  "Successfully changed the puk code.", NULL, "change-puk")) goto out;
    for (unsigned k = 0; k < 4; k++) {
        struct stat s;
        if (seal_tmp(slots[k])) goto out;
        snprintf(pub, sizeof(pub), CONTROL "/prov-pub-%s", slots[k]);
        snprintf(cert, sizeof(cert), CONTROL "/prov-cert-%s", slots[k]);
        /* Slot 9c is generated with --pin-policy once: the applet
         * maps generate-with-default on 9c to PIN_ALWAYS (9a/9d map
         * to ONCE, 9e to NEVER), and OpenSC never learns per-slot
         * PIN policies (it reads only the discovery-object global
         * policy) while always issuing a read between VERIFY and
         * the GENERAL AUTHENTICATE final block -- so a
         * PIN_ALWAYS 9c key could never sign through this
         * driver (6982, surfaced as 0x101). The policy is a
         * native provisioning-time key attribute (same class as
         * the algorithm choice); the applet's PIN_ALWAYS
         * enforcement itself is untouched. */
        argv[0] = TOOL; argv[1] = "-r"; argv[2] = at_reader;
        argv[3] = "-a"; argv[4] = "generate"; argv[5] = "-s"; argv[6] = (char *)slots[k];
        argv[7] = "-A"; argv[8] = (char *)algos[k];
        if (!strcmp(slots[k], "9c")) {
            argv[9] = "--pin-policy"; argv[10] = "once";
            argv[11] = "-o"; argv[12] = pub; argv[13] = NULL;
        } else {
            argv[9] = "-o"; argv[10] = pub; argv[11] = NULL;
        }
        if (run_ykpiv(argv, NULL, 0,
                      "Successfully generated a new private key.", NULL, slots[k])) {
            unlink_tmp(slots[k]);
            goto out;
        }
        memcpy(stdin_buf, user, ulen);
        stdin_buf[ulen] = '\n';
        {
            /* The selfsign invocation needs 16 words plus NULL. */
            char *selfsign_argv[17];
            selfsign_argv[0] = TOOL; selfsign_argv[1] = "-r"; selfsign_argv[2] = at_reader;
            selfsign_argv[3] = "--stdin-input"; selfsign_argv[4] = "-a"; selfsign_argv[5] = "verify-pin";
            selfsign_argv[6] = "-a"; selfsign_argv[7] = "selfsign-certificate";
            selfsign_argv[8] = "-s"; selfsign_argv[9] = (char *)slots[k];
            selfsign_argv[10] = "-S"; selfsign_argv[11] = (char *)subjects[k];
            selfsign_argv[12] = "-i"; selfsign_argv[13] = pub;
            selfsign_argv[14] = "-o"; selfsign_argv[15] = cert; selfsign_argv[16] = NULL;
            if (run_ykpiv(selfsign_argv, stdin_buf, ulen + 1,
                          "Successfully verified PIN.",
                          "Successfully generated a new self signed certificate.",
                          slots[k])) {
                unlink_tmp(slots[k]);
                goto out;
            }
        }
        if (stat(cert, &s) || !S_ISREG(s.st_mode) || s.st_size < 200 || s.st_size > 8192) {
            fprintf(stderr, "p11lab-opensc-pivapplet: provision %s bad certificate size\n", slots[k]);
            unlink_tmp(slots[k]);
            goto out;
        }
        argv[0] = TOOL; argv[1] = "-r"; argv[2] = at_reader;
        argv[3] = "-a"; argv[4] = "import-certificate"; argv[5] = "-s";
        argv[6] = (char *)slots[k]; argv[7] = "-i"; argv[8] = cert; argv[9] = NULL;
        if (run_ykpiv(argv, NULL, 0,
                      "Successfully imported a new certificate.", NULL, slots[k])) {
            unlink_tmp(slots[k]);
            goto out;
        }
        unlink_tmp(slots[k]);
    }
    status = 0;
out:
    erase(stdin_buf, sizeof(stdin_buf));
    for (unsigned k = 0; k < 4; k++) unlink_tmp(slots[k]);
    return status;
}

static pid_t fork_native(int quiet, const unsigned char *pin, size_t pin_len)
{
    pid_t child = fork();
    if (child == 0) {
        int slot_id = 0, present = 0;
        unsigned objects = 0;
        int status;
        (void)setpgid(0, 0);
        if (quiet && !freopen("/dev/null", "w", stdout)) _exit(1);
        status = native(quiet, &slot_id, &present, &objects, pin, pin_len);
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
                fprintf(stderr, "p11lab-opensc-pivapplet: required %s exited during operation\n", first_name);
                (void)finish_child(child, 1);
                return 1;
            }
        }
        if (second > 0) {
            int code;
            if (waitpid(second, &code, WNOHANG) == second) {
                fprintf(stderr, "p11lab-opensc-pivapplet: required %s exited during operation\n", second_name);
                (void)finish_child(child, 1);
                return 1;
            }
        }
        if (stopping || log_bounded(LOGDIR "/pcscd.log") || log_bounded(LOGDIR "/emulator.log") ||
            log_bounded(LOGDIR "/provision.log")) {
            if (!stopping) fputs("p11lab-opensc-pivapplet: service log exceeded bound\n", stderr);
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
    static unsigned char user[PIN_MAX + 1], puk[PUK_MAX + 1];
    static char reader[256];
    size_t ulen = 0, plen = 0;
    pid_t pcscd = -1, emulator = -1;
    char *pcscd_argv[4], *emulator_argv[10];
    pid_t child = -1;
    int status = 1, lease = -1, service = -1;
    struct stat s;
    struct sigaction action;
    const char *mode;
    if (argc < 2 || (strcmp(argv[1], "init") && strcmp(argv[1], "health") && strcmp(argv[1], "exec")) ||
        (!strcmp(argv[1], "exec") ? argc < 3 : argc != 2)) return 2;
    mode = argv[1];
    umask(077);
    if (!atr_consistent()) {
        fputs("p11lab-opensc-pivapplet: frozen ATR forms disagree\n", stderr);
        return 2;
    }
    /* The card is RAM-only, so every operation provisions a fresh
     * card and every operation consumes caller credentials. */
    if (secrets(user, &ulen, puk, &plen)) {
        fputs("p11lab-opensc-pivapplet: credential record refused\n", stderr);
        goto out;
    }
    lease = open(LEASE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (!protected_file(lease) || flock(lease, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-opensc-pivapplet: state is unsafe or already in use\n", stderr); goto out;
    }
    service = open(CONTROL "/service-lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (!protected_file(service) || flock(service, LOCK_EX | LOCK_NB)) {
        fputs("p11lab-opensc-pivapplet: control directory is unsafe or already in use\n", stderr); goto out;
    }
    if (!lstat(CONTROL "/pcscd.pid", &s) || !lstat(CONTROL "/emulator.pid", &s) ||
        !lstat(SOCKET, &s) || !lstat(SOCKETDIR "/pcscd.pid", &s)) {
        fputs("p11lab-opensc-pivapplet: occupied daemon control state\n", stderr); goto out;
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
     * listed (proving the handler is loaded and listening). The JVM
     * spawns only after this: its single startup connect has no
     * retry. Bounded; a dead daemon fails fast with its logs. */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !stopping; i++) {
            int code;
            pid_t r = waitpid(pcscd, &code, WNOHANG);
            if (r == pcscd) {
                fputs("p11lab-opensc-pivapplet: required pcscd exited during startup\n", stderr);
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
            if (!stopping) fputs("p11lab-opensc-pivapplet: pcscd/vpcd not ready\n", stderr);
            goto cleanup;
        }
    }
    emulator_argv[0] = JAVA; emulator_argv[1] = "-cp"; emulator_argv[2] = CP;
    emulator_argv[3] = "PivAppletCard"; emulator_argv[4] = "127.0.0.1";
    emulator_argv[5] = "35963"; emulator_argv[6] = ATR_HEX;
    emulator_argv[7] = "A000000308000010000100";
    emulator_argv[8] = "net.cooperi.pivapplet.PivApplet";
    emulator_argv[9] = NULL;
    emulator = spawn_service(emulator_argv, LOGDIR "/emulator.log", CONTROL "/emulator.pid", CONTROL);
    if (emulator <= 0) goto cleanup;
    /* Phase 2: the emulator-backed reader with its ATR match, proving
     * the vpcd loopback path plus the live card, never process-alive
     * alone. Then the per-operation fresh-card provisioning plus the
     * native census. Bounded; a dead service fails fast with its
     * logs. */
    {
        int ready = 0;
        for (int i = 0; i < 600 && !stopping; i++) {
            int code;
            pid_t r = waitpid(pcscd, &code, WNOHANG);
            if (r == pcscd) {
                fputs("p11lab-opensc-pivapplet: required pcscd exited during startup\n", stderr);
                pcscd = -1;
                goto cleanup;
            }
            r = waitpid(emulator, &code, WNOHANG);
            if (r == emulator) {
                fputs("p11lab-opensc-pivapplet: required emulator exited during startup\n", stderr);
                emulator = -1;
                goto cleanup;
            }
            if (discover_reader(reader, sizeof(reader))) {
                ready = 1;
                break;
            }
            pause_poll();
        }
        if (!ready || stopping) {
            if (!stopping) fputs("p11lab-opensc-pivapplet: emulator/card not ready\n", stderr);
            goto cleanup;
        }
    }
    if (provision_piv(user, ulen, puk, plen, reader)) {
        fputs("p11lab-opensc-pivapplet: native initialization failed\n", stderr);
        goto cleanup;
    }
    erase(puk, sizeof(puk));
    child = fork_native(!strcmp(mode, "exec"), user, ulen);
    if (child < 0) goto cleanup;
    erase(user, sizeof(user));
    status = monitor(child, pcscd, "pcscd", emulator, "emulator");
    if (status || strcmp(mode, "exec")) goto cleanup;
    child = fork();
    if (child < 0) { status = 1; goto cleanup; }
    if (child == 0) {
        (void)setpgid(0, 0);
        execvp(argv[2], &argv[2]);
        perror("p11lab-opensc-pivapplet: application exec");
        _exit(127);
    }
    (void)setpgid(child, child);
    status = monitor(child, pcscd, "pcscd", emulator, "emulator");
cleanup:
    erase(user, sizeof(user)); erase(puk, sizeof(puk));
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
    erase(user, sizeof(user)); erase(puk, sizeof(puk));
    if (service >= 0) close(service);
    if (lease >= 0) close(lease);
    return stopping ? 128 + stopping : status;
}
