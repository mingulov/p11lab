/* SPDX-License-Identifier: Apache-2.0 */
/* Original P11Lab application. No checker binding or crypto library dependency. */
#include "vendor/pkcs11.h"
#include "p256.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
typedef HMODULE Module;
#define make_directory(path) _mkdir(path)
#else
#include <dlfcn.h>
#include <sys/stat.h>
typedef void *Module;
#define make_directory(path) mkdir(path, 0700)
#endif

#define MAX_ENUM 4096UL
#define MAX_ATTRIBUTE 1024UL
#define MAX_PIN 4096
#define MAX_PATH_BYTES 4096
#define COUNT(a) ((CK_ULONG)(sizeof(a) / sizeof((a)[0])))

static const unsigned char message[] = "P11Lab independent PKCS11 smoke v1\n";
/* SHA256(message excluding the C terminating NUL); independently checked in tests. */
static const unsigned char digest[32] = {
    0xe8,0x23,0x4d,0xb4,0xec,0x58,0xc8,0x6b,0xb2,0xf2,0x25,0x42,0x3b,0xc8,0xd8,0xee,
    0x8a,0xbd,0xc5,0x28,0xae,0xf8,0x8c,0x92,0xdf,0x63,0x2f,0x82,0xa9,0x15,0x73,0xf3
};
static const unsigned char p256_oid[] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};

typedef struct {
    const char *module, *label, *pin_file, *output, *mode, *key_id, *public_key;
    unsigned char id[128];
    CK_ULONG id_length;
} Options;

typedef struct {
    Module module;
    CK_FUNCTION_LIST_PTR f;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE public_key, private_key;
    int initialized, session_open, logged_in, generated;
} State;

static void usage(FILE *stream)
{
    fputs("p11lab-smoke --module PATH --token-label LABEL [--pin-file PATH] --output DIR\n"
          "             --key-mode generated|existing [--key-id HEX] [--public-key DER_PATH]\n"
          "PIN files contain exact raw PIN bytes, with no newline trimming.\n"
          "Existing mode requires a nonempty hexadecimal CKA_ID. Public input is P256 DER/SPKI.\n"
          "Output must be a new directory with an existing parent.\n", stream);
}

static int error(const char *text)
{
    fprintf(stderr, "p11lab-smoke: %s\n", text);
    return 0;
}

static int native(const char *operation, CK_RV rv)
{
    if (rv == CKR_OK) return 1;
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", operation, (unsigned long)rv);
    return 0;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int options(int argc, char **argv, Options *o)
{
    int i;
    memset(o, 0, sizeof(*o));
    for (i = 1; i < argc; i += 2) {
        const char **target = NULL;
        if (strcmp(argv[i], "--module") == 0) target = &o->module;
        else if (strcmp(argv[i], "--token-label") == 0) target = &o->label;
        else if (strcmp(argv[i], "--pin-file") == 0) target = &o->pin_file;
        else if (strcmp(argv[i], "--output") == 0) target = &o->output;
        else if (strcmp(argv[i], "--key-mode") == 0) target = &o->mode;
        else if (strcmp(argv[i], "--key-id") == 0) target = &o->key_id;
        else if (strcmp(argv[i], "--public-key") == 0) target = &o->public_key;
        if (!target || i + 1 == argc || *target) return error("invalid, repeated or incomplete option");
        *target = argv[i + 1];
    }
    if (!o->module || !o->module[0] || !o->label || !o->label[0] ||
        strlen(o->label) > 32 || !o->output || !o->output[0] || !o->mode)
        return error("module, token label (1..32 bytes), output and key mode required");
    if (strcmp(o->mode, "generated") == 0) {
        if (o->key_id || o->public_key) return error("key selection only applies to existing mode");
    } else if (strcmp(o->mode, "existing") == 0) {
        size_t n, j;
        if (!o->key_id) return error("existing mode requires --key-id HEX");
        n = strlen(o->key_id);
        if (!n || n % 2 || n > sizeof(o->id) * 2) return error("invalid key ID length");
        for (j = 0; j < n; j += 2) {
            int a = hex_digit(o->key_id[j]), b = hex_digit(o->key_id[j + 1]);
            if (a < 0 || b < 0) return error("key ID must be hexadecimal");
            o->id[j / 2] = (unsigned char)(a * 16 + b);
        }
        o->id_length = (CK_ULONG)(n / 2);
    } else return error("key mode must be generated or existing");
    return 1;
}

/* MSVC deprecates fopen as C4996 (fatal under this repo's /WX Windows gate);
 * fopen_s is behavior-identical for these fixed binary modes. */
static FILE *open_binary(const char *path, const char *mode)
{
#ifdef _MSC_VER
    FILE *file = NULL;
    if (fopen_s(&file, path, mode) != 0) return NULL;
    return file;
#else
    return fopen(path, mode);
#endif
}

/* No path, content, or credential-derived value is echoed on read failures. */
static int read_bounded(const char *path, unsigned char *buffer, size_t capacity, size_t *length)
{
    FILE *file = open_binary(path, "rb");
    int extra, failed;
    if (!file) return error("cannot open input file");
    *length = fread(buffer, 1, capacity, file);
    extra = fgetc(file);
    failed = ferror(file) || extra != EOF;
    if (fclose(file) != 0) failed = 1;
    if (failed) return error("input read failed or exceeded size limit");
    return 1;
}

static void wipe(unsigned char *p, size_t length)
{
    volatile unsigned char *v = p;
    while (length--) *v++ = 0;
}

static int load_module(State *s)
{
    CK_C_GetFunctionList get_list = NULL;
    CK_C_GetInterface get_interface = NULL;
#ifdef _WIN32
    FARPROC symbol;
    symbol = GetProcAddress(s->module, "C_GetInterface");
    memcpy(&get_interface, &symbol, sizeof(get_interface));
    symbol = GetProcAddress(s->module, "C_GetFunctionList");
    memcpy(&get_list, &symbol, sizeof(get_list));
#else
    void *symbol = dlsym(s->module, "C_GetInterface");
    _Static_assert(sizeof(symbol) == sizeof(get_interface), "function pointer ABI");
    memcpy(&get_interface, &symbol, sizeof(get_interface));
    symbol = dlsym(s->module, "C_GetFunctionList");
    memcpy(&get_list, &symbol, sizeof(get_list));
#endif
    if (get_interface) {
        CK_INTERFACE_PTR selected_interface = NULL;
        if (!native("C_GetInterface", get_interface((CK_UTF8CHAR_PTR)"PKCS 11", NULL, &selected_interface, 0))) return 0;
        if (!selected_interface || !selected_interface->pFunctionList) return error("provider returned null interface");
        s->f = (CK_FUNCTION_LIST_PTR)selected_interface->pFunctionList;
    } else {
        if (!get_list) return error("module has no PKCS11 discovery entry point");
        if (!native("C_GetFunctionList", get_list(&s->f))) return 0;
    }
    if (!s->f || (s->f->version.major != 2 && s->f->version.major != 3)) return error("unsupported or null PKCS11 function list");
    if (!s->f->C_Initialize || !s->f->C_Finalize || !s->f->C_GetInfo ||
        !s->f->C_GetSlotList || !s->f->C_GetSlotInfo || !s->f->C_GetTokenInfo ||
        !s->f->C_GetMechanismList || !s->f->C_GetMechanismInfo || !s->f->C_OpenSession ||
        !s->f->C_GetSessionInfo || !s->f->C_CloseSession || !s->f->C_Login || !s->f->C_Logout ||
        !s->f->C_GetAttributeValue || !s->f->C_FindObjectsInit || !s->f->C_FindObjects ||
        !s->f->C_FindObjectsFinal || !s->f->C_SignInit || !s->f->C_Sign)
        return error("provider function list lacks required operations");
    return 1;
}

static int select_slot(State *s, const Options *o, CK_SLOT_ID *selected, CK_TOKEN_INFO *token)
{
    CK_SLOT_ID slots[MAX_ENUM];
    CK_ULONG count = 0, capacity, i, matches = 0;
    unsigned char wanted[32];
    memset(wanted, ' ', sizeof(wanted));
    memcpy(wanted, o->label, strlen(o->label));
    if (!native("C_GetSlotList(size)", s->f->C_GetSlotList(CK_TRUE, NULL, &count))) return 0;
    if (count > MAX_ENUM) return error("slot list exceeds bound");
    capacity = count;
    if (!native("C_GetSlotList", s->f->C_GetSlotList(CK_TRUE, slots, &count))) return 0;
    if (count > capacity) return error("provider slot count exceeds supplied capacity");
    for (i = 0; i < count; ++i) {
        CK_TOKEN_INFO info;
        if (!native("C_GetTokenInfo", s->f->C_GetTokenInfo(slots[i], &info))) return 0;
        if (memcmp(info.label, wanted, sizeof(wanted)) == 0) {
            *selected = slots[i];
            *token = info;
            ++matches;
        }
    }
    if (!matches) return error("no token matches the exact padded label");
    if (matches != 1) return error("multiple tokens match the label");
    return 1;
}

static int mechanisms(State *s, CK_SLOT_ID slot, int generated)
{
    CK_MECHANISM_TYPE list[MAX_ENUM];
    CK_ULONG count = 0, capacity, i;
    int sign = 0, generate = 0;
    CK_MECHANISM_INFO info;
    if (!native("C_GetMechanismList(size)", s->f->C_GetMechanismList(slot, NULL, &count))) return 0;
    if (count > MAX_ENUM) return error("mechanism list exceeds bound");
    capacity = count;
    if (!native("C_GetMechanismList", s->f->C_GetMechanismList(slot, list, &count))) return 0;
    if (count > capacity) return error("provider mechanism count exceeds supplied capacity");
    for (i = 0; i < count; ++i) {
        if (list[i] == CKM_ECDSA) sign = 1;
        if (list[i] == CKM_EC_KEY_PAIR_GEN) generate = 1;
    }
    if (!sign || (generated && !generate)) return error("required ECDSA mechanism unavailable");
    if (!native("C_GetMechanismInfo(ECDSA)", s->f->C_GetMechanismInfo(slot, CKM_ECDSA, &info))) return 0;
    if (!(info.flags & CKF_SIGN)) return error("ECDSA mechanism cannot sign");
    if (generated) {
        if (!native("C_GetMechanismInfo(EC_KEY_PAIR_GEN)",
                    s->f->C_GetMechanismInfo(slot, CKM_EC_KEY_PAIR_GEN, &info))) return 0;
        if (!(info.flags & CKF_GENERATE_KEY_PAIR)) return error("EC mechanism cannot generate key pairs");
    }
    return 1;
}

static int find_key(State *s, CK_OBJECT_CLASS key_class, const Options *o,
                    CK_OBJECT_HANDLE *key, int required)
{
    CK_KEY_TYPE key_type = CKK_EC;
    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)}, {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ID, (void *)o->id, o->id_length}
    };
    CK_OBJECT_HANDLE found[2];
    CK_ULONG count = 0;
    CK_RV rv = CKR_OK, final_rv;
    int valid = 1;
    if (!native("C_FindObjectsInit", s->f->C_FindObjectsInit(s->session, attrs, COUNT(attrs)))) return 0;
    /* A provider may yield fewer objects than requested without ending the search. */
    while (count < 2) {
        CK_ULONG page = 0, capacity = 2 - count;
        rv = s->f->C_FindObjects(s->session, found + count, capacity, &page);
        if (rv != CKR_OK) break;
        if (page > capacity) { valid = error("object count exceeds supplied capacity"); break; }
        count += page;
        if (page == 0) break;
    }
    final_rv = s->f->C_FindObjectsFinal(s->session);
    if (!native("C_FindObjects", rv) || !valid) { native("C_FindObjectsFinal(cleanup)", final_rv); return 0; }
    if (!native("C_FindObjectsFinal", final_rv)) return 0;
    if (count > 1) return error("key ID selects multiple EC objects of the requested class");
    if (!count) {
        if (required) return error("key ID selects no EC private key");
        *key = CK_INVALID_HANDLE;
    } else *key = found[0];
    return 1;
}

static int generate_keys(State *s)
{
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
    CK_ATTRIBUTE public_attrs[] = {
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_EC_PARAMS, (void *)p256_oid, sizeof(p256_oid)}
    };
    CK_ATTRIBUTE private_attrs[] = {
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SIGN, &yes, sizeof(yes)}, {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)}
    };
    if (!s->f->C_GenerateKeyPair || !s->f->C_DestroyObject)
        return error("provider lacks generation or generated-object cleanup operations");
    if (!native("C_GenerateKeyPair", s->f->C_GenerateKeyPair(s->session, &mechanism,
                public_attrs, COUNT(public_attrs), private_attrs, COUNT(private_attrs),
                &s->public_key, &s->private_key))) return 0;
    s->generated = 1;
    return 1;
}

static int attribute(State *s, CK_OBJECT_HANDLE key, CK_ATTRIBUTE_TYPE type,
                      unsigned char value[MAX_ATTRIBUTE], CK_ULONG *length)
{
    CK_ATTRIBUTE attr = {type, NULL, 0};
    CK_ULONG capacity;
    if (!native("C_GetAttributeValue(size)", s->f->C_GetAttributeValue(s->session, key, &attr, 1))) return 0;
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION || attr.ulValueLen > MAX_ATTRIBUTE)
        return error("attribute unavailable or exceeds bound");
    capacity = attr.ulValueLen;
    attr.pValue = value;
    if (!native("C_GetAttributeValue", s->f->C_GetAttributeValue(s->session, key, &attr, 1))) return 0;
    if (attr.ulValueLen > capacity) return error("attribute length exceeds supplied capacity");
    *length = attr.ulValueLen;
    return 1;
}

static int export_point(State *s, const Options *o, unsigned char point[65])
{
    unsigned char value[MAX_ATTRIBUTE];
    CK_ULONG length;
    CK_OBJECT_HANDLE key = s->public_key;
    if (o->public_key) {
        size_t n;
        if (!read_bounded(o->public_key, value, sizeof(value), &n)) return 0;
        if (!p11_spki(value, n, point)) return error("public key input must be canonical uncompressed P256 DER/SPKI");
        return 1;
    }
    /* Some signing-only providers have no separate public object. A caller can
     * declare an independent SPKI when their private object's public attrs are unreadable. */
    if (key == CK_INVALID_HANDLE) key = s->private_key;
    if (!attribute(s, key, CKA_EC_PARAMS, value, &length)) return 0;
    if (length != sizeof(p256_oid) || memcmp(value, p256_oid, sizeof(p256_oid)) != 0)
        return error("selected key is not named-curve P256");
    if (!attribute(s, key, CKA_EC_POINT, value, &length)) return 0;
    if (!p11_ec_point(value, (size_t)length, point)) return error("invalid DER OCTET STRING P256 EC point");
    return 1;
}

/* Cleanup never replaces an earlier failure, and every native cleanup error is retained. */
static int cleanup(State *s, int primary_ok)
{
    if (s->generated && s->session_open) {
        if (!native("C_DestroyObject(private cleanup)", s->f->C_DestroyObject(s->session, s->private_key))) primary_ok = 0;
        if (!native("C_DestroyObject(public cleanup)", s->f->C_DestroyObject(s->session, s->public_key))) primary_ok = 0;
    }
    if (s->logged_in && !native("C_Logout(cleanup)", s->f->C_Logout(s->session))) primary_ok = 0;
    if (s->session_open && !native("C_CloseSession(cleanup)", s->f->C_CloseSession(s->session))) primary_ok = 0;
    if (s->initialized && !native("C_Finalize(cleanup)", s->f->C_Finalize(NULL))) primary_ok = 0;
#ifdef _WIN32
    if (s->module && !FreeLibrary(s->module)) { error("module unload failed"); primary_ok = 0; }
#else
    if (s->module && dlclose(s->module) != 0) { error("module unload failed"); primary_ok = 0; }
#endif
    return primary_ok;
}

static int write_file(const char *directory, const char *name, const void *data, size_t length)
{
    char path[MAX_PATH_BYTES];
    int n = snprintf(path, sizeof(path), "%s/%s", directory, name);
    FILE *file;
    int ok;
    if (n < 0 || (size_t)n >= sizeof(path)) return error("output path exceeds bound");
    file = open_binary(path, "wb");
    if (!file) return error("cannot create output artifact");
    ok = fwrite(data, 1, length, file) == length;
    if (fclose(file) != 0) ok = 0;
    if (!ok) return error("output artifact write failed");
    return 1;
}

int main(int argc, char **argv)
{
    Options o;
    State s;
    CK_SLOT_ID slot = 0;
    CK_TOKEN_INFO token = {0};
    CK_SLOT_INFO slot_info;
    CK_SESSION_INFO session_info = {0};
    CK_INFO info = {0};
    CK_VERSION interface_version = {0, 0};
    CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};
    unsigned char pin[MAX_PIN], point[65], signature[64], der[72], spki[91];
    CK_ULONG signature_length = sizeof(signature);
    size_t pin_length = 0, der_length = sizeof(der), pem_length;
    char pem[192], record[512];
    int ok = 0, n;
    memset(&s, 0, sizeof(s));
    s.public_key = s.private_key = CK_INVALID_HANDLE;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) { usage(stdout); return 0; }
    if (!options(argc, argv, &o)) { usage(stderr); return 2; }
    /* Reserve a new output directory before any state-changing provider call. */
    if (strlen(o.output) + 32 >= MAX_PATH_BYTES) { error("output path exceeds bound"); return 2; }
    if (make_directory(o.output) != 0) { error("output directory must be new with an existing parent"); return 2; }
#ifdef _WIN32
    s.module = LoadLibraryA(o.module);
#else
    s.module = dlopen(o.module, RTLD_NOW | RTLD_LOCAL);
#endif
    if (!s.module) { error("cannot load supplied module"); goto done; }
    if (!load_module(&s)) goto done;
    interface_version = s.f->version;
    if (!native("C_Initialize", s.f->C_Initialize(NULL))) goto done;
    s.initialized = 1;
    if (!native("C_GetInfo", s.f->C_GetInfo(&info))) goto done;
    if (!select_slot(&s, &o, &slot, &token)) goto done;
    if (!native("C_GetSlotInfo", s.f->C_GetSlotInfo(slot, &slot_info))) goto done;
    if (!mechanisms(&s, slot, strcmp(o.mode, "generated") == 0)) goto done;
    if (!native("C_OpenSession", s.f->C_OpenSession(slot, CKF_SERIAL_SESSION |
                         (strcmp(o.mode, "generated") == 0 ? CKF_RW_SESSION : 0),
                         NULL, NULL, &s.session))) goto done;
    s.session_open = 1;
    if (!native("C_GetSessionInfo", s.f->C_GetSessionInfo(s.session, &session_info))) goto done;
    if (!o.pin_file && (token.flags & CKF_LOGIN_REQUIRED)) { error("PIN file required by selected token"); goto done; }
    if (o.pin_file) {
        CK_RV rv;
        if (!read_bounded(o.pin_file, pin, sizeof(pin), &pin_length)) goto done;
        /* One trailing LF frames the credential file and is not part of the
           PIN, matching the runtime contract. Anything else reaches the
           token untouched and fails with its native error. */
        if (pin_length > 0 && pin[pin_length - 1] == '\n') pin_length--;
        rv = s.f->C_Login(s.session, CKU_USER, pin, (CK_ULONG)pin_length);
        wipe(pin, sizeof(pin));
        if (!native("C_Login", rv)) goto done;
        s.logged_in = 1;
    }
    if (strcmp(o.mode, "generated") == 0) {
        if (!generate_keys(&s)) goto done;
    } else {
        if (!find_key(&s, CKO_PRIVATE_KEY, &o, &s.private_key, 1)) goto done;
        if (!o.public_key && !find_key(&s, CKO_PUBLIC_KEY, &o, &s.public_key, 0)) goto done;
    }
    if (!export_point(&s, &o, point)) goto done;
    if (!native("C_SignInit", s.f->C_SignInit(s.session, &mechanism, s.private_key))) goto done;
    /* One mutating call, no retry or signature length query. P256 ECDSA is exactly 64 bytes. */
    if (!native("C_Sign", s.f->C_Sign(s.session, (CK_BYTE_PTR)digest, sizeof(digest),
                                     signature, &signature_length))) goto done;
    if (signature_length != sizeof(signature)) { error("P256 signature must contain exactly 64 bytes"); goto done; }
    if (!p11_signature_der(signature, sizeof(signature), der, &der_length)) { error("invalid P256 ECDSA signature scalars"); goto done; }
    ok = 1;
done:
    wipe(pin, sizeof(pin));
    ok = cleanup(&s, ok);
    if (!ok) return 1;
    p11_make_spki(point, spki);
    pem_length = p11_public_pem(point, pem);
    n = snprintf(record, sizeof(record),
        "{\"schema\":1,\"mechanism\":\"CKM_ECDSA\",\"mechanism_id\":%lu,"
        "\"key_mode\":\"%s\",\"public_key_source\":\"%s\",\"slot_id\":%lu,"
        "\"interface_version\":\"%u.%u\",\"cryptoki_version\":\"%u.%u\","
        "\"session_flags\":%lu,\"token_flags\":%lu}\n",
        (unsigned long)CKM_ECDSA, o.mode, o.public_key ? "declared-input" : "provider",
        (unsigned long)slot, (unsigned)interface_version.major, (unsigned)interface_version.minor,
        (unsigned)info.cryptokiVersion.major, (unsigned)info.cryptokiVersion.minor,
        (unsigned long)session_info.flags, (unsigned long)token.flags);
    if (n < 0 || (size_t)n >= sizeof(record)) { error("result record exceeds bound"); return 1; }
    if (!write_file(o.output, "public-key.pem", pem, pem_length) ||
        !write_file(o.output, "public-key.der", spki, sizeof(spki)) ||
        !write_file(o.output, "message.bin", message, sizeof(message) - 1) ||
        !write_file(o.output, "digest.bin", digest, sizeof(digest)) ||
        !write_file(o.output, "signature.raw", signature, sizeof(signature)) ||
        !write_file(o.output, "signature.der", der, der_length) ||
        !write_file(o.output, "result.json", record, (size_t)n)) return 1;
    puts("P256 signature exported; run the independent OpenSSL verifier.");
    return 0;
}
