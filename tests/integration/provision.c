/* T7 acceptance-only persistent-key provisioner (test-only, never shipped).
 * Creates one persistent P-256 EC key pair with the given hex CKA_ID on the
 * selected token. Usage:
 * provision --module PATH --token-label LABEL --pin-file PATH --key-id HEX */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef HMODULE Module;
#else
#include <dlfcn.h>
typedef void *Module;
#endif

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BBOOL;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;

typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

typedef CK_RV (*FnInit)(void *);
typedef CK_RV (*FnFinal)(void *);
typedef CK_RV (*FnSlots)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*FnOpen)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*FnClose)(CK_SESSION_HANDLE);
typedef CK_RV (*FnLogin)(CK_SESSION_HANDLE, CK_ULONG, unsigned char *, CK_ULONG);
typedef CK_RV (*FnLogout)(CK_SESSION_HANDLE);
typedef CK_RV (*FnGenPair)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG,
                           CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
typedef CK_RV (*FnGetList)(void *);

typedef struct {
    CK_VERSION version;
    FnInit C_Initialize;
    FnFinal C_Finalize;
    void *C_GetInfo;
    void *C_GetFunctionList;
    FnSlots C_GetSlotList;
    void *C_GetSlotInfo;
    void *C_GetTokenInfo;
    void *C_GetMechanismList;
    void *C_GetMechanismInfo;
    void *C_InitToken;
    void *C_InitPIN;
    void *C_SetPIN;
    FnOpen C_OpenSession;
    FnClose C_CloseSession;
    void *C_CloseAllSessions;
    void *C_GetSessionInfo;
    void *C_GetOperationState;
    void *C_SetOperationState;
    FnLogin C_Login;
    FnLogout C_Logout;
    void *C_CreateObject;
    void *C_CopyObject;
    void *C_DestroyObject;
    void *C_GetObjectSize;
    void *C_GetAttributeValue;
    void *C_SetAttributeValue;
    void *C_FindObjectsInit;
    void *C_FindObjects;
    void *C_FindObjectsFinal;
    void *C_EncryptInit;
    void *C_Encrypt;
    void *C_EncryptUpdate;
    void *C_EncryptFinal;
    void *C_DecryptInit;
    void *C_Decrypt;
    void *C_DecryptUpdate;
    void *C_DecryptFinal;
    void *C_DigestInit;
    void *C_Digest;
    void *C_DigestUpdate;
    void *C_DigestKey;
    void *C_DigestFinal;
    void *C_SignInit;
    void *C_Sign;
    void *C_SignUpdate;
    void *C_SignFinal;
    void *C_SignRecoverInit;
    void *C_SignRecover;
    void *C_VerifyInit;
    void *C_Verify;
    void *C_VerifyUpdate;
    void *C_VerifyFinal;
    void *C_VerifyRecoverInit;
    void *C_VerifyRecover;
    void *C_DigestEncryptUpdate;
    void *C_DecryptDigestUpdate;
    void *C_SignEncryptUpdate;
    void *C_DecryptVerifyUpdate;
    void *C_GenerateKey;
    FnGenPair C_GenerateKeyPair;
} List;

#define CKO_PUBLIC_KEY 2UL
#define CKO_PRIVATE_KEY 3UL
#define CKK_EC 3UL
#define CKM_EC_KEY_PAIR_GEN 0x1040UL
#define CKA_CLASS 0UL
#define CKA_TOKEN 1UL
#define CKA_PRIVATE 2UL
#define CKA_LABEL 3UL
#define CKA_KEY_TYPE 0x100UL
#define CKA_ID 0x102UL
#define CKA_SIGN 0x108UL
#define CKA_VERIFY 0x10AUL
#define CKA_EC_PARAMS 0x180UL
#define CKU_USER 1UL
#define CKF_RW_SESSION 2UL
#define CKF_SERIAL_SESSION 4UL

static const unsigned char p256_oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    const char *module = NULL, *label = NULL, *pin_file = NULL, *key_id = NULL;
    int i;
    unsigned char id[128];
    size_t id_len = 0;
    FILE *f;
    unsigned char pin[4096];
    size_t pin_len = 0;
    Module handle = (Module)0;
    FnGetList get_list = NULL;
    List *list = NULL;
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_ULONG count = 0, n = 0;
    CK_SLOT_ID *slots = NULL;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    int rc = 1;

    for (i = 1; i < argc; i++) {
        const char **target = NULL;
        if (strcmp(argv[i], "--module") == 0) target = &module;
        else if (strcmp(argv[i], "--token-label") == 0) target = &label;
        else if (strcmp(argv[i], "--pin-file") == 0) target = &pin_file;
        else if (strcmp(argv[i], "--key-id") == 0) target = &key_id;
        else { fprintf(stderr, "provision: unknown argument: %s\n", argv[i]); return 2; }
        if (i + 1 >= argc) { fprintf(stderr, "provision: option needs a value\n"); return 2; }
        *target = argv[++i];
    }
    if (!module || !label || !pin_file || !key_id) {
        fprintf(stderr, "provision --module PATH --token-label L --pin-file P --key-id HEX\n");
        return 2;
    }
    {
        size_t hexlen = strlen(key_id);
        size_t j;
        if (!hexlen || hexlen % 2 || hexlen / 2 > sizeof(id)) {
            fprintf(stderr, "provision: bad key id\n");
            return 2;
        }
        for (j = 0; j < hexlen; j += 2) {
            int hi = hexval(key_id[j]), lo = hexval(key_id[j + 1]);
            if (hi < 0 || lo < 0) { fprintf(stderr, "provision: bad key id\n"); return 2; }
            id[j / 2] = (unsigned char)((hi << 4) | lo);
        }
        id_len = hexlen / 2;
    }
    f = fopen(pin_file, "rb");
    if (!f) { fprintf(stderr, "provision: cannot open pin file\n"); return 2; }
    {
        size_t r = fread(pin, 1, sizeof(pin), f);
        int extra = fgetc(f);
        fclose(f);
        if (!r || extra != EOF) { fprintf(stderr, "provision: bad pin file\n"); return 2; }
        pin_len = r;
    }
#ifdef _WIN32
    handle = LoadLibraryA(module);
    if (handle) {
        FARPROC symbol = GetProcAddress(handle, "C_GetFunctionList");
        _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
        memcpy(&get_list, &symbol, sizeof(get_list));
    }
#else
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (handle) {
        void *symbol = dlsym(handle, "C_GetFunctionList");
        _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
        memcpy(&get_list, &symbol, sizeof(get_list));
    }
#endif
    if (!get_list) { fprintf(stderr, "provision: cannot load module\n"); goto out; }
    {
        CK_RV (*real_get)(List **) = NULL;
        memcpy(&real_get, &get_list, sizeof(real_get));
        rv = real_get(&list);
    }
    if (rv || !list) { fprintf(stderr, "provision: C_GetFunctionList: CK_RV=0x%lx\n", rv); goto out; }
    if ((rv = list->C_Initialize(NULL))) {
        fprintf(stderr, "provision: C_Initialize: CK_RV=0x%lx\n", rv);
        goto out;
    }
    if ((rv = list->C_GetSlotList(1, NULL, &count)) || !count) {
        fprintf(stderr, "provision: no token-present slot: CK_RV=0x%lx\n", rv);
        list->C_Finalize(NULL);
        goto out;
    }
    slots = malloc(count * sizeof(*slots));
    n = count;
    if ((rv = list->C_GetSlotList(1, slots, &n))) {
        fprintf(stderr, "provision: C_GetSlotList: CK_RV=0x%lx\n", rv);
        list->C_Finalize(NULL);
        goto out;
    }
    /* Single-slot policy: the first token-present slot is the provisioned token. */
    slot = slots[0];
    if ((rv = list->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session))) {
        fprintf(stderr, "provision: C_OpenSession: CK_RV=0x%lx\n", rv);
        list->C_Finalize(NULL);
        goto out;
    }
    if ((rv = list->C_Login(session, CKU_USER, pin, (CK_ULONG)pin_len))) {
        fprintf(stderr, "provision: C_Login: CK_RV=0x%lx\n", rv);
        goto session_out;
    }
    {
        CK_ULONG pub_class = CKO_PUBLIC_KEY, priv_class = CKO_PRIVATE_KEY;
        CK_ULONG ec = CKK_EC;
        CK_BBOOL yes = 1;
        CK_ATTRIBUTE pub_t[] = {
            {CKA_CLASS, &pub_class, sizeof(pub_class)},
            {CKA_KEY_TYPE, &ec, sizeof(ec)},
            {CKA_TOKEN, &yes, sizeof(yes)},
            {CKA_VERIFY, &yes, sizeof(yes)},
            {CKA_ID, id, (CK_ULONG)id_len},
            {CKA_EC_PARAMS, (void *)p256_oid, sizeof(p256_oid)},
        };
        CK_ATTRIBUTE priv_t[] = {
            {CKA_CLASS, &priv_class, sizeof(priv_class)},
            {CKA_KEY_TYPE, &ec, sizeof(ec)},
            {CKA_TOKEN, &yes, sizeof(yes)},
            {CKA_PRIVATE, &yes, sizeof(yes)},
            {CKA_SIGN, &yes, sizeof(yes)},
            {CKA_ID, id, (CK_ULONG)id_len},
        };
        CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
        rv = list->C_GenerateKeyPair(session, &mech, pub_t, 6, priv_t, 6, &pub, &priv);
        if (rv) {
            fprintf(stderr, "provision: C_GenerateKeyPair: CK_RV=0x%lx\n", rv);
            goto session_out;
        }
    }
    printf("provisioned: pub=%lu priv=%lu\n", pub, priv);
    (void)list->C_Logout(session);
    rc = 0;
session_out:
    list->C_CloseSession(session);
    list->C_Finalize(NULL);
out:
    free(slots);
#ifdef _WIN32
    if (handle) FreeLibrary(handle);
#else
    if (handle) dlclose(handle);
#endif
    memset(pin, 0, sizeof(pin));
    return rc;
}
