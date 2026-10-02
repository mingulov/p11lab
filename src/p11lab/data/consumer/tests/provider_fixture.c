/* SPDX-License-Identifier: Apache-2.0 */
/* Narrow native-ABI fault fixture. It is deliberately not a crypto provider. */
#include "../vendor/pkcs11.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int find_position;
static int mode(const char *wanted)
{
    const char *actual = getenv("P11_FIXTURE_MODE");
    return actual && strcmp(actual, wanted) == 0;
}
static void record(const char *call)
{
    const char *path = getenv("P11_FIXTURE_LOG");
    FILE *f;
    if (!path) return;
    f = fopen(path, "ab");
    if (!f) abort();
    fprintf(f, "%s\n", call);
    if (fclose(f) != 0) abort();
}
static CK_RV initialize(CK_VOID_PTR args) { (void)args; return CKR_OK; }
static CK_RV finalize(CK_VOID_PTR args) { (void)args; record("Finalize"); return CKR_OK; }
static CK_RV info(CK_INFO_PTR out)
{
    memset(out, 0, sizeof(*out)); out->cryptokiVersion.major = 2; out->cryptokiVersion.minor = 40;
    return CKR_OK;
}
static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR out, CK_ULONG_PTR count)
{
    (void)present;
    if (out) { if (*count < 1) return CKR_BUFFER_TOO_SMALL; out[0] = 1; }
    *count = 1; return CKR_OK;
}
static CK_RV slot_info(CK_SLOT_ID id, CK_SLOT_INFO_PTR out)
{
    (void)id; memset(out, 0, sizeof(*out)); out->flags = CKF_TOKEN_PRESENT; return CKR_OK;
}
static CK_RV token_info(CK_SLOT_ID id, CK_TOKEN_INFO_PTR out)
{
    (void)id; memset(out, 0, sizeof(*out)); memset(out->label, ' ', sizeof(out->label));
    memcpy(out->label, "Fixture", 7); return CKR_OK;
}
static CK_RV mechanism_list(CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR count)
{
    (void)id;
    if (out) {
        if (*count < 2) return CKR_BUFFER_TOO_SMALL;
        out[0] = CKM_ECDSA; out[1] = CKM_EC_KEY_PAIR_GEN;
    }
    *count = 2; return CKR_OK;
}
static CK_RV mechanism_info(CK_SLOT_ID id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR out)
{
    (void)id; (void)type; memset(out, 0, sizeof(*out));
    out->flags = CKF_SIGN | CKF_GENERATE_KEY_PAIR; return CKR_OK;
}
static CK_RV open_session(CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR application,
                           CK_NOTIFY notify, CK_SESSION_HANDLE_PTR handle)
{
    (void)id; (void)application; (void)notify;
    if (mode("readonly-existing") && (flags & CKF_RW_SESSION)) return CKR_TOKEN_WRITE_PROTECTED;
    *handle = 1; return CKR_OK;
}
static CK_RV session_info(CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR out)
{
    (void)handle; memset(out, 0, sizeof(*out)); out->slotID = 1;
    out->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION; return CKR_OK;
}
static CK_RV close_session(CK_SESSION_HANDLE handle)
{
    (void)handle; record("CloseSession"); return (mode("cleanup-error") || mode("sign-and-cleanup-error")) ? CKR_FUNCTION_FAILED : CKR_OK;
}
static CK_RV login(CK_SESSION_HANDLE handle, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG length)
{
    (void)handle; (void)user; record("Login");
    if (mode("empty-pin") && pin != NULL && length == 0) return CKR_OK;
    return CKR_PIN_INCORRECT;
}
static CK_RV logout(CK_SESSION_HANDLE handle) { (void)handle; record("Logout"); return CKR_OK; }
static CK_RV generate(CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_ATTRIBUTE_PTR pub, CK_ULONG npub, CK_ATTRIBUTE_PTR priv, CK_ULONG npriv,
                     CK_OBJECT_HANDLE_PTR public_key, CK_OBJECT_HANDLE_PTR private_key)
{
    (void)handle; (void)mechanism; (void)pub; (void)npub; (void)priv; (void)npriv;
    record("GenerateKeyPair"); *public_key = 2; *private_key = 3; return CKR_OK;
}
static CK_RV destroy(CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key)
{
    (void)handle; (void)key; record("DestroyObject"); return CKR_OK;
}
static CK_RV find_init(CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
    (void)handle; (void)attrs; (void)count; find_position = 0; return CKR_OK;
}
static CK_RV find(CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE_PTR out, CK_ULONG limit, CK_ULONG_PTR count)
{
    (void)handle;
    if (!limit) return CKR_ARGUMENTS_BAD;
    /* A legal provider can return only one match per page, even when limit=2. */
    if (find_position < (mode("duplicate-key") ? 2U : 1U)) { out[0] = 3 + find_position++; *count = 1; }
    else *count = 0;
    return CKR_OK;
}
static CK_RV find_final(CK_SESSION_HANDLE handle) { (void)handle; return CKR_OK; }
static CK_RV attributes(CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key,
                       CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
    static const unsigned char params[10] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    /* Standard P256 generator, fixed independently of the application. */
    static const unsigned char point[67] = {
        0x04,0x41,0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,
        0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,
        0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
    };
    const unsigned char *value;
    CK_ULONG length;
    (void)handle; (void)key;
    if (count != 1) return CKR_ARGUMENTS_BAD;
    if (mode("attribute-oversize")) { attrs[0].ulValueLen = 2048; return CKR_OK; }
    if (attrs[0].type == CKA_EC_PARAMS) { value = params; length = sizeof(params); }
    else if (attrs[0].type == CKA_EC_POINT) { value = point; length = sizeof(point); }
    else return CKR_ATTRIBUTE_TYPE_INVALID;
    if (attrs[0].pValue) {
        if (mode("attribute-growth")) { attrs[0].ulValueLen = length + 1; return CKR_OK; }
        if (attrs[0].ulValueLen < length) return CKR_BUFFER_TOO_SMALL;
        memcpy(attrs[0].pValue, value, (size_t)length);
        if (mode("point-malformed") && attrs[0].type == CKA_EC_POINT)
            ((unsigned char *)attrs[0].pValue)[1] = 66;
    }
    attrs[0].ulValueLen = length; return CKR_OK;
}
static CK_RV sign_init(CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)handle; (void)key; return mechanism->mechanism == CKM_ECDSA ? CKR_OK : CKR_MECHANISM_INVALID;
}
static CK_RV sign_data(CK_SESSION_HANDLE handle, CK_BYTE_PTR input, CK_ULONG length,
                      CK_BYTE_PTR signature, CK_ULONG_PTR capacity)
{
    (void)handle; (void)input; record("Sign");
    if (mode("sign-error") || mode("sign-and-cleanup-error")) return CKR_DEVICE_ERROR;
    if (mode("sign-buffer-too-small")) return CKR_BUFFER_TOO_SMALL;
    if (mode("sign-oversize")) { *capacity = 65; return CKR_OK; }
    if (length != 32 || !signature || *capacity != 64) return CKR_ARGUMENTS_BAD;
    memset(signature, 0, 64); signature[31] = 1; signature[63] = 2; *capacity = 64; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list)
{
    static CK_FUNCTION_LIST functions;
    functions.version.major = 2; functions.version.minor = 40;
    functions.C_Initialize = initialize; functions.C_Finalize = finalize; functions.C_GetInfo = info;
    functions.C_GetSlotList = slots; functions.C_GetSlotInfo = slot_info; functions.C_GetTokenInfo = token_info;
    functions.C_GetMechanismList = mechanism_list; functions.C_GetMechanismInfo = mechanism_info;
    functions.C_OpenSession = open_session; functions.C_GetSessionInfo = session_info;
    functions.C_CloseSession = close_session; functions.C_Login = login; functions.C_Logout = logout;
    functions.C_GenerateKeyPair = generate; functions.C_DestroyObject = destroy;
    functions.C_FindObjectsInit = find_init; functions.C_FindObjects = find; functions.C_FindObjectsFinal = find_final;
    functions.C_GetAttributeValue = attributes; functions.C_SignInit = sign_init; functions.C_Sign = sign_data;
    *list = &functions; return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version,
                      CK_INTERFACE_PTR_PTR out, CK_FLAGS flags)
{
    static CK_INTERFACE interface;
    CK_FUNCTION_LIST_PTR list;
    (void)name; (void)version; (void)flags;
    if (mode("interface-error")) return CKR_FUNCTION_NOT_SUPPORTED;
    C_GetFunctionList(&list);
    interface.pInterfaceName = "PKCS 11";
    interface.pFunctionList = list; interface.flags = 0;
    *out = &interface; return CKR_OK;
}
