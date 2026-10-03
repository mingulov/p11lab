/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab native readiness checker. No initialization or secret inputs:
 * OpenSSL CLI provisions the file keys; this program loads the actual module,
 * opens each certificate-backed session and checks its native key type. */
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int native(const char *operation, CK_RV rv)
{
    if (rv == CKR_OK) return 1;
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", operation, (unsigned long)rv);
    return 0;
}

int main(void)
{
    const char *module = getenv("P11LAB_MODULE");
    void *handle = NULL, *symbol;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slots[10];
    CK_ULONG count = 10;
    CK_SLOT_INFO slot_info;
    int initialized = 0, status = 1;
    if (!module) return 2;
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("cannot load module\n", stderr); goto out; }
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get), "native function pointer ABI");
    memcpy(&get, &symbol, sizeof(get));
    if (!get || !native("C_GetFunctionList", get(&f)) || !f) goto out;
    if (!native("C_Initialize", f->C_Initialize(NULL))) goto out;
    initialized = 1;
    if (!native("C_GetSlotList", f->C_GetSlotList(CK_FALSE, slots, &count)) ||
        count != 3 || slots[0] != 0 || slots[1] != 1 || slots[2] != 2) goto out;
    if (!native("C_GetSlotInfo(empty)", f->C_GetSlotInfo(1, &slot_info)) || slot_info.flags) goto out;
    for (CK_SLOT_ID slot = 0; slot <= 2; slot += 2) {
        CK_TOKEN_INFO info;
        CK_OBJECT_CLASS kind = CKO_PRIVATE_KEY;
        CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
        CK_KEY_TYPE type = 0;
        CK_ATTRIBUTE attr = {CKA_CLASS, &kind, sizeof(kind)};
        char label[32] = {0};
        (void)snprintf(label, sizeof(label), "pkcs11-to-cmd-%lu", (unsigned long)slot);
        if (!native("C_GetTokenInfo", f->C_GetTokenInfo(slot, &info)) ||
            info.flags != CKF_TOKEN_INITIALIZED || info.ulMinPinLen || info.ulMaxPinLen ||
            memcmp(info.label, label, sizeof(label))) goto out;
        if (!native("C_OpenSession", f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &session))) goto out;
        if (!native("C_FindObjectsInit", f->C_FindObjectsInit(session, &attr, 1))) goto out;
        count = 0;
        if (!native("C_FindObjects", f->C_FindObjects(session, &object, 1, &count)) || count != 1) goto out;
        if (!native("C_FindObjectsFinal", f->C_FindObjectsFinal(session))) goto out;
        attr = (CK_ATTRIBUTE){CKA_KEY_TYPE, &type, sizeof(type)};
        if (!native("C_GetAttributeValue", f->C_GetAttributeValue(session, object, &attr, 1)) ||
            type != (slot == 0 ? CKK_RSA : CKK_EC)) goto out;
        if (!native("C_CloseSession", f->C_CloseSession(session))) goto out;
        session = CK_INVALID_HANDLE;
        printf("native_slot=%lu label=%s pin_min=0 pin_max=0 login_required=false key_type=%lu\n",
               (unsigned long)slot, label, (unsigned long)type);
    }
    status = 0;
out:
    if (session != CK_INVALID_HANDLE && f && !native("C_CloseSession(cleanup)", f->C_CloseSession(session))) status = 1;
    if (initialized && !native("C_Finalize", f->C_Finalize(NULL))) status = 1;
    if (handle && dlclose(handle)) status = 1;
    return status;
}
