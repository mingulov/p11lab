/* SPDX-License-Identifier: Apache-2.0
 * P11Lab provisioning/readiness adapter; libc + dl only. The OASIS
 * PKCS#11 headers are taken from the exact RustSSM source being built; their
 * original copyright/IPR notices are retained separately in the runtime.
 * Secret bytes arrive through private inherited pipes, never argv or env.
 */
#include <pkcs11.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int report(const char *operation, CK_RV rv)
{
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", operation, rv);
    return 1;
}

static int read_secret(int descriptor, unsigned char *buffer, size_t *length)
{
    ssize_t count;
    *length = 0;
    while ((count = read(descriptor, buffer + *length, 4097 - *length)) > 0) {
        *length += (size_t)count;
        if (*length > 4096) return 1;
    }
    return count < 0 || *length == 0;
}

static void erase(unsigned char *buffer, size_t length)
{
    volatile unsigned char *pointer = buffer;
    while (length--) *pointer++ = 0;
}

int main(int argc, char **argv)
{
    const char *module = getenv("P11LAB_MODULE");
    const char *label = getenv("P11LAB_LABEL");
    CK_FUNCTION_LIST_PTR functions = NULL;
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_TOKEN_INFO info;
    CK_SLOT_ID slot = 0;
    CK_ULONG slots = 1;
    CK_RV rv;
    unsigned char pin[4097] = {0}, so_pin[4097] = {0}, padded[32];
    size_t pin_length = 0, so_length = 0;
    void *handle = NULL, *symbol;
    int initialized = 0, status = 1;
    if (argc != 2 || !module || !label || strlen(label) > sizeof(padded) ||
        (strcmp(argv[1], "init") && strcmp(argv[1], "health"))) {
        fputs("p11lab-rustssm: invalid operation or module/label controls\n", stderr);
        return 2;
    }
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, label, strlen(label));
    if (!strcmp(argv[1], "init") &&
        (read_secret(3, pin, &pin_length) || read_secret(4, so_pin, &so_length))) {
        fputs("p11lab-rustssm: cannot read credential pipes\n", stderr);
        goto out;
    }
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-rustssm: cannot load module\n", stderr); goto out; }
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
    memcpy(&get_list, &symbol, sizeof(get_list));
    if (!get_list) { fputs("p11lab-rustssm: missing C_GetFunctionList\n", stderr); goto out; }
    rv = get_list(&functions);
    if (rv || !functions) { report("C_GetFunctionList", rv); goto out; }
    rv = functions->C_Initialize(NULL);
    if (rv) { report("C_Initialize", rv); goto out; }
    initialized = 1;
    rv = functions->C_GetSlotList(CK_TRUE, NULL, &slots);
    if (rv || slots != 1) { report("C_GetSlotList", rv); goto out; }
    rv = functions->C_GetSlotList(CK_TRUE, &slot, &slots);
    if (rv || slots != 1 || slot != 0) { report("C_GetSlotList", rv); goto out; }
    rv = functions->C_GetTokenInfo(slot, &info);
    if (rv) { report("C_GetTokenInfo", rv); goto out; }
    if (!strcmp(argv[1], "init")) {
        /* This guard adds provisioning safety without changing provider RVs. */
        if (info.flags & CKF_TOKEN_INITIALIZED) {
            fputs("p11lab-rustssm: refusing to reset an initialized token\n", stderr);
            goto out;
        }
        rv = functions->C_InitToken(slot, so_pin, (CK_ULONG)so_length, padded);
        if (rv) { report("C_InitToken", rv); goto out; }
        rv = functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
        if (rv) { report("C_OpenSession", rv); goto out; }
        rv = functions->C_Login(session, CKU_SO, so_pin, (CK_ULONG)so_length);
        if (rv) { report("C_Login", rv); goto out; }
        rv = functions->C_InitPIN(session, pin, (CK_ULONG)pin_length);
        if (rv) { report("C_InitPIN", rv); goto out; }
        rv = functions->C_Logout(session);
        if (rv) { report("C_Logout", rv); goto out; }
        rv = functions->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
        if (rv) { report("C_CloseSession", rv); goto out; }
        rv = functions->C_GetTokenInfo(slot, &info);
        if (rv) { report("C_GetTokenInfo", rv); goto out; }
    }
    if ((info.flags & (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED)) !=
        (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED) ||
        memcmp(info.label, padded, sizeof(padded))) {
        fputs("p11lab-rustssm: expected initialized token is not ready\n", stderr);
        goto out;
    }
    printf("ready: native_slot=0 token_present_index=0 label=%s\n", label);
    status = 0;
out:
    erase(pin, sizeof(pin));
    erase(so_pin, sizeof(so_pin));
    if (session != CK_INVALID_HANDLE) {
        rv = functions->C_CloseSession(session);
        if (rv) status = report("C_CloseSession", rv);
    }
    if (initialized) {
        rv = functions->C_Finalize(NULL);
        if (rv) status = report("C_Finalize", rv);
    }
    if (handle) dlclose(handle);
    return status;
}
