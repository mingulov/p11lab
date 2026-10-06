/* SPDX-License-Identifier: Apache-2.0
 * Standalone module usability probe. No token provisioning or function shim. */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#define NULL_PTR 0
#include <pkcs11.h>

static int result(const char *operation, CK_RV rv)
{
    if (rv != CKR_OK) {
        fprintf(stderr, "p11lab-corepkcs11: %s CK_RV=0x%08lx\n", operation, (unsigned long)rv);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *module = getenv("P11LAB_MODULE");
    void *library, *symbol;
    CK_C_GetFunctionList get_functions;
    CK_FUNCTION_LIST_PTR p11 = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slot = 0;
    CK_ULONG count = 0;
    CK_BYTE random[32];
    int status = 0;
    if (argc != 2 || strcmp(argv[1], "health") != 0 || module == NULL) {
        fputs("p11lab-corepkcs11: usage: health (P11LAB_MODULE required)\n", stderr);
        return 2;
    }
    library = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fputs("p11lab-corepkcs11: cannot load module\n", stderr);
        return 1;
    }
    symbol = dlsym(library, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get_functions), "POSIX function pointer ABI");
    memcpy(&get_functions, &symbol, sizeof(get_functions));
    if (get_functions == NULL || result("C_GetFunctionList", get_functions(&p11)) || p11 == NULL) {
        dlclose(library);
        return 1;
    }
    if (p11->C_Initialize == NULL || p11->C_Finalize == NULL || p11->C_GetSlotList == NULL ||
        p11->C_OpenSession == NULL || p11->C_CloseSession == NULL || p11->C_GenerateRandom == NULL) {
        fputs("p11lab-corepkcs11: required native function is absent\n", stderr);
        dlclose(library);
        return 1;
    }
    if (result("C_Initialize", p11->C_Initialize(NULL))) {
        dlclose(library);
        return 1;
    }
    status = result("C_GetSlotList(count)", p11->C_GetSlotList(CK_TRUE, NULL, &count));
    if (!status && count != 1) {
        fputs("p11lab-corepkcs11: expected one native slot\n", stderr);
        status = 1;
    }
    if (!status) status = result("C_GetSlotList", p11->C_GetSlotList(CK_TRUE, &slot, &count));
    if (!status) status = result("C_OpenSession", p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session));
    if (!status) status = result("C_GenerateRandom", p11->C_GenerateRandom(session, random, sizeof(random)));
    if (session != CK_INVALID_HANDLE) status |= result("C_CloseSession", p11->C_CloseSession(session));
    status |= result("C_Finalize", p11->C_Finalize(NULL));
    if (!status) printf("fresh-process-module-open native_slot=%lu token_present_index=0 state_mode=process-local; no application-token claim\n", (unsigned long)slot);
    if (dlclose(library) != 0) status = 1;
    return status;
}
