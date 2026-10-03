/* SPDX-License-Identifier: Apache-2.0 */
/* Minimal PKCS#11 readiness probe for the BouncyHSM native client.
 *
 * Loads an arbitrary compatible module by path, resolves C_GetFunctionList,
 * and either reports the function-list version (--load-only, no server
 * needed) or performs C_Initialize, C_GetSlotList (all and token-present)
 * and C_Finalize. Native return values are preserved on stderr; an empty
 * slot list is a successful observation, not an error, and the caller
 * decides what the counts mean. The client transport comes from
 * BOUNCY_HSM_CFG_STRING: --server/--port set it for this process, otherwise
 * the ambient value is used. C11, libc only. Windows uses the process ANSI
 * code page for the module path, matching the independent C consumer. */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
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

#ifdef _WIN32
/* BouncyHSM packs PKCS#11 structures to 1 byte on Windows only
 * (its bouncy-pkcs11.h); default packing reads wrong offsets. */
#pragma pack(push, cryptoki, 1)
#endif
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef CK_RV (*C_InitializeFn)(void *init_args);
typedef CK_RV (*C_FinalizeFn)(void *reserved);
typedef CK_RV (*C_GetSlotListFn)(CK_BBOOL token_present, CK_SLOT_ID *slot_list,
                                 CK_ULONG *count);

typedef struct {
    CK_VERSION version;
    C_InitializeFn C_Initialize;
    C_FinalizeFn C_Finalize;
    void *C_GetInfo;
    void *C_GetFunctionList;
    C_GetSlotListFn C_GetSlotList;
} CK_FUNCTION_LIST;
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

typedef CK_RV (*C_GetFunctionListFn)(CK_FUNCTION_LIST **function_list);

#define CKR_OK 0UL

static int set_cfg(const char *server, const char *port) {
    char *cfg;
    size_t need;
    int rc;
    if ((!server && port) || (server && !port)) {
        fprintf(stderr, "probe: --server and --port must be given together\n");
        return 0;
    }
    if (!server) {
        return 1;
    }
    need = strlen("Server=;Port=;") + strlen(server) + strlen(port) + 1;
    cfg = (char *)malloc(need);
    if (!cfg) {
        fprintf(stderr, "probe: out of memory\n");
        return 0;
    }
    snprintf(cfg, need, "Server=%s;Port=%s;", server, port);
#ifdef _WIN32
    rc = _putenv_s("BOUNCY_HSM_CFG_STRING", cfg);
#else
    rc = setenv("BOUNCY_HSM_CFG_STRING", cfg, 1);
#endif
    /* The module may retain the pointer on some paths; keep it alive. */
    (void)rc;
    if (rc != 0) {
        fprintf(stderr, "probe: cannot set BOUNCY_HSM_CFG_STRING\n");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *module = NULL;
    const char *server = NULL;
    const char *port = NULL;
    int load_only = 0;
    int i;
    Module handle = (Module)0;
    C_GetFunctionListFn get_list = NULL;
    CK_FUNCTION_LIST *list = NULL;
    CK_RV rv;
    CK_ULONG all = 0;
    CK_ULONG present = 0;

    for (i = 1; i < argc; i++) {
        const char **target = NULL;
        if (strcmp(argv[i], "--module") == 0) {
            target = &module;
        } else if (strcmp(argv[i], "--server") == 0) {
            target = &server;
        } else if (strcmp(argv[i], "--port") == 0) {
            target = &port;
        } else if (strcmp(argv[i], "--load-only") == 0) {
            load_only = 1;
            continue;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("probe --module PATH [--load-only] [--server HOST --port PORT]\n");
            return 0;
        } else {
            fprintf(stderr, "probe: unknown argument: %s\n", argv[i]);
            return 2;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "probe: option needs a value: %s\n", argv[i]);
            return 2;
        }
        *target = argv[++i];
    }
    if (!module || !*module) {
        fprintf(stderr, "probe --module PATH [--load-only] [--server HOST --port PORT]\n");
        return 2;
    }
    if (load_only && (server || port)) {
        fprintf(stderr, "probe: --load-only takes no server options\n");
        return 2;
    }
    if (!set_cfg(server, port)) {
        return 2;
    }

#ifdef _WIN32
    {
        FARPROC symbol;
        handle = LoadLibraryA(module);
        if (!handle) {
            fprintf(stderr, "probe: cannot load module: %s (error %lu)\n", module,
                    (unsigned long)GetLastError());
            return 1;
        }
        symbol = GetProcAddress(handle, "C_GetFunctionList");
        _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
        memcpy(&get_list, &symbol, sizeof(get_list));
        if (!get_list) {
            fprintf(stderr, "probe: C_GetFunctionList is not exported: %s (error %lu)\n",
                    module, (unsigned long)GetLastError());
            FreeLibrary(handle);
            return 1;
        }
    }
#else
    {
        void *symbol;
        handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "probe: cannot load module: %s (%s)\n", module, dlerror());
            return 1;
        }
        dlerror();
        symbol = dlsym(handle, "C_GetFunctionList");
        _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
        memcpy(&get_list, &symbol, sizeof(get_list));
        if (!get_list) {
            fprintf(stderr, "probe: C_GetFunctionList is not exported: %s\n", module);
            dlclose(handle);
            return 1;
        }
    }
#endif

    rv = get_list(&list);
    if (rv != CKR_OK || !list) {
        fprintf(stderr, "probe: C_GetFunctionList: CK_RV=0x%llx\n",
                (unsigned long long)rv);
        goto fail;
    }
    if (load_only) {
        printf("version=%u.%u\n", list->version.major, list->version.minor);
        goto done;
    }
    if (!list->C_Initialize || !list->C_Finalize || !list->C_GetSlotList) {
        fprintf(stderr, "probe: required function pointer is null\n");
        goto fail;
    }
    rv = list->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "probe: C_Initialize: CK_RV=0x%llx\n", (unsigned long long)rv);
        goto fail;
    }
    rv = list->C_GetSlotList(0, NULL, &all);
    if (rv != CKR_OK) {
        fprintf(stderr, "probe: C_GetSlotList: CK_RV=0x%llx\n", (unsigned long long)rv);
        list->C_Finalize(NULL);
        goto fail;
    }
    rv = list->C_GetSlotList(1, NULL, &present);
    if (rv != CKR_OK) {
        fprintf(stderr, "probe: C_GetSlotList: CK_RV=0x%llx\n", (unsigned long long)rv);
        list->C_Finalize(NULL);
        goto fail;
    }
    rv = list->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "probe: C_Finalize: CK_RV=0x%llx\n", (unsigned long long)rv);
        goto fail;
    }
    printf("version=%u.%u slots=%llu present=%llu\n", list->version.major,
           list->version.minor, (unsigned long long)all, (unsigned long long)present);
done:
#ifdef _WIN32
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif
    return 0;
fail:
#ifdef _WIN32
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif
    return 1;
}
