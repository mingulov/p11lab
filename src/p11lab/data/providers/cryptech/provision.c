/* SPDX-License-Identifier: Apache-2.0
 * Simulator lifecycle only. C_Initialize performs module-native state creation;
 * the standard PIN provisioning functions remain untouched and unsupported.
 */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(r, n) r n
#define CK_DECLARE_FUNCTION(r, n) r n
#define CK_DECLARE_FUNCTION_POINTER(r, n) r (*n)
#define CK_CALLBACK_FUNCTION(r, n) r (*n)
#define NULL_PTR 0
#include <pkcs11.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int report(const char *name, CK_RV rv)
{
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", name, (unsigned long)rv);
    return 1;
}

/* The upstream NOR driver omits status when calculating its CRC. CRC covers
 * type, legacy bytes, and payload, but excludes status and the CRC itself.
 * This parser never opens HAL and never repairs an invalid file. */
static int inspect(const char *path)
{
    unsigned char block[8192];
    FILE *file = fopen(path, "rb");
    unsigned pins = 0;
    int status = 1;
    if (!file) goto out;
    for (unsigned b = 0; b < 64; b++) {
        if (fread(block, 1, sizeof(block), file) != sizeof(block)) goto out;
        if (block[0] == 0xff) {
            for (size_t i = 0; i < sizeof(block); i++) if (block[i] != 0xff) goto out;
            continue;
        }
        if (block[0] == 0x00) continue; /* upstream zeroed free block */
        if ((block[0] != 0xaa && block[0] != 0x55) ||
            (block[1] != 0x66 && block[1] != 0x44) ||
            (block[2] != 0xff && block[2] != 0x00) ||
            (block[3] != 0xff && block[3] != 0x00)) goto out;
        uint32_t crc = UINT32_MAX;
        for (size_t i = 0; i < sizeof(block); i++) {
            if (i == 1 || (i >= 4 && i < 8)) continue;
            crc ^= block[i];
            for (unsigned bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
        }
        crc ^= UINT32_MAX;
        uint32_t stored = (uint32_t)block[4] | (uint32_t)block[5] << 8 |
            (uint32_t)block[6] << 16 | (uint32_t)block[7] << 24;
        if (crc != stored) goto out;
        if (block[0] == 0xaa && block[1] == 0x66) pins++;
    }
    if (fgetc(file) != EOF || ferror(file) || pins != 1) goto out;
    status = 0;
out:
    if (file && fclose(file)) status = 1;
    if (status) fputs("p11lab-cryptech: invalid NOR keystore; state preserved\n", stderr);
    return status;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "inspect")) return inspect(argv[2]);
    const char *module = getenv("P11LAB_MODULE");
    CK_FUNCTION_LIST_PTR functions = NULL;
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slot = 0;
    CK_ULONG slots = 0;
    CK_TOKEN_INFO info;
    CK_RV rv;
    void *handle = NULL, *symbol;
    int initialized = 0, status = 1;
    unsigned char label[32], pin[] = "fnord";
    if (argc != 2 || !module || (strcmp(argv[1], "init") && strcmp(argv[1], "health"))) {
        fputs("p11lab-cryptech: invalid operation or module control\n", stderr);
        return 2;
    }
    memset(label, ' ', sizeof(label));
    memcpy(label, "Cryptech Token", 14);
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-cryptech: cannot load module\n", stderr); goto out; }
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
    memcpy(&get_list, &symbol, sizeof(get_list));
    if (!get_list) { fputs("p11lab-cryptech: missing C_GetFunctionList\n", stderr); goto out; }
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
    if (memcmp(info.label, label, sizeof(label))) {
        fputs("p11lab-cryptech: unexpected native token label\n", stderr); goto out;
    }
    rv = functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv) { report("C_OpenSession", rv); goto out; }
    for (CK_USER_TYPE user = CKU_SO; user <= CKU_USER; user++) {
        rv = functions->C_Login(session, user, pin, sizeof(pin) - 1);
        if (rv) { report("C_Login", rv); goto out; }
        rv = functions->C_Logout(session);
        if (rv) { report("C_Logout", rv); goto out; }
    }
    puts("ready: native_slot=0 token_present_index=0 label=Cryptech Token; fixed-credential simulator; crypto unqualified");
    status = 0;
out:
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
