/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab lifecycle adapter. The exact build's wolfPKCS11 header and
 * loaded module retain GPLv3/commercial terms; P11Lab selects GPLv3 for the
 * combined executable. Credentials arrive through private inherited pipes.
 * inspect reads this recipe's native file metadata before loading the module;
 * it does not supply PKCS#11 behavior, decrypt keys, or repair damaged state.
 */
#define _POSIX_C_SOURCE 200809L
#include <wolfpkcs11/pkcs11.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int report(const char *operation, CK_RV rv)
{
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", operation, rv);
    return 1;
}

static void erase(unsigned char *buffer, size_t length)
{
    volatile unsigned char *pointer = buffer;
    while (length--) *pointer++ = 0;
}

static int read_secret(int descriptor, unsigned char *buffer, size_t *length)
{
    ssize_t count;
    *length = 0;
    while ((count = read(descriptor, buffer + *length, 33 - *length)) > 0) {
        *length += (size_t)count;
        if (*length > 32) return 1;
    }
    return count < 0 || *length < 4;
}

static uint32_t big32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int inspect(const char *directory, const unsigned char *label)
{
    /* amd64 non-TPM/non-DHUK native format: two 32-byte PIN hashes with
     * 16-byte seeds and failure counters/times, a 16-byte token seed, then
     * object count/types (8 bytes each), token flags and next-object ID.
     * Secret hashes/seeds are read only to skip them and never printed.
     */
    char path[4096];
    unsigned char metadata[196], tail[8], byte;
    struct stat st;
    uint32_t count;
    int fd, n;
    ssize_t got;
    if (!directory) return 1;
    n = snprintf(path, sizeof(path), "%s/wp11_token_0000000000000001", directory);
    if (n < 0 || (size_t)n >= sizeof(path)) return 1;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != getuid() || (st.st_mode & 0777) != 0600) goto bad;
    got = read(fd, metadata, sizeof(metadata));
    if (got != (ssize_t)sizeof(metadata) || memcmp(metadata, label, 32) ||
        big32(metadata + 32) != 32 || big32(metadata + 104) != 32) goto bad;
    count = big32(metadata + 192);
    if (count > 65536 || st.st_size != (off_t)(204 + (uint64_t)count * 8) ||
        lseek(fd, (off_t)(196 + (uint64_t)count * 8), SEEK_SET) < 0 ||
        read(fd, tail, sizeof(tail)) != (ssize_t)sizeof(tail) ||
        (big32(tail) & 3) != 3 || big32(tail + 4) == 0 || read(fd, &byte, 1) != 0) goto bad;
    close(fd);
    erase(metadata, sizeof(metadata));
    return 0;
bad:
    close(fd);
    erase(metadata, sizeof(metadata));
    return 1;
}

int main(int argc, char **argv)
{
    const char *module = getenv("P11LAB_MODULE"), *label = getenv("P11LAB_LABEL");
    CK_FUNCTION_LIST_PTR functions = NULL;
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_TOKEN_INFO info;
    CK_SLOT_ID slot = 1;
    CK_ULONG slots = 1;
    CK_RV rv;
    unsigned char pin[33] = {0}, so_pin[33] = {0}, padded[32];
    size_t pin_length = 0, so_length = 0;
    void *handle = NULL, *symbol;
    int initialized = 0, status = 1;
    if (argc != 2 || !module || !label || !*label || strlen(label) > sizeof(padded) ||
        (strcmp(argv[1], "init") && strcmp(argv[1], "health") && strcmp(argv[1], "inspect"))) {
        fputs("p11lab-wolfpkcs11: invalid operation or module/label controls\n", stderr);
        return 2;
    }
    memset(padded, ' ', sizeof(padded));
    memcpy(padded, label, strlen(label));
    if (!strcmp(argv[1], "inspect")) {
        status = inspect(getenv("WOLFPKCS11_TOKEN_PATH"), padded);
        if (status) fputs("p11lab-wolfpkcs11: partial or incompatible native token metadata\n", stderr);
        return status;
    }
    if (!strcmp(argv[1], "init") &&
        (read_secret(3, pin, &pin_length) || read_secret(4, so_pin, &so_length))) {
        fputs("p11lab-wolfpkcs11: cannot read valid 4..32 byte credential pipes\n", stderr);
        goto out;
    }
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("p11lab-wolfpkcs11: cannot load module\n", stderr); goto out; }
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol) == sizeof(get_list), "function pointer ABI");
    memcpy(&get_list, &symbol, sizeof(get_list));
    if (!get_list) { fputs("p11lab-wolfpkcs11: missing C_GetFunctionList\n", stderr); goto out; }
    rv = get_list(&functions);
    if (rv || !functions) { report("C_GetFunctionList", rv); goto out; }
    rv = functions->C_Initialize(NULL);
    if (rv) { report("C_Initialize", rv); goto out; }
    initialized = 1;
    rv = functions->C_GetSlotList(CK_TRUE, NULL, &slots);
    if (rv || slots != 1) { report("C_GetSlotList", rv); goto out; }
    rv = functions->C_GetSlotList(CK_TRUE, &slot, &slots);
    if (rv || slots != 1 || slot != 1) { report("C_GetSlotList", rv); goto out; }
    rv = functions->C_GetTokenInfo(slot, &info);
    if (rv) { report("C_GetTokenInfo", rv); goto out; }
    if (!strcmp(argv[1], "init")) {
        if (info.flags & CKF_TOKEN_INITIALIZED) {
            fputs("p11lab-wolfpkcs11: refusing to reset an initialized token\n", stderr);
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
        rv = functions->C_Login(session, CKU_USER, pin, (CK_ULONG)pin_length);
        if (rv) { report("C_Login", rv); goto out; }
        rv = functions->C_Logout(session);
        if (rv) { report("C_Logout", rv); goto out; }
        rv = functions->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
        if (rv) { report("C_CloseSession", rv); goto out; }
        rv = functions->C_GetTokenInfo(slot, &info);
        if (rv) { report("C_GetTokenInfo", rv); goto out; }
    }
    if ((info.flags & (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED)) !=
        (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED) ||
        memcmp(info.label, padded, sizeof(padded)) || info.ulMinPinLen != 4 || info.ulMaxPinLen != 32) {
        fputs("p11lab-wolfpkcs11: expected initialized token is not ready\n", stderr);
        goto out;
    }
    printf("ready: native_slot=1 token_present_index=0 label=%s\n", label);
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
