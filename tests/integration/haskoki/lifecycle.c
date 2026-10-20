/* SPDX-License-Identifier: Apache-2.0
 * Test-only real PKCS#11 lifecycle driver. Never ships in a provider image.
 * PINs are read from caller-owned files and are never printed. Native CK_RV
 * failures remain visible; no retries, reset, or return-value normalization.
 */
#define _POSIX_C_SOURCE 200809L
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include "pkcs11.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Immutable once handlers are installed, before dlopen/C_Initialize can
 * create workers. A byte wakes the holder even when a worker takes the stop.
 * Keep both ends open until process exit: handlers may run during finalization.
 */
static int signal_writer = -1;
static void stop(int sig) {
    int saved_errno = errno;
    unsigned char byte = (unsigned char)sig;
    ssize_t written;
    do { written = write(signal_writer, &byte, 1); } while (written < 0 && errno == EINTR);
    /* EAGAIN means an earlier queued stop already makes the pipe readable. */
    errno = saved_errno;
}
static int report(const char *operation, CK_RV rv) {
    if (rv == CKR_OK) return 0;
    fprintf(stderr, "lifecycle: %s failed (rv=0x%lx)\n", operation, (unsigned long)rv);
    return 1;
}
static int pin_read(const char *path, unsigned char *bytes, CK_ULONG *size) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { fputs("lifecycle: cannot open PIN file\n", stderr); return 1; }
    ssize_t used = 0, got;
    while (used < 1025 && (got = read(fd, bytes + used, (size_t)(1025 - used))) > 0) used += got;
    int read_failed = used == 1025 || used == 0 || got < 0;
    int close_failed = close(fd) != 0;
    int failed = read_failed || close_failed;
    if (failed) { fputs("lifecycle: invalid PIN file\n", stderr); return 1; }
    *size = (CK_ULONG)used;
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 3 ||
        !( (strcmp(argv[2], "hold") == 0 && argc == 3) ||
           (strcmp(argv[2], "login") == 0 && argc == 5) ||
           (strcmp(argv[2], "set-pin") == 0 && argc == 6) ||
           (strcmp(argv[2], "init-pin") == 0 && argc == 5) ||
           (strcmp(argv[2], "init-token") == 0 && argc == 5))) {
        fputs("usage: lifecycle MODULE hold|login ROLE PIN_FILE|set-pin ROLE OLD_FILE NEW_FILE|init-pin SO_FILE NEW_FILE|init-token SO_FILE LABEL\n", stderr);
        return 2;
    }
    CK_USER_TYPE role = CKU_USER;
    if (strcmp(argv[2], "login") == 0 || strcmp(argv[2], "set-pin") == 0) {
        if (strcmp(argv[3], "so") == 0) role = CKU_SO;
        else if (strcmp(argv[3], "user") != 0) { fputs("lifecycle: invalid role\n", stderr); return 2; }
    }
    int stop_pipe[2] = {-1, -1};
    if (strcmp(argv[2], "hold") == 0) {
        if (pipe(stop_pipe) || fcntl(stop_pipe[0], F_SETFD, FD_CLOEXEC) < 0 ||
            fcntl(stop_pipe[1], F_SETFD, FD_CLOEXEC) < 0 ||
            fcntl(stop_pipe[1], F_SETFL, O_NONBLOCK) < 0) {
            fputs("lifecycle: stop pipe setup failed\n", stderr); return 1;
        }
        signal_writer = stop_pipe[1];
        struct sigaction action;
        memset(&action, 0, sizeof(action)); action.sa_handler = stop;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, SIGTERM); sigaddset(&action.sa_mask, SIGINT);
        if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 1;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fputs("lifecycle: dlopen failed\n", stderr); return 1; }
    CK_C_GetFunctionList get = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR f = NULL;
    if (!get || report("C_GetFunctionList", get(&f)) || !f) { dlclose(handle); return 1; }
    if (report("C_Initialize", f->C_Initialize(NULL_PTR))) { dlclose(handle); return 1; }
    int result = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char old_pin[1025] = {0}, new_pin[1025] = {0};
    CK_ULONG old_size = 0, new_size = 0;
    if (strcmp(argv[2], "hold") == 0) {
        /* No flag-check/wait seam: a stop delivered on any module worker
         * leaves a queued byte even if it arrives before this read. */
        unsigned char byte;
        ssize_t received;
        puts("holder-ready"); fflush(stdout);
        do { received = read(stop_pipe[0], &byte, 1); } while (received < 0 && errno == EINTR);
        if (received != 1) { fputs("lifecycle: holder wait failed\n", stderr); result = 1; }
    } else if (strcmp(argv[2], "init-token") == 0) {
        unsigned char label[32]; memset(label, ' ', sizeof(label));
        size_t n = strlen(argv[4]);
        if (n > sizeof(label)) result = 2;
        else if ((result = pin_read(argv[3], old_pin, &old_size)) == 0) {
            memcpy(label, argv[4], n);
            result = report("C_InitToken", f->C_InitToken(0, old_pin, old_size, label));
        }
    } else {
        int init_pin = strcmp(argv[2], "init-pin") == 0;
        result = pin_read(argv[init_pin ? 3 : 4], old_pin, &old_size);
        if (!result && (init_pin || strcmp(argv[2], "set-pin") == 0))
            result = pin_read(argv[init_pin ? 4 : 5], new_pin, &new_size);
        if (!result) result = report("C_OpenSession", f->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session));
        if (!result) result = report("C_Login", f->C_Login(session, init_pin ? CKU_SO : role, old_pin, old_size));
        if (!result && init_pin) result = report("C_InitPIN", f->C_InitPIN(session, new_pin, new_size));
        if (!result && strcmp(argv[2], "set-pin") == 0) result = report("C_SetPIN", f->C_SetPIN(session, old_pin, old_size, new_pin, new_size));
    }
    memset(old_pin, 0, sizeof(old_pin)); memset(new_pin, 0, sizeof(new_pin));
    if (session != CK_INVALID_HANDLE && report("C_CloseSession", f->C_CloseSession(session))) result = 1;
    if (report("C_Finalize", f->C_Finalize(NULL_PTR))) result = 1;
    if (dlclose(handle) != 0) result = 1;
    if (!result) puts("lifecycle: OK");
    return result;
}
