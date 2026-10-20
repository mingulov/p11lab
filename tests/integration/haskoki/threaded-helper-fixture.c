/* SPDX-License-Identifier: Apache-2.0
 * Deterministic test-helper fixture, not Haskoki behavior evidence.
 * A module worker explicitly unmasks stop signals. It delivers a process-
 * directed stop exactly between the holder's check and blocking syscall.
 */
#define _GNU_SOURCE
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include "pkcs11.h"
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int want_signal, initialized, injected, stop_signal;
static volatile sig_atomic_t delivered;
static pthread_t thread, main_thread;
static void (*original_handler)(int);

static void observed_handler(int signum) {
    original_handler(signum);
    delivered = 1;
}
static void *worker(void *unused) {
    (void)unused;
    sigset_t signals;
    sigemptyset(&signals); sigaddset(&signals, SIGTERM); sigaddset(&signals, SIGINT);
    pthread_sigmask(SIG_UNBLOCK, &signals, NULL);
    pthread_mutex_lock(&mutex);
    while (!want_signal) pthread_cond_wait(&changed, &mutex);
    kill(getpid(), stop_signal);
    while (!delivered) { }
    pthread_cond_signal(&changed);
    pthread_mutex_unlock(&mutex);
    return NULL;
}
static CK_RV initialize(CK_VOID_PTR unused) {
    (void)unused;
    main_thread = pthread_self();
    stop_signal = atoi(getenv("MOCK_STOP_SIGNAL"));
    struct sigaction current;
    if (sigaction(stop_signal, NULL, &current)) return CKR_GENERAL_ERROR;
    original_handler = current.sa_handler;
    current.sa_handler = observed_handler;
    if (sigaction(stop_signal, &current, NULL)) return CKR_GENERAL_ERROR;
    if (pthread_create(&thread, NULL, worker, NULL)) return CKR_GENERAL_ERROR;
    initialized = 1;
    return CKR_OK;
}
static CK_RV finalize(CK_VOID_PTR unused) {
    (void)unused;
    pthread_join(thread, NULL);
    const char marker[] = "worker-stop-delivered; finalize-called\n";
    ssize_t written = write(STDERR_FILENO, marker, sizeof(marker) - 1);
    (void)written;
    return (CK_RV)atoi(getenv("MOCK_FINALIZE_RV"));
}
static CK_FUNCTION_LIST functions = { .C_Initialize = initialize, .C_Finalize = finalize };
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) { *list = &functions; return CKR_OK; }

static void inject_stop_before_wait(void) {
    if (!initialized || injected || !pthread_equal(main_thread, pthread_self())) return;
    injected = 1;
    sigset_t blocked, previous;
    sigemptyset(&blocked); sigaddset(&blocked, stop_signal);
    pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    pthread_mutex_lock(&mutex);
    want_signal = 1;
    pthread_cond_signal(&changed);
    while (!delivered) pthread_cond_wait(&changed, &mutex);
    pthread_mutex_unlock(&mutex);
    pthread_sigmask(SIG_SETMASK, &previous, NULL);
}
int sigsuspend(const sigset_t *mask) {
    int (*original)(const sigset_t *) = dlsym(RTLD_NEXT, "sigsuspend");
    inject_stop_before_wait();
    return original(mask);
}
ssize_t read(int fd, void *buffer, size_t length) {
    ssize_t (*original)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    inject_stop_before_wait();
    return original(fd, buffer, length);
}
