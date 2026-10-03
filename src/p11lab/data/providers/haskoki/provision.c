/* SPDX-License-Identifier: Apache-2.0 */
/* P11Lab Haskoki provisioner (P11Lab-original helper).
 *
 * Performs the single provisioning open of the configured store: dlopen the
 * module, C_Initialize (seats and commits the provisioned token into the
 * configured SQLite store on first open), verify slot 0 serves label
 * "haskoki-demo" with initialized flags, then C_Finalize. HASKOKI_CONFIG
 * comes from the environment (exported by the provider adapter).
 *
 * Exit 0 iff provisioning/open/label checks pass. Native PKCS#11 return
 * values are preserved on stderr, never normalized. This tool opens the
 * single-writer store, so the adapter runs it only under the init lock;
 * health/readiness never invoke it (lock-safe store inspection instead).
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void fail(const char *msg, CK_RV rv) {
  fprintf(stderr, "provision: %s (rv=0x%lx)\n", msg, (unsigned long)rv);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: haskoki-provision /path/to/libhaskoki.so\n");
    return 2;
  }
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "provision: dlopen failed: %s\n", dlerror());
    return 1;
  }
  CK_C_GetFunctionList get_list =
      (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (!get_list) {
    fprintf(stderr, "provision: dlsym C_GetFunctionList failed: %s\n", dlerror());
    return 1;
  }
  CK_FUNCTION_LIST_PTR f = NULL;
  CK_RV rv = get_list(&f);
  if (rv != CKR_OK || !f) {
    fail("C_GetFunctionList failed", rv);
    return 1;
  }
  rv = f->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    fail("C_Initialize failed", rv);
    return 1;
  }
  CK_ULONG count = 0;
  rv = f->C_GetSlotList(CK_TRUE, NULL_PTR, &count);
  if (rv != CKR_OK || count != 1) {
    fail("expected exactly one token-present slot", rv);
    f->C_Finalize(NULL_PTR);
    return 1;
  }
  CK_SLOT_ID slot = 0;
  rv = f->C_GetSlotList(CK_TRUE, &slot, &count);
  if (rv != CKR_OK || slot != 0) {
    fail("expected the token on slot 0", rv);
    f->C_Finalize(NULL_PTR);
    return 1;
  }
  CK_TOKEN_INFO info;
  memset(&info, 0, sizeof(info));
  rv = f->C_GetTokenInfo(slot, &info);
  if (rv != CKR_OK) {
    fail("C_GetTokenInfo failed", rv);
    f->C_Finalize(NULL_PTR);
    return 1;
  }
  char label[33];
  memcpy(label, info.label, 32);
  label[32] = '\0';
  for (int i = 31; i >= 0 && label[i] == ' '; i--) {
    label[i] = '\0';
  }
  if (strcmp(label, "haskoki-demo") != 0) {
    fprintf(stderr, "provision: unexpected token label: %s\n", label);
    f->C_Finalize(NULL_PTR);
    return 1;
  }
  if (!(info.flags & CKF_TOKEN_INITIALIZED) ||
      !(info.flags & CKF_USER_PIN_INITIALIZED) ||
      !(info.flags & CKF_LOGIN_REQUIRED)) {
    fprintf(stderr,
            "provision: token flags missing initialized/login-required bits: 0x%lx\n",
            (unsigned long)info.flags);
    f->C_Finalize(NULL_PTR);
    return 1;
  }
  printf("provision: slot 0 label=%s flags=0x%lx\n", label,
         (unsigned long)info.flags);
  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    fail("C_Finalize failed", rv);
    return 1;
  }
  printf("provision: OK\n");
  return 0;
}
