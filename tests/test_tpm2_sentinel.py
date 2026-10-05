"""Slot-scan sentinel regression: a labelled token at slot 0 must be found.

Compiles the tpm2 provisioner against a hermetic cryptoki-subset shim and
drives its native slot scan with a stub module. Slot 0 is a valid PKCS#11
slot ID, so the scan must track "match seen" separately from the slot value
(the sibling provisioners already do; tpm2 used ``if (!found)``).
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from p11lab.catalog import packaged_asset

SHIM = r"""
#ifndef P11LAB_TEST_PKCS11_SHIM_H
#define P11LAB_TEST_PKCS11_SHIM_H
/* Hermetic cryptoki subset for slot-scan tests. CK_TOKEN_INFO and
 * CK_MECHANISM_INFO layouts, the CK_FUNCTION_LIST member order, and every
 * prototype below used by the scan mirror PKCS#11 v2.40; members the scan
 * never touches are present for layout only with placeholder types. Both
 * the stub module and the provisioner compile against this header, so the
 * test proves scan logic, not third-party ABI compatibility. */
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;
typedef void *CK_VOID_PTR;
typedef struct CK_VERSION { unsigned char major; unsigned char minor; } CK_VERSION;
typedef struct CK_TOKEN_INFO {
    unsigned char label[32];
    unsigned char manufacturerID[32];
    unsigned char model[16];
    unsigned char serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    unsigned char utcTime[16];
} CK_TOKEN_INFO;
typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef struct CK_ATTRIBUTE {
    CK_ULONG type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;
typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;
typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;
typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;
#define CK_TRUE 1
#define CK_INVALID_HANDLE 0
#define CKR_OK 0
#define CKR_GENERAL_ERROR 5
#define CKF_SERIAL_SESSION 0x00000004UL
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_ULONG event, CK_VOID_PTR pApplication);
typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_UNUSED)(void);
typedef struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_UNUSED C_GetInfo;
    CK_C_UNUSED C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_UNUSED C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_UNUSED C_InitToken;
    CK_C_UNUSED C_InitPIN;
    CK_C_UNUSED C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_UNUSED C_CloseAllSessions;
    CK_C_UNUSED C_GetSessionInfo;
    CK_C_UNUSED C_GetOperationState;
    CK_C_UNUSED C_SetOperationState;
    CK_C_UNUSED C_Login;
    CK_C_UNUSED C_Logout;
    CK_C_UNUSED C_CreateObject;
    CK_C_UNUSED C_CopyObject;
    CK_C_UNUSED C_DestroyObject;
    CK_C_UNUSED C_GetObjectSize;
    CK_C_UNUSED C_GetAttributeValue;
    CK_C_UNUSED C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_UNUSED C_EncryptInit;
    CK_C_UNUSED C_Encrypt;
    CK_C_UNUSED C_EncryptUpdate;
    CK_C_UNUSED C_EncryptFinal;
    CK_C_UNUSED C_DecryptInit;
    CK_C_UNUSED C_Decrypt;
    CK_C_UNUSED C_DecryptUpdate;
    CK_C_UNUSED C_DecryptFinal;
    CK_C_UNUSED C_DigestInit;
    CK_C_UNUSED C_Digest;
    CK_C_UNUSED C_DigestUpdate;
    CK_C_UNUSED C_DigestKey;
    CK_C_UNUSED C_DigestFinal;
    CK_C_UNUSED C_SignInit;
    CK_C_UNUSED C_Sign;
    CK_C_UNUSED C_SignUpdate;
    CK_C_UNUSED C_SignFinal;
    CK_C_UNUSED C_SignRecoverInit;
    CK_C_UNUSED C_SignRecover;
    CK_C_UNUSED C_VerifyInit;
    CK_C_UNUSED C_Verify;
    CK_C_UNUSED C_VerifyUpdate;
    CK_C_UNUSED C_VerifyFinal;
    CK_C_UNUSED C_VerifyRecoverInit;
    CK_C_UNUSED C_VerifyRecover;
    CK_C_UNUSED C_DigestEncryptUpdate;
    CK_C_UNUSED C_DecryptDigestUpdate;
    CK_C_UNUSED C_SignEncryptUpdate;
    CK_C_UNUSED C_DecryptVerifyUpdate;
    CK_C_UNUSED C_GenerateKey;
    CK_C_UNUSED C_GenerateKeyPair;
    CK_C_UNUSED C_WrapKey;
    CK_C_UNUSED C_UnwrapKey;
    CK_C_UNUSED C_DeriveKey;
    CK_C_UNUSED C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_UNUSED C_GetFunctionStatus;
    CK_C_UNUSED C_CancelFunction;
    CK_C_UNUSED C_WaitForSlotEvent;
} CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;
#endif
"""

STUB = r"""
#include <p11-kit/pkcs11.h>
#include <string.h>
#ifndef STUB_MATCH_SLOT
#define STUB_MATCH_SLOT 0
#endif
#define OTHER_SLOT 5
static CK_RV on_initialize(CK_VOID_PTR args) { (void)args; return CKR_OK; }
static CK_RV on_finalize(CK_VOID_PTR reserved) { (void)reserved; return CKR_OK; }
static CK_RV on_slots(CK_BBOOL present, CK_SLOT_ID_PTR list, CK_ULONG_PTR count) {
    if (!present || !count) return CKR_GENERAL_ERROR;
    if (!list) { *count = 2; return CKR_OK; }
    if (*count < 2) return CKR_GENERAL_ERROR;
    list[0] = OTHER_SLOT;
    list[1] = STUB_MATCH_SLOT;
    *count = 2;
    return CKR_OK;
}
static CK_RV on_token(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
    const char *label = (slot == STUB_MATCH_SLOT) ? "P11Lab" : "Other";
    if (!info || (slot != STUB_MATCH_SLOT && slot != OTHER_SLOT)) return CKR_GENERAL_ERROR;
    memset(info, 0, sizeof(*info));
    memset(info->label, ' ', sizeof(info->label));
    memcpy(info->label, label, strlen(label));
    info->flags = (slot == STUB_MATCH_SLOT) ? 0x40d : 0x0;
    return CKR_OK;
}
static CK_RV on_mechs(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    static const CK_MECHANISM_TYPE mechs[] = {0x1041, 0x1040, 0x0};
    if (slot != STUB_MATCH_SLOT || !count) return CKR_GENERAL_ERROR;
    if (!list) { *count = 3; return CKR_OK; }
    if (*count < 3) return CKR_GENERAL_ERROR;
    memcpy(list, mechs, sizeof(mechs));
    *count = 3;
    return CKR_OK;
}
static CK_RV on_mech_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info) {
    if (slot != STUB_MATCH_SLOT || !info) return CKR_GENERAL_ERROR;
    memset(info, 0, sizeof(*info));
    if (type == 0x1041) info->flags = 0x800;
    else if (type == 0x1040) info->flags = 0x10000;
    else if (type != 0x0) return CKR_GENERAL_ERROR;
    return CKR_OK;
}
static CK_RV on_open(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify,
    CK_SESSION_HANDLE_PTR session) {
    (void)app; (void)notify;
    if (slot != STUB_MATCH_SLOT || !(flags & CKF_SERIAL_SESSION) || !session) return CKR_GENERAL_ERROR;
    *session = 1;
    return CKR_OK;
}
static CK_RV on_close(CK_SESSION_HANDLE session) { return session == 1 ? CKR_OK : CKR_GENERAL_ERROR; }
static CK_RV on_random(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG length) {
    if (session != 1 || !data) return CKR_GENERAL_ERROR;
    memset(data, 0xa5, length);
    return CKR_OK;
}
static int find_calls;
static CK_RV on_find_init(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR tpl, CK_ULONG count) {
    (void)tpl; (void)count;
    if (session != 1) return CKR_GENERAL_ERROR;
    find_calls = 0;
    return CKR_OK;
}
static CK_RV on_find(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects, CK_ULONG max,
    CK_ULONG_PTR got) {
    if (session != 1 || !objects || !got || max < 1) return CKR_GENERAL_ERROR;
    find_calls++;
    if (find_calls == 1) { objects[0] = 42; *got = 1; } else { *got = 0; }
    return CKR_OK;
}
static CK_RV on_find_final(CK_SESSION_HANDLE session) { return session == 1 ? CKR_OK : CKR_GENERAL_ERROR; }
static CK_FUNCTION_LIST table = {
    .version = {2, 40},
    .C_Initialize = on_initialize,
    .C_Finalize = on_finalize,
    .C_GetSlotList = on_slots,
    .C_GetTokenInfo = on_token,
    .C_GetMechanismList = on_mechs,
    .C_GetMechanismInfo = on_mech_info,
    .C_OpenSession = on_open,
    .C_CloseSession = on_close,
    .C_GenerateRandom = on_random,
    .C_FindObjectsInit = on_find_init,
    .C_FindObjects = on_find,
    .C_FindObjectsFinal = on_find_final,
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
    if (!list) return CKR_GENERAL_ERROR;
    *list = &table;
    return CKR_OK;
}
"""

DRIVER = r"""
#define main p11lab_tpm2_hidden_main
#include "PROVISION_C"
#undef main
#include <stdio.h>
int main(void) {
    int slot_id = -1, present_index = -1;
    unsigned objects = 0;
    int status = native(0, &slot_id, &present_index, &objects);
    printf("scan: status=%d slot=%d present=%d objects=%u\n", status, slot_id, present_index, objects);
    return status;
}
"""


def _build(tmp_path: Path, match_slot: int):
    include = tmp_path / "include" / "p11-kit"
    include.mkdir(parents=True)
    (include / "pkcs11.h").write_text(SHIM)
    provision = Path(str(packaged_asset("tpm2", "provision.c")))
    (tmp_path / "stub.c").write_text(STUB)
    (tmp_path / "driver.c").write_text(DRIVER.replace("PROVISION_C", str(provision)))
    module = tmp_path / "stub.so"
    driver = tmp_path / "driver"
    subprocess.run(["gcc", "-shared", "-fPIC", f"-DSTUB_MATCH_SLOT={match_slot}", "-I", str(tmp_path / "include"),
                    str(tmp_path / "stub.c"), "-o", str(module)], check=True, capture_output=True, text=True)
    subprocess.run(["gcc", "-I", str(tmp_path / "include"), str(tmp_path / "driver.c"), "-o", str(driver), "-ldl"],
                   check=True, capture_output=True, text=True)
    return module, driver


def _run(driver, module, label):
    env = dict(os.environ, P11LAB_MODULE=str(module), P11LAB_LABEL=label)
    return subprocess.run([str(driver)], env=env, capture_output=True, text=True, timeout=60)


@pytest.mark.skipif(not shutil.which("gcc"), reason="requires gcc")
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="provisioner needs Linux headers")
@pytest.mark.parametrize("match_slot", [0, 1])
def test_labelled_token_found_at_configured_slot(tmp_path, match_slot):
    module, driver = _build(tmp_path, match_slot)
    completed = _run(driver, module, "P11Lab")
    assert completed.returncode == 0, completed.stderr
    assert f"scan: status=0 slot={match_slot} present=1 objects=1" in completed.stdout


@pytest.mark.skipif(not shutil.which("gcc"), reason="requires gcc")
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="provisioner needs Linux headers")
def test_missing_label_still_refuses(tmp_path):
    module, driver = _build(tmp_path, 0)
    completed = _run(driver, module, "Absent")
    assert completed.returncode == 1
    assert "labelled token not present" in completed.stderr


def test_swtpm_listeners_bind_loopback_only():
    """Both swtpm TCP listeners must loopback-bind explicitly (STRIDE S2/D4).

    Shipped swtpm 0.7.1 already defaults both --ctrl/--server TCP
    sockets to 127.0.0.1; the explicit bindaddr pins that property
    in-tree against upstream default changes. The sentinel compile
    above keeps covering buildability.
    """
    source = packaged_asset("tpm2", "provision.c").read_text()
    assert "type=tcp,port=2322,bindaddr=127.0.0.1" in source
    assert "type=tcp,port=2321,bindaddr=127.0.0.1" in source
    for line in source.splitlines():
        if "type=tcp,port=" in line and "snprintf" in line:
            assert "bindaddr=127.0.0.1" in line
