/*
 * stm-keystore.h -- pkcs11-check simulator stub.
 *
 * Cryptech's ks_token.c is written for bare-metal STM32 flash via <stm-keystore.h>.
 * That header is normally supplied by the Cryptech platform firmware tree; it has
 * never lived in sw/libhal, so a Linux in-process build of libhal needs a stub.
 *
 * This stub backs the same small API with a plain file (default
 * /var/lib/cryptech/keystore.bin; override via $CRYPTECH_KEYSTORE_DIR) so libhal
 * builds as a Linux in-process module and persists token state across the
 * subprocess-per-test-file isolation model pkcs11-check uses.
 *
 * NOR-flash semantics are emulated: a write can only clear bits (1->0); setting
 * bits back to 1 requires an erase. ks_token.c depends on this behaviour.
 *
 * Test-only. Not for production. See docker/cryptech/Dockerfile.
 */
#ifndef STM_KEYSTORE_H
#define STM_KEYSTORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMSIS_HAL_OK 0

/* HAL_KS_BLOCK_SIZE is 4096*2 (ks.h). One block per subsector keeps the
 * "block size is a multiple of subsector size" compile-time check trivially
 * satisfied; 64 subsectors = 512 KiB, ample for PKCS#11 token objects. */
#define KEYSTORE_PAGE_SIZE       256
#define KEYSTORE_SUBSECTOR_SIZE  HAL_KS_BLOCK_SIZE
#define KEYSTORE_NUM_SUBSECTORS  64

static const char *cryptech_keystore_path(void) {
  static char path[512];
  const char *dir = getenv("CRYPTECH_KEYSTORE_DIR");
  if (!dir || !*dir) dir = "/var/lib/cryptech";
  snprintf(path, sizeof(path), "%s/keystore.bin", dir);
  return path;
}

static int cryptech_keystore_ensure(size_t total_size) {
  const char *path = cryptech_keystore_path();
  FILE *f = fopen(path, "rb");
  if (f) { fclose(f); return 0; }
  f = fopen(path, "w+b");
  if (!f) return -1;
  unsigned char fill[4096];
  memset(fill, 0xFF, sizeof(fill));
  size_t remaining = total_size;
  while (remaining > 0) {
    size_t n = remaining > sizeof(fill) ? sizeof(fill) : remaining;
    if (fwrite(fill, 1, n, f) != n) { fclose(f); return -1; }
    remaining -= n;
  }
  fclose(f);
  return 0;
}

static int keystore_read_data(uint32_t offset, uint8_t *dst, size_t len) {
  if (cryptech_keystore_ensure((size_t)KEYSTORE_NUM_SUBSECTORS * KEYSTORE_SUBSECTOR_SIZE) != 0)
    return -1;
  FILE *f = fopen(cryptech_keystore_path(), "rb");
  if (!f) return -1;
  if (fseek(f, (long)offset, SEEK_SET) != 0) { fclose(f); return -1; }
  size_t n = fread(dst, 1, len, f);
  fclose(f);
  return (n == len) ? CMSIS_HAL_OK : -1;
}

static int keystore_write_data(uint32_t offset, const uint8_t *src, size_t len) {
  if (cryptech_keystore_ensure((size_t)KEYSTORE_NUM_SUBSECTORS * KEYSTORE_SUBSECTOR_SIZE) != 0)
    return -1;
  FILE *f = fopen(cryptech_keystore_path(), "r+b");
  if (!f) return -1;
  if (fseek(f, (long)offset, SEEK_SET) != 0) { fclose(f); return -1; }
  unsigned char buf[256];
  while (len > 0) {
    size_t chunk = len > sizeof(buf) ? sizeof(buf) : len;
    if (fread(buf, 1, chunk, f) != chunk) { fclose(f); return -1; }
    for (size_t i = 0; i < chunk; i++) buf[i] &= src[i];
    if (fseek(f, -(long)chunk, SEEK_CUR) != 0) { fclose(f); return -1; }
    if (fwrite(buf, 1, chunk, f) != chunk) { fclose(f); return -1; }
    offset += (uint32_t)chunk;
    src    += chunk;
    len    -= chunk;
  }
  fclose(f);
  return CMSIS_HAL_OK;
}

static int keystore_erase_subsector(uint32_t subsector) {
  if (subsector >= KEYSTORE_NUM_SUBSECTORS) return -1;
  if (cryptech_keystore_ensure((size_t)KEYSTORE_NUM_SUBSECTORS * KEYSTORE_SUBSECTOR_SIZE) != 0)
    return -1;
  FILE *f = fopen(cryptech_keystore_path(), "r+b");
  if (!f) return -1;
  unsigned char fill[4096];
  memset(fill, 0xFF, sizeof(fill));
  if (fseek(f, (long)(subsector * KEYSTORE_SUBSECTOR_SIZE), SEEK_SET) != 0) { fclose(f); return -1; }
  size_t remaining = KEYSTORE_SUBSECTOR_SIZE;
  while (remaining > 0) {
    size_t n = remaining > sizeof(fill) ? sizeof(fill) : remaining;
    if (fwrite(fill, 1, n, f) != n) { fclose(f); return -1; }
    remaining -= n;
  }
  fclose(f);
  return CMSIS_HAL_OK;
}

/*
 * Platform stubs required when libhal is built without platform firmware
 * (IO_BUS=none). These are declared extern in hal_internal.h / hal.h but
 * never defined in sw/libhal -- on real hardware they're supplied by the
 * Cryptech platform firmware tree. Defined here as plain (non-static)
 * functions so they're global symbols in ks_token.o; ks_token.c is the only
 * translation unit that includes this header, so there's no multiple-
 * definition risk, and the libhal.a link pulls ks_token.o in to satisfy
 * the keystore API (which makes these stubs visible process-wide).
 */

#include <stdlib.h>

/* hal_error_t is an enum in hal.h; HAL_OK is 0 by convention. */
#ifndef HAL_OK
#define HAL_OK 0
#endif

/* PKCS#11 login failure throttle. Real platform sleeps; for tests we yield. */
void hal_sleep(const unsigned seconds) {
  (void)seconds;
  /* No-op: tests don't need the anti-brute-force delay. */
}

/* Static-memory allocator. On the HSM this returns from a reserved arena;
   for the Linux in-process build, plain malloc/free is correct. */
void *hal_allocate_static_memory(const size_t size) {
  return malloc(size);
}

hal_error_t hal_free_static_memory(const void * const ptr) {
  free((void *)ptr);  /* free(NULL) is safe */
  return HAL_OK;
}

/*
 * FPGA core I/O. With IO_BUS=none there are no hardware cores; libhal uses
 * software fallbacks (libtfm bignum + s/w hash) via HAL_ONLY_USE_SOFTWARE_-
 * HASH_CORES=1, so these should never be called in the in-process test
 * build. If they are, return HAL_ERROR_CORE_NOT_FOUND rather than crash.
 */
hal_error_t hal_io_write(const hal_core_t *core, const hal_addr_t offset,
                         const uint8_t *buf, const size_t len) {
  (void)core; (void)offset; (void)buf; (void)len;
  return HAL_ERROR_CORE_NOT_FOUND;
}

hal_error_t hal_io_read(const hal_core_t *core, const hal_addr_t offset,
                        uint8_t *buf, const size_t len) {
  (void)core; (void)offset; (void)buf; (void)len;
  return HAL_ERROR_CORE_NOT_FOUND;
}

#endif /* STM_KEYSTORE_H */
