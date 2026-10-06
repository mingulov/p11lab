/* SPDX-License-Identifier: Apache-2.0 */
#ifndef P11LAB_P256_H
#define P11LAB_P256_H
#include <stddef.h>
int p11_ec_point(const unsigned char *der, size_t length, unsigned char point[65]);
int p11_signature_der(const unsigned char *raw, size_t length,
                      unsigned char *der, size_t *capacity);
int p11_spki(const unsigned char *der, size_t length, unsigned char point[65]);
void p11_make_spki(const unsigned char point[65], unsigned char der[91]);
size_t p11_public_pem(const unsigned char point[65], char pem[192]);
#endif
