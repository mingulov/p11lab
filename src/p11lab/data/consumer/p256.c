/* SPDX-License-Identifier: Apache-2.0 */
#include "p256.h"
#include <string.h>

/* The only canonical DER length for a 65-byte P256 point is short form.
 * Long form for lengths below 128, indefinite lengths, and extra bytes are invalid. */
int p11_ec_point(const unsigned char *der, size_t length, unsigned char point[65])
{
    if (length != 67 || der[0] != 4 || der[1] != 65 || der[2] != 4)
        return 0;
    memcpy(point, der + 2, 65);
    return 1;
}

static const unsigned char order[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};

static size_t integer_der(const unsigned char scalar[32], unsigned char out[35])
{
    size_t start = 0, width, padding;
    while (start < 32 && scalar[start] == 0) ++start;
    if (start == 32 || memcmp(scalar, order, 32) >= 0) return 0;
    width = 32 - start;
    padding = (scalar[start] & 0x80) != 0;
    out[0] = 2;
    out[1] = (unsigned char)(width + padding);
    if (padding) out[2] = 0;
    memcpy(out + 2 + padding, scalar + start, width);
    return width + padding + 2;
}

int p11_signature_der(const unsigned char *raw, size_t length,
                      unsigned char *der, size_t *capacity)
{
    unsigned char r[35], s[35];
    size_t nr, ns, total;
    if (length != 64) return 0;
    nr = integer_der(raw, r);
    ns = integer_der(raw + 32, s);
    if (nr == 0 || ns == 0) return 0;
    total = nr + ns + 2;
    if (*capacity < total) return 0;
    der[0] = 0x30;
    der[1] = (unsigned char)(nr + ns);
    memcpy(der + 2, r, nr);
    memcpy(der + 2 + nr, s, ns);
    *capacity = total;
    return 1;
}

/* SEQUENCE { AlgorithmIdentifier { id-ecPublicKey, prime256v1 }, BIT STRING } */
static const unsigned char spki_prefix[26] = {
    0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
    0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00
};

int p11_spki(const unsigned char *der, size_t length, unsigned char point[65])
{
    if (length != 91 || memcmp(der, spki_prefix, 26) != 0 || der[26] != 4)
        return 0;
    memcpy(point, der + 26, 65);
    return 1;
}

void p11_make_spki(const unsigned char point[65], unsigned char der[91])
{
    memcpy(der, spki_prefix, 26);
    memcpy(der + 26, point, 65);
}

size_t p11_public_pem(const unsigned char point[65], char pem[192])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char begin[] = "-----BEGIN PUBLIC KEY-----\n";
    static const char end[] = "-----END PUBLIC KEY-----\n";
    unsigned char der[91];
    size_t i, used = sizeof(begin) - 1, column = 0;
    p11_make_spki(point, der);
    memcpy(pem, begin, used);
    for (i = 0; i < sizeof(der); i += 3) {
        unsigned long value = (unsigned long)der[i] << 16;
        if (i + 1 < sizeof(der)) value |= (unsigned long)der[i + 1] << 8;
        if (i + 2 < sizeof(der)) value |= der[i + 2];
        pem[used++] = alphabet[(value >> 18) & 63];
        pem[used++] = alphabet[(value >> 12) & 63];
        pem[used++] = i + 1 < sizeof(der) ? alphabet[(value >> 6) & 63] : '=';
        pem[used++] = i + 2 < sizeof(der) ? alphabet[value & 63] : '=';
        column += 4;
        if (column == 64) { pem[used++] = '\n'; column = 0; }
    }
    if (column) pem[used++] = '\n';
    memcpy(pem + used, end, sizeof(end) - 1);
    return used + sizeof(end) - 1;
}
