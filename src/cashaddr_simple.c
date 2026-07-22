/*
 * Simplified CashAddr decoder for Bitcoin Cash
 * Based on asicseer-pool implementation approach
 * Focuses only on extracting hash160 from CashAddr format
 */

#define _GNU_SOURCE  /* For asprintf */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include "libckpool.h"

/* CashAddr charset for base32 */
static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/* Polymod checksum calculation */
static uint64_t polymod(const uint8_t *values, size_t len)
{
    uint64_t c = 1;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c0 = c >> 35;
        c = ((c & 0x07ffffffffULL) << 5) ^ values[i];
        
        if (c0 & 0x01) c ^= 0x98f2bc8e61ULL;
        if (c0 & 0x02) c ^= 0x79b76d99e2ULL;
        if (c0 & 0x04) c ^= 0xf33e5fb3c4ULL;
        if (c0 & 0x08) c ^= 0xae2eabe2a8ULL;
        if (c0 & 0x10) c ^= 0x1e4f43e470ULL;
    }
    return c;
}

/* Convert from 5-bit groups to 8-bit bytes */
static bool convert_bits_5to8(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
    uint32_t acc = 0;
    int bits = 0;
    *outlen = 0;

    for (size_t i = 0; i < inlen; ++i) {
        uint8_t value = in[i];

        /* Each input value should be 0-31 (5 bits) */
        if (value >= 32) {
            return false;
        }

        acc = (acc << 5) | value;
        bits += 5;

        while (bits >= 8) {
            bits -= 8;
            out[(*outlen)++] = (acc >> bits) & 0xff;
        }
    }

    /* Check that any remaining bits are zero (proper padding) */
    if (bits >= 5 || (bits > 0 && ((acc << (8 - bits)) & 0xff) != 0)) {
        return false;
    }

    return true;
}

/* Extract hash160 from CashAddr - simplified version */
bool cashaddr_decode_simple(const char *addr, uint8_t *hash160, bool *is_p2sh)
{
    const char *sep, *payload;
    size_t prefix_len, payload_len, i;
    uint8_t checksum_values[256];
    uint8_t data[112];
    uint8_t decoded[65];
    size_t data_len = 0, decoded_len;
    bool saw_lower = false, saw_upper = false;

    if (!addr || !hash160 || !is_p2sh)
        return false;

    sep = strrchr(addr, ':');
    if (!sep || sep == addr || !sep[1]) {
        LOGDEBUG("CashAddr-style address requires an explicit prefix");
        return false;
    }

    prefix_len = (size_t)(sep - addr);
    payload = sep + 1;
    payload_len = strlen(payload);
    if (prefix_len > 83 || payload_len < 14 || payload_len > 112 ||
        prefix_len + 1 + payload_len > sizeof(checksum_values)) {
        LOGDEBUG("Invalid CashAddr-style address length");
        return false;
    }

    for (i = 0; i < prefix_len; i++) {
        unsigned char ch = (unsigned char)addr[i];

        if (ch < 33 || ch > 126) {
            LOGDEBUG("Invalid prefix character");
            return false;
        }
        if (islower(ch)) saw_lower = true;
        if (isupper(ch)) saw_upper = true;
        checksum_values[i] = (uint8_t)(tolower(ch) & 0x1f);
    }
    checksum_values[prefix_len] = 0;

    for (i = 0; i < payload_len; i++) {
        unsigned char ch = (unsigned char)payload[i];
        int8_t value;

        if (islower(ch)) saw_lower = true;
        if (isupper(ch)) saw_upper = true;
        if (ch >= sizeof(CHARSET_REV)) {
            LOGDEBUG("Invalid character in payload");
            return false;
        }
        value = CHARSET_REV[(uint8_t)tolower(ch)];
        if (value < 0) {
            LOGDEBUG("Invalid character in payload: %c", payload[i]);
            return false;
        }
        data[data_len++] = (uint8_t)value;
        checksum_values[prefix_len + 1 + i] = (uint8_t)value;
    }

    if (saw_lower && saw_upper) {
        LOGDEBUG("Mixed-case CashAddr-style address is invalid");
        return false;
    }

    /* This polymod implementation returns the pre-XOR state. A valid
     * CashAddr checksum therefore has the constant value 1. */
    if (polymod(checksum_values, prefix_len + 1 + payload_len) != 1) {
        LOGDEBUG("CashAddr-style checksum validation failed");
        return false;
    }

    /* The last eight 5-bit symbols are the 40-bit checksum. */
    if (data_len < 9)
        return false;
    data_len -= 8;

    if (!convert_bits_5to8(decoded, &decoded_len, data, data_len)) {
        LOGDEBUG("Failed to convert CashAddr-style payload to bytes");
        return false;
    }

    /* CKPool currently creates standard 20-byte P2PKH and P2SH outputs. */
    if (decoded_len != 21 || (decoded[0] & 0x07) != 0) {
        LOGDEBUG("Unsupported CashAddr-style payload size");
        return false;
    }

    switch (decoded[0] >> 3) {
    case 0:
        *is_p2sh = false;
        break;
    case 1:
        *is_p2sh = true;
        break;
    default:
        LOGDEBUG("Unsupported CashAddr-style address type");
        return false;
    }

    memcpy(hash160, decoded + 1, 20);
    return true;
}

/* Build P2PKH script from hash160 */
int hash160_to_p2pkh_script(uint8_t *script, const uint8_t *hash160)
{
    script[0] = 0x76;  /* OP_DUP */
    script[1] = 0xa9;  /* OP_HASH160 */
    script[2] = 0x14;  /* Push 20 bytes */
    memcpy(&script[3], hash160, 20);
    script[23] = 0x88; /* OP_EQUALVERIFY */
    script[24] = 0xac; /* OP_CHECKSIG */
    return 25;
}

/* Build P2SH script from hash160 */
int hash160_to_p2sh_script(uint8_t *script, const uint8_t *hash160)
{
    script[0] = 0xa9;  /* OP_HASH160 */
    script[1] = 0x14;  /* Push 20 bytes */
    memcpy(&script[2], hash160, 20);
    script[22] = 0x87; /* OP_EQUAL */
    return 23;
}

/* Simple CashAddr to script converter */
int cashaddr_to_script(const char *addr, uint8_t *script)
{
    uint8_t hash160[20];
    bool is_p2sh;
    
    if (!cashaddr_decode_simple(addr, hash160, &is_p2sh)) {
        LOGWARNING("Failed to decode CashAddr: %s", addr);
        return 0;
    }
    
    if (is_p2sh) {
        return hash160_to_p2sh_script(script, hash160);
    } else {
        return hash160_to_p2pkh_script(script, hash160);
    }
}