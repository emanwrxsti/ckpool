/*
 * SHA-512/256 implementation for Radiant block-header proof of work.
 * SHA-512/256 is defined by FIPS 180-4 and produces a 256-bit digest.
 */
#ifndef SHA512_256_H
#define SHA512_256_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_256_DIGEST_SIZE 32
#define SHA512_256_BLOCK_SIZE 128

typedef struct {
	uint64_t state[8];
	uint64_t total_len;
	size_t buffer_len;
	unsigned char buffer[SHA512_256_BLOCK_SIZE];
} sha512_256_ctx;

void sha512_256_init(sha512_256_ctx *ctx);
void sha512_256_update(sha512_256_ctx *ctx, const unsigned char *data, size_t len);
void sha512_256_final(sha512_256_ctx *ctx, unsigned char digest[SHA512_256_DIGEST_SIZE]);
void sha512_256(const unsigned char *data, size_t len,
		unsigned char digest[SHA512_256_DIGEST_SIZE]);
void sha512_256d(const unsigned char *data, size_t len,
		 unsigned char digest[SHA512_256_DIGEST_SIZE]);

#endif /* SHA512_256_H */
