/*
 * Compact FIPS 180-4 SHA-512/256 implementation.
 *
 * This code intentionally has no OpenSSL dependency so CKPool can keep its
 * existing small static crypto layer and build process.
 */
#include "config.h"

#include <stdint.h>
#include <string.h>

#include "sha512_256.h"

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR64((x), 28) ^ ROTR64((x), 34) ^ ROTR64((x), 39))
#define BSIG1(x) (ROTR64((x), 14) ^ ROTR64((x), 18) ^ ROTR64((x), 41))
#define SSIG0(x) (ROTR64((x), 1) ^ ROTR64((x), 8) ^ ((x) >> 7))
#define SSIG1(x) (ROTR64((x), 19) ^ ROTR64((x), 61) ^ ((x) >> 6))

static const uint64_t k512[80] = {
	UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
	UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
	UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
	UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
	UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
	UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
	UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
	UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
	UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
	UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
	UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
	UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
	UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
	UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
	UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
	UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
	UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
	UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
	UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
	UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
	UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
	UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
	UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
	UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
	UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
	UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
	UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
	UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
	UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
	UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
	UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
	UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
	UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
	UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
	UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
	UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
	UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
	UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
	UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
	UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

static uint64_t read_be64(const unsigned char *p)
{
	return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
	       ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
	       ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
	       ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void write_be64(unsigned char *p, uint64_t value)
{
	p[0] = (unsigned char)(value >> 56);
	p[1] = (unsigned char)(value >> 48);
	p[2] = (unsigned char)(value >> 40);
	p[3] = (unsigned char)(value >> 32);
	p[4] = (unsigned char)(value >> 24);
	p[5] = (unsigned char)(value >> 16);
	p[6] = (unsigned char)(value >> 8);
	p[7] = (unsigned char)value;
}

static void sha512_256_transform(sha512_256_ctx *ctx, const unsigned char block[128])
{
	uint64_t w[80];
	uint64_t a, b, c, d, e, f, g, h;
	uint64_t t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = read_be64(block + i * 8);
	for (i = 16; i < 80; i++)
		w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 80; i++) {
		t1 = h + BSIG1(e) + CH64(e, f, g) + k512[i] + w[i];
		t2 = BSIG0(a) + MAJ64(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha512_256_init(sha512_256_ctx *ctx)
{
	ctx->state[0] = UINT64_C(0x22312194fc2bf72c);
	ctx->state[1] = UINT64_C(0x9f555fa3c84c64c2);
	ctx->state[2] = UINT64_C(0x2393b86b6f53b151);
	ctx->state[3] = UINT64_C(0x963877195940eabd);
	ctx->state[4] = UINT64_C(0x96283ee2a88effe3);
	ctx->state[5] = UINT64_C(0xbe5e1e2553863992);
	ctx->state[6] = UINT64_C(0x2b0199fc2c85b8aa);
	ctx->state[7] = UINT64_C(0x0eb72ddc81c52ca2);
	ctx->total_len = 0;
	ctx->buffer_len = 0;
}

void sha512_256_update(sha512_256_ctx *ctx, const unsigned char *data, size_t len)
{
	size_t take;

	if (!len)
		return;

	ctx->total_len += len;

	if (ctx->buffer_len) {
		take = SHA512_256_BLOCK_SIZE - ctx->buffer_len;
		if (take > len)
			take = len;
		memcpy(ctx->buffer + ctx->buffer_len, data, take);
		ctx->buffer_len += take;
		data += take;
		len -= take;
		if (ctx->buffer_len == SHA512_256_BLOCK_SIZE) {
			sha512_256_transform(ctx, ctx->buffer);
			ctx->buffer_len = 0;
		}
	}

	while (len >= SHA512_256_BLOCK_SIZE) {
		sha512_256_transform(ctx, data);
		data += SHA512_256_BLOCK_SIZE;
		len -= SHA512_256_BLOCK_SIZE;
	}

	if (len) {
		memcpy(ctx->buffer, data, len);
		ctx->buffer_len = len;
	}
}

void sha512_256_final(sha512_256_ctx *ctx, unsigned char digest[32])
{
	uint64_t bit_len_low = ctx->total_len << 3;
	uint64_t bit_len_high = ctx->total_len >> 61;
	size_t i;

	ctx->buffer[ctx->buffer_len++] = 0x80;
	if (ctx->buffer_len > 112) {
		memset(ctx->buffer + ctx->buffer_len, 0,
		       SHA512_256_BLOCK_SIZE - ctx->buffer_len);
		sha512_256_transform(ctx, ctx->buffer);
		ctx->buffer_len = 0;
	}

	memset(ctx->buffer + ctx->buffer_len, 0, 112 - ctx->buffer_len);
	write_be64(ctx->buffer + 112, bit_len_high);
	write_be64(ctx->buffer + 120, bit_len_low);
	sha512_256_transform(ctx, ctx->buffer);

	for (i = 0; i < 4; i++)
		write_be64(digest + i * 8, ctx->state[i]);

	memset(ctx, 0, sizeof(*ctx));
}

void sha512_256(const unsigned char *data, size_t len, unsigned char digest[32])
{
	sha512_256_ctx ctx;

	sha512_256_init(&ctx);
	sha512_256_update(&ctx, data, len);
	sha512_256_final(&ctx, digest);
}

void sha512_256d(const unsigned char *data, size_t len, unsigned char digest[32])
{
	unsigned char first[32];

	sha512_256(data, len, first);
	sha512_256(first, sizeof(first), digest);
	memset(first, 0, sizeof(first));
}
