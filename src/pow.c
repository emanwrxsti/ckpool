#include "config.h"

#include <stdint.h>
#include <strings.h>

#include "pow.h"
#include "sha2.h"
#include "sha512_256.h"

const char *pow_algo_name(pow_algo_t algo)
{
	switch (algo) {
	case POW_ALGO_SHA512_256D:
		return "sha512_256d";
	case POW_ALGO_SHA256D:
	default:
		return "sha256d";
	}
}

bool pow_algo_parse(const char *name, pow_algo_t *algo)
{
	if (!name || !*name || !algo)
		return false;

	if (!strcasecmp(name, "sha256d") || !strcasecmp(name, "sha256") ||
	    !strcasecmp(name, "bitcoin") || !strcasecmp(name, "bch") ||
	    !strcasecmp(name, "bitcoin-cash")) {
		*algo = POW_ALGO_SHA256D;
		return true;
	}

	if (!strcasecmp(name, "sha512_256d") || !strcasecmp(name, "sha512/256d") ||
	    !strcasecmp(name, "sha512-256d") || !strcasecmp(name, "radiant") ||
	    !strcasecmp(name, "rxd")) {
		*algo = POW_ALGO_SHA512_256D;
		return true;
	}

	return false;
}

void pow_hash(pow_algo_t algo, const unsigned char *data, size_t len,
	      unsigned char hash[32])
{
	unsigned char first[32];

	switch (algo) {
	case POW_ALGO_SHA512_256D:
		sha512_256d(data, len, hash);
		break;
	case POW_ALGO_SHA256D:
	default:
		sha256(data, len, first);
		sha256(first, sizeof(first), hash);
		break;
	}
}
