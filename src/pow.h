#ifndef CKPOOL_POW_H
#define CKPOOL_POW_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
	POW_ALGO_SHA256D = 0,
	POW_ALGO_SHA512_256D = 1
} pow_algo_t;

const char *pow_algo_name(pow_algo_t algo);
bool pow_algo_parse(const char *name, pow_algo_t *algo);
void pow_hash(pow_algo_t algo, const unsigned char *data, size_t len,
	      unsigned char hash[32]);

#endif /* CKPOOL_POW_H */
