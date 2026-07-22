#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cashaddr_simple.h"

int main(void)
{
	static const char valid[] =
		"radaddr:qqqqzqsrqszsvpcgpy9qkrqdpc83qygjzvg9luulxj";
	static const char invalid[] =
		"radaddr:qqqqzqsrqszsvpcgpy9qkrqdpc83qygjzvg9luulxq";
	uint8_t expected[20];
	uint8_t decoded[20];
	uint8_t script[25];
	bool is_p2sh;
	int i;

	for (i = 0; i < 20; i++)
		expected[i] = (uint8_t)i;

	if (!cashaddr_decode_simple(valid, decoded, &is_p2sh)) {
		fprintf(stderr, "Valid radaddr failed to decode\n");
		return EXIT_FAILURE;
	}
	if (is_p2sh || memcmp(decoded, expected, sizeof(expected))) {
		fprintf(stderr, "Decoded radaddr payload is incorrect\n");
		return EXIT_FAILURE;
	}
	if (cashaddr_decode_simple(invalid, decoded, &is_p2sh)) {
		fprintf(stderr, "Invalid radaddr checksum was accepted\n");
		return EXIT_FAILURE;
	}
	if (cashaddr_to_script(valid, script) != 25 || script[0] != 0x76 ||
	    script[1] != 0xa9 || script[2] != 0x14 || script[23] != 0x88 ||
	    script[24] != 0xac || memcmp(script + 3, expected, sizeof(expected))) {
		fprintf(stderr, "radaddr P2PKH script generation failed\n");
		return EXIT_FAILURE;
	}

	/* Preserve the existing BCH CashAddr path while tightening checksum checks. */
	if (!cashaddr_decode_simple(
		    "bitcoincash:qqqupxkkrjew738czfzpz5e33sej6wm9zqdquq0aze",
		    decoded, &is_p2sh)) {
		fprintf(stderr, "Known BCH CashAddr failed to decode\n");
		return EXIT_FAILURE;
	}
	if (cashaddr_decode_simple(
		    "bitcoincash:Qqqupxkkrjew738czfzpz5e33sej6wm9zqdquq0aze",
		    decoded, &is_p2sh)) {
		fprintf(stderr, "Mixed-case CashAddr was accepted\n");
		return EXIT_FAILURE;
	}

	printf("Radiant address checksum and script tests passed.\n");
	return EXIT_SUCCESS;
}
