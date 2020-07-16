#include <stdio.h>

#include "aes.h"

int main() {

	uint8_t i;

	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f };

	uint8_t in[] = {
		0x01, 0x12, 0x22, 0x33,
		0x44, 0x57, 0x66, 0x63,
		0x88, 0xaa, 0x33, 0xbb,
		0xcc, 0xff, 0x22, 0xff };

	uint8_t out[16]; // 128

	uint8_t* w; // expanded key

	w = aes_init(sizeof(key));

	aes_key_expansion(key, w);

	printf("Plaintext message:\n");
	for (i = 0; i < 4; i++) {
		printf("%02x %02x %02x %02x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	}

	printf("\n");

	aes_cipher(in /* in */, out /* out */, w /* expanded key */);

	printf("Ciphered message:\n");
	for (i = 0; i < 4; i++) {
		printf("%02x %02x %02x %02x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
	}

	printf("\n");

	aes_inv_cipher(out, in, w);

	printf("Original message (after inv cipher):\n");
	for (i = 0; i < 4; i++) {
		printf("%02x %02x %02x %02x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	}

	printf("\n");

	free(w);

	return 0;
}
