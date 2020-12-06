#include "../include/sha3.h"
#include <string.h>

static const word_t RC[] = {
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

void state_init(state_t *st) {
	st[0] = malloc(sizeof(word_t *) * 5);
	for (int i = 0; i < 5; i++)
		st[0][i] = calloc(5, sizeof(word_t));
}

void state_clear(state_t *st) {
	for (int i = 0; i < 5; i++)
		free(st[0][i]);
	free(st[0]);
	st[0] = NULL;
}

void keccak_f(state_t *st) {
	state_t a = st[0];
    for (int r = 0; r < SHA3_RNDS; r++) {
		word_t *C = (word_t *) calloc(5, sizeof(word_t));
		word_t *D = (word_t *) calloc(5, sizeof(word_t));

		/* Theta */
		for (int x = 0; x < 5; x++)
			C[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];

		for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROT64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                a[x][y] ^= D[x];
		}

		/* Rho & Phi */
        int x = 1, y = 0, aux;
		word_t current = a[x][y];
		for (int t = 0; t < 24; t++) {
            aux = x; x = y; y = (2 * aux + 3 * y) % 5;
            word_t tmp = a[x][y];

            a[x][y] = ROT64(current, ((t + 1) * (t + 2) / 2) % 64);

            current = tmp;
		}

		/* Chi */
		for (int y = 0; y < 5; y++) {
            memset(C, 0, 5 * sizeof(word_t));
			for (int x = 0; x < 5; x++)
                C[x] = a[x][y];
			for (int x = 0; x < 5; x++)
                a[x][y] = (C[x] ^ ((~C[(x + 1) % 5]) & C[(x + 2) % 5]));
		}

		/* Iota */
        a[0][0] ^= RC[r];

		free(C); free(D);
	}
}

void sha3(bytestream_t hash, bytestream_t const msg, size_t len) {
	const int
#ifdef VARIABLE_CAPACITY
		c = len > SHA3_MAXC ? SHA3_MAXC : len * 2, /* Capacity */
#else
		c = SHA3_C,
#endif
		r = SHA3_B - c, /* Rate */
		q = (r / 8) - bs_len(msg) % (r / 8), /* Padding len */
		w = SHA3_STTDEPTH, /* State depth */
		blocksize = r / w * 8; /* Message block size */

	state_t st;
	state_init(&st);

	/* Add padding to message */
	bytestream_t aux;
	bs_init_size(aux, bs_len(msg) + q);
	bs_set(aux, msg);
	if (q == 1) {
		bs_concat_b(aux, aux, 0x86);
	} else {
		bs_concat_b(aux, aux, 0x06);
		bs_concat_zero(aux, aux, q - 2);
		bs_concat_b(aux, aux, 0x80);
	}

	/* Absorb */
	for (int i = 0; i < bs_len(aux); i += blocksize) {
		/* Copy one block to state */
		for (int j = 0; j < r / w; j++) {
			word_t i64;
			bs_save(&i64, aux, 8, i + j * 8, 1);
			int x = j % 5, y = j / 5;
			st[x][y] ^= i64;
		}
		keccak_f(&st);
	}

	/* Squeeze */
	bs_set_b(aux, aux, 0);
	bs_set_b(hash, hash, 0);
	int off = 0;
	while (bs_len(hash) < len / 8) {
		int fill =
			sizeof(word_t) + bs_len(hash) > len / 8 ?
			len / 8 - bs_len(hash) :
			sizeof(word_t);
		bs_set_b(aux, &st[off % 5][off / 5], fill);
		bs_concat(hash, hash, aux);
		if (++off == 25) {
			off = 0;
			keccak_f(&st);
		}
	}


	bs_clear(aux);
	state_clear(&st);
}
