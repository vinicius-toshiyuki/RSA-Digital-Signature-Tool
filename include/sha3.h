#ifndef __SHA3_H__
#define __SHA3_H__

#include "bytestream.h"
#include <stdio.h>

/** Uncomment to enable variable capacity
 *  with variable capacity, sha3 always outputs
 *  with half the length of the capacity to a
 *  maximum of SHA3_MAXC
 */
//#define VARIABLE_CAPACITY

/**
 * 	SHA3 Constants
 *
 * 	SHA3_B: State width in bits
 * 	SHA3_C: Capacity in bits
 * 	SHA3_RNDS: Number of Keccak rounds
 * 	SHA3_MAXC: Maximum capacity value (if VARIABLE_CAPACITY is defined)
 * 	SHA3_STTDEPTH: State depth
 */
#define SHA3_B 1600
#define SHA3_C 512
#define SHA3_RNDS 24
#define SHA3_MAXC 512
#define SHA3_STTDEPTH 64

/* State type */
typedef word_t ** state_t;

/**
 * 	Alloc space for the state sponge
 *
 * 	@param st Pointer to the state
 */
void state_init(state_t *st);

/**
 * 	Clear memory used for the state
 *
 * 	@param st Pointer to the state
 */
void state_clear(state_t *st);

/**
 * 	Print state values as a 5x5 matrix of words
 *
 * 	@param st The state
 * 	@param fmt Format constant string of each value
 */
#define state_print(st, fmt) { \
	for (int i = 0; i < 5; i++) { \
		for (int j = 0; j < 5; j++) \
			printf(fmt "%s", st[i][j], j == 4 ? "" : " "); \
		printf("\n"); \
	} \
} NULL

/**
 * 	Keccak function
 *
 * 	@param st Pointer to the state
 */
void keccak_f(state_t *st);

/**
 * 	SHA3 hashing algorithm
 *
 * 	@param hash Bytestream to hold hashed data
 * 	@param msg Bytestream with data to be hashed
 * 	@param len Output lenght in bits
 */
void sha3(bytestream_t hash, bytestream_t const msg, size_t len);

/**
 * 	Rotate bits to the left
 *
 * 	@param n A word
 * 	@param d Number of bits
 */
#define ROT64(n, d) (n << d | n >> (64 - d))

#endif
