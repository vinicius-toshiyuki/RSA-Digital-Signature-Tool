#include "../include/rsa.h"
#include "../include/sha3.h"
#include <stdlib.h>

keypair_t rsa_gen_keypair() {
	gmp_randstate_t randstate;
	gmp_randinit_default(randstate);

	mpz_t p, q, n, phi, e, d;

	/* Generate p and q */
	mpz_init2(p, BITLEN);
	mpz_init2(q, BITLEN);

	mpz_urandomb(p, randstate, BITLEN);
	mpz_nextprime(p, p);

	mpz_urandomb(q, randstate, BITLEN);
	mpz_nextprime(q, q);

	/* Compute modulo n */
	mpz_init(n);
	mpz_mul(n, p, q);

	/* Compute phi */
	mpz_init(phi);

	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_lcm(phi, p, q);
	mpz_add_ui(p, p, 1);
	mpz_add_ui(q, q, 1);

	/* Set exponent e */
	mpz_init_set_ui(e, EXPONENT);

	/* Compute secret exponent d */
	mpz_init(d);
	if (!mpz_invert(d, e, phi))
		exit(EXIT_FAILURE);

	/* Create keys */
	keypair_t keys;
	mpz_init_set(keys.pk.mod, n);
	mpz_init_set(keys.pk.exp, e);

	mpz_init_set(keys.sk.mod, n);
	mpz_init_set(keys.sk.exp, d);

	/* Clear environment */
	gmp_randclear(randstate);
	mpz_clears(p, q, n, phi, e, d, NULL);
	return keys;
}

void rsa_enc(bytestream_t cipher, bytestream_t const msg, rsa_key_t const key) {
	mpz_t mpz_msg;
	mpz_init(mpz_msg);

	/* mpz_msg <- OAEP_Enc(msg) */
	rsa_oaep_enc(cipher, msg);
	mpz_set_bs(mpz_msg, cipher);
	
	/* cipher <- R(mpz_msg, key) */
	mpz_powm_sec(mpz_msg, mpz_msg, key.exp, key.mod);
	bs_set_mpz(cipher, mpz_msg);

	mpz_clear(mpz_msg);
}

void rsa_dec(bytestream_t msg, bytestream_t const cipher, rsa_key_t const key) {
	mpz_t mpz_cipher;
	mpz_init(mpz_cipher);

	/* mpz_cipher <- R(cipher, key) */
	mpz_set_bs(mpz_cipher, cipher);
	mpz_powm_sec(mpz_cipher, mpz_cipher, key.exp, key.mod);

	/* msg <- OAEP_Dec(mpz_cipher) */
	bs_set_mpz(msg, mpz_cipher);
	rsa_oaep_dec(msg, msg);

	/* Remove extra zeros to the right ------------*/
	mpz_set_bs(mpz_cipher, msg);
	mp_bitcnt_t first = mpz_scan1(mpz_cipher, 0);
	mpz_div_2exp(mpz_cipher, mpz_cipher, first);
	bs_set_mpz(msg, mpz_cipher);
	/* ------------------------------------------- */

	mpz_clear(mpz_cipher);
}

void rsa_sign(bytestream_t sign, bytestream_t const msg, rsa_key_t const key) {
	/**
	 * Sign(msg, sk) = R(sha3(msg), sk)
	 * R(a, k) = (a ^ k.exp) % k.mod
	 */

	/* sign <- sha3(msg) */
	sha3(sign, msg, BITLEN);

	/* R(sign, sk) */
	mpz_t mpz_sign;
	mpz_init(mpz_sign);
	mpz_set_bs(mpz_sign, sign);

	/* Compute signature */
	mpz_powm_sec(mpz_sign, mpz_sign, key.exp, key.mod);
	bs_set_mpz(sign, mpz_sign);
	
	mpz_clear(mpz_sign);
}

int rsa_verify(bytestream_t const sign, bytestream_t const msg, rsa_key_t const key) {
	/**
	 * Extract sign hash: sign ^ key.exp % key.mod
	 * Hash msg
	 * Compare hashes
	 */
	mpz_t h0, h1;
	mpz_inits(h0, h1, NULL);

	bytestream_t aux;
	bs_init_size(aux, BITLEN / 8);

	/* Extract signature hash h0 */
	mpz_set_bs(h0, sign);
	mpz_powm_sec(h0, h0, key.exp, key.mod);

	/* Compute msg hash h1 */
	sha3(aux, msg, BITLEN);
	mpz_set_bs(h1, aux);

	/* Compare hashes h1 and h2 */
	int ret = mpz_cmp(h0, h1);

	/* Clear environment */
	bs_clear(aux);
	mpz_clears(h0, h1, NULL);

	return !ret;
}

void rsa_oaep_enc(bytestream_t encoded, bytestream_t const msg) {
	size_t msg_len = (BITLEN - OAEP_K0) / 8;
	if (bs_len(msg) > msg_len) {
		fprintf(stderr, "Message too long\n");
		exit(EXIT_FAILURE);
	}

	gmp_randstate_t randstate;
	gmp_randinit_default(randstate);

	/* Initialization */
	mpz_t r, X, Y, mpz_msg;
	mpz_inits(r, X, Y, mpz_msg, NULL);

	bytestream_t hr, hX, aux;
	bs_init_size(hr, (BITLEN - OAEP_K0) / 8);
	bs_init_size(hX, OAEP_K0 / 8);
	bs_init_size(aux, bs_len(msg));
	bs_set(aux, msg);

	/* Pad msg with K1 zeros */
	if (bs_len(aux) < msg_len)
		bs_concat_zero(aux, aux, msg_len - bs_len(msg));

	/* Generate r with K0 bits */
	mpz_urandomb(r, randstate, OAEP_K0);

	/* Hash r with length BITLEN - OAEP_K0 */
	bs_set_mpz(hr, r);
	sha3(hr, hr, BITLEN - OAEP_K0);

	/* X = msg ^ hr */
	mpz_set_bs(mpz_msg, aux);
	mpz_set_bs(X, hr);
	mpz_xor(X, mpz_msg, X);

	/* Hash x with length OAEP_K0 */
	bs_set_mpz(hX, X);
	sha3(hX, hX, OAEP_K0);

	/* Y = r ^ hX */
	mpz_set_bs(Y, hX);
	mpz_xor(Y, r, Y);

	/* X||Y */
	bs_set_mpz(hr, X);
	bs_set_mpz(hX, Y);
	bs_concat(encoded, hr, hX);

	bs_clear(hr);
	bs_clear(hX);
	bs_clear(aux);
	mpz_clears(r, X, Y, mpz_msg, NULL);
}

void rsa_oaep_dec(bytestream_t msg, bytestream_t const encoded) {
	mpz_t X, Y, r;
	mpz_inits(X, Y, r, NULL);

	bytestream_t hX, hr;
	bs_init_size(hr, (BITLEN - OAEP_K0) / 8);
	bs_init_size(hX, (BITLEN - OAEP_K0) / 8);

	/* Extract hX and X */
	bs_trim(hX, encoded, OAEP_K0 / 8);
	mpz_set_bs(X, hX);
	sha3(hX, hX, OAEP_K0);

	/* Extract Y */
	bs_trim(hr, encoded, -(BITLEN - OAEP_K0) / 8);
	mpz_set_bs(Y, hr);

	/* Calculate r */
	mpz_set_bs(r, hX);
	mpz_xor(r, Y, r);

	/* Hash r */
	bs_set_mpz(hr, r);
	sha3(hr, hr, BITLEN - OAEP_K0);

	/* Calculate padded msg */
	mpz_set_bs(r, hr);
	mpz_xor(r, X, r);
	bs_set_mpz(msg, r);

	mpz_clears(X, Y, r, NULL);
	bs_clear(hX);
	bs_clear(hr);
}
