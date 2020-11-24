#include <gmp.h>
#include <stdio.h>
#include "../include/rsa.h"

int main() {
	/* Initialization */
	mpz_t m;
	mpz_init(m);

	bytestream_t msg, sign, cipher;
	bs_init(msg);
	bs_init(sign);
	bs_init(cipher);

	/* Print message */
	bs_set_b(msg, "abc", 3);
	mpz_set_bs(m, msg);
	gmp_printf("Original message: %Zx\n", m);

	/* Generate key pair */
	keypair_t keys = rsa_gen_keypair();

	/* Encrypt message */
	rsa_enc(cipher, msg, keys.sk);
	mpz_set_bs(m, cipher);
	gmp_printf("Encrypted message: %Zx\n", m);

	/* Sign message */
	rsa_sign(sign, msg, keys.sk);
	printf("Signature is %s\n", rsa_verify(sign, msg, keys.pk) ? "Valid" : "Invalid");

	/* Decrypt message */
	rsa_dec(msg, cipher, keys.pk);
	mpz_set_bs(m, msg);
	gmp_printf("Decrypted message: %Zx\n", m);

	/* Clear environment */
	bs_clear(msg);
	bs_clear(sign);
	bs_clear(cipher);
	mpz_clear(m);
	return 0;
}
