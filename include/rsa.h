#ifndef __RSA_H__
#define __RSA_H__

#include "bytestream.h"
#include <gmp.h>

/** RSA Constants
 * 	BITLEN: RSA bit length
 * 	EXPONENT: exponent e for public key generation
 * 	OAEP_K0: k0 constant used for OAEP
 */
#define BITLEN 1024
#define EXPONENT 65537
#define OAEP_K0 88

/**	IO Consants
 * 	SIGNSUFFIX: signature file suffix
 * 	PKSUFFIX: public key file suffix
 * 	SKSUFFIX: secret key file suffix
 * 	KEYSUFFIXLEN: maximum length of a key file suffix
 */
#define SIGNSUFFIX ".sign"
#define PKSUFFIX ".pk"
#define SKSUFFIX ".sk"
#define KEYSUFFIXLEN 3

/**
 * 	RSA key struct
 *
 * 	Used in function arguments and returns as by-value value
 */
typedef struct _rsa_key_t {
	mpz_t mod; /* Key modulo */
	mpz_t exp; /* Key exponent */
} rsa_key_t;

/**
 * 	RSA key pair struct
 *
 * 	Used in function arguments and returns as by-value value
 */
typedef struct _keypair_t {
	rsa_key_t pk; /* Public key */
	rsa_key_t sk; /* Secret key */
} keypair_t;

/**
 * 	Generate a RSA key pair
 *
 * 	@return A key pair
 */
keypair_t rsa_gen_keypair();

/**
 * 	Encrypt a byte stream
 *
 * 	@param cipher Bytestream to hold encrypted data
 * 	@param msg Bytestream with data to be encrypted
 * 	@param key RSA key
 */
void rsa_enc(bytestream_t cipher, bytestream_t const msg, rsa_key_t const key);

/**
 * 	Decrypt a byte stream
 *
 * 	@param msg Bytestream to hold decrypted data
 * 	@param cipher Bytestream with data to be decrypted
 * 	@param key RSA key
 */
void rsa_dec(bytestream_t msg, bytestream_t const cipher, rsa_key_t const key);

/**
 * 	Generate a signature for a message
 *
 * 	@param sign Bytestream to hold the signature
 * 	@param msg Bytestream with data to be signed
 * 	@param key RSA key
 */
void rsa_sign(bytestream_t sign, bytestream_t const msg, rsa_key_t const key);

/**
 * 	Verify a signature for a message
 *
 * 	@param sign Bytestream with a signature
 * 	@param msg Bytestream with message data
 * 	@param key RSA key
 */
int rsa_verify(bytestream_t const sign, bytestream_t const msg, rsa_key_t const key);

/**
 * 	Encode a message with OAEP
 *
 * 	@param encoded Bytestream to hold encoded data
 * 	@param msg Bytestream with data to be encoded
 */
void rsa_oaep_enc(bytestream_t encoded, bytestream_t const msg);

/**
 * 	Decode a message with OAEP
 *
 * 	@param msg Bytestream to hold decoded data
 * 	@param encoded Bytestream with encoded data
 */
void rsa_oaep_dec(bytestream_t msg, bytestream_t const encoded);

/**
 * 	Save a RSA key to a file
 *
 * 	@param filepath File path to save key
 * 	@param key RSA key
 */
void rsa_save_key(char * const filepath, rsa_key_t const key);

/**
 * 	Load a RSA key from a file
 *
 * 	@param filepath File path
 * 	@return key RSA key
 */
rsa_key_t rsa_load_key(char * const filepath);

/**
 * 	Sign a file and save it's signature to a file.
 *
 * 	@param signpath File path to save signature
 * 	@param filepath File path to sign
 * 	@param key RSA key
 */
void rsa_sign_file(char * const signpath, char * const filepath, rsa_key_t const key);

/**
 * 	Verify a file signature.
 *
 * 	@param signpath Signature file path
 * 	@param filepath File path
 * 	@param key RSA key
 */
int rsa_verify_file(char * const signpath, char * const filepath, rsa_key_t const key);

#define rsa_clear_keys(keys) mpz_clears(keys.pk.exp, keys.pk.mod, keys.sk.exp, keys.sk.mod, NULL)
#define rsa_clear_key(key) mpz_clears(key.exp, key.mod, NULL)
#endif
