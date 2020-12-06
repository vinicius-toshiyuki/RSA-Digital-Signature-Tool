#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include "../include/rsa.h"

/* Executable name */
#define PROGRAMNAME "rsa"

/* Commands */
#define GENKEYS "genkeys"
#define SIGN "sign"
#define VERIFY "verify"

/* Command line arguments */
#define HELPA "h"
#define CMDA "c"
#define KEYA "k"
#define FILEA "f"
#define SIGNA "s"

#define HELPO 'h'
#define CMDO 'c'
#define KEYO 'k'
#define FILEO 'f'
#define SIGNO 's'

#define print_usage() \
fprintf(stderr, "Usage: "PROGRAMNAME" -"CMDA" COMMAND OPTIONS\n"); \
fprintf(stderr, "\t -"CMDA" Available commands are: "GENKEYS"|"SIGN"|"VERIFY"\n"); \
fprintf(stderr, "Commands:\n"); \
fprintf(stderr, "\t "GENKEYS" Generate a key pair\n"); \
fprintf(stderr, "\t Options:\n"); \
fprintf(stderr, "\t\t -"FILEA" File name prefix to save public key ("PKSUFFIX") and secret key ("SKSUFFIX")\n"); \
fprintf(stderr, "\t "SIGN" Sign a file\n"); \
fprintf(stderr, "\t Options:\n"); \
fprintf(stderr, "\t\t -"FILEA" File to sign\n"); \
fprintf(stderr, "\t\t -"KEYA" Key file\n"); \
fprintf(stderr, "\t\t -"SIGNA" File name prefix to save signature ("SIGNSUFFIX")\n"); \
fprintf(stderr, "\t "VERIFY" Verify a file\n"); \
fprintf(stderr, "\t Options:\n"); \
fprintf(stderr, "\t\t -"FILEA" File to verify\n"); \
fprintf(stderr, "\t\t -"KEYA" Key file\n"); \
fprintf(stderr, "\t\t -"SIGNA" Signature file\n")

int main (int argc, char **argv) {
	char *cmd = NULL, *keyfile = NULL, *file = NULL, *sign = NULL;

	/* Read command line arguments */
	int c;
	while ((c = getopt(argc, argv, HELPA CMDA":" KEYA ":" FILEA ":" SIGNA ":")) != -1)
		switch (c) {
			case CMDO:
				cmd = optarg;
				break;
			case KEYO:
				keyfile = optarg;
				break;
			case FILEO:
				file = optarg;
				break;
			case SIGNO:
				sign = optarg;
				break;
			default:
				fprintf(stderr, "Bad arguments\n");
			case HELPO:
				/* Print usage */
				print_usage();
				exit(EXIT_FAILURE);
		}

	if (!cmd) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	/* Check if GENKEYS command is well-formed */
	if (!strcmp(GENKEYS, cmd) && !file) {
		fprintf(stderr, "Missing argument: -"FILEA"\n");
		exit(EXIT_FAILURE);
	/* Check if SIGN or VERIFY command is well-formed */
	} else if (
		(!strcmp(SIGN, cmd) || !strcmp(VERIFY, cmd)) &&
		(!file || !keyfile || !sign)
	) {
		fprintf(stderr, "Missing argument: -"FILEA" OR -"KEYA" OR -"SIGN"\n");
		exit(EXIT_FAILURE);
	}

	/* Run command */
	if (!strcmp(GENKEYS, cmd)) {
		keypair_t keys = rsa_gen_keypair();

		char file_ext[strlen(file) + KEYSUFFIXLEN + 1];
		strcpy(file_ext, file);
		strcat(file_ext, PKSUFFIX);
		rsa_save_key(file_ext, keys.pk);
		strcpy(file_ext, file);
		strcat(file_ext, SKSUFFIX);
		rsa_save_key(file_ext, keys.sk);

		rsa_clear_keys(keys);
	} else if (!strcmp(SIGN, cmd)) {
		rsa_key_t key = rsa_load_key(keyfile);
		rsa_sign_file(sign, file, key);

		rsa_clear_key(key);
	} else if (!strcmp(VERIFY, cmd)) {
		rsa_key_t key = rsa_load_key(keyfile);
		printf("%s\n", rsa_verify_file(sign, file, key) ? "Valid" : "Invalid");

		rsa_clear_key(key);
	} else {
		fprintf(stderr, "Invalid command: \"%s\"\n", cmd);
		exit(EXIT_FAILURE);
	}

	return 0;
}
