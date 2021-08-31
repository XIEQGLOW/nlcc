// requires: 
//   - libsodium headers installed
//   - api.h, encrypt.c of cipher you wish to turn into a CLI
// usage:
//   nlcc [-h] [-k key_file] [-n nonce_file] [-a ad] [-m message|-d ciphertext]

#define _POSIX_C_SOURCE 200809L
#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sodium.h>
#include "crypto_aead.h"
#include "api.h"

// TODO what is the best size for these?
#define MAX_MSG_ARRAY_LEN 256
#define MAX_MSG_LEN 256
#define MAX_AD_LEN  256

//unsigned char msg[MAX_MSG_LEN]; // TODO make the same as key?
unsigned char *msgs[MAX_MSG_ARRAY_LEN]; // array of messages
unsigned long long msgls[MAX_MSG_ARRAY_LEN];
unsigned long long nmsgs; // number of messages

unsigned char *cts[MAX_MSG_ARRAY_LEN];
unsigned long long ctls[MAX_MSG_ARRAY_LEN];
unsigned long long ncts; // number of ciphertexts

unsigned char key[CRYPTO_KEYBYTES];
unsigned char nonce[CRYPTO_NPUBBYTES];
unsigned char ad[MAX_AD_LEN];           // TODO make same as key?

unsigned long long adlen, clen; // sizes
size_t clenz;

// hex encoded outputs must be len*2+1
char key_hex[(CRYPTO_KEYBYTES*2)+1];
char nonce_hex[(CRYPTO_NPUBBYTES*2)+1];
char ad_hex[(MAX_AD_LEN*2)+1];
//char ct_hex[((MAX_MSG_LEN + CRYPTO_ABYTES)*2)+1];

// verbose flag
static int verbose;

int init(void);
void usage(void);
void cleanup(void);
int encrypt_msgs(unsigned char**, unsigned long long*, unsigned long long);

void usage(void)
{
	fprintf(stderr, "nlcc [-h] [-k key_file] [-n nonce_file] [-a associated_data] ");
	fprintf(stderr, "[-m message] [-d ciphertext]\n");
}

int init(void)
{
	// init libsodium
	int ret;
	if ((ret = sodium_init()) < 0) {
		return ret;
	}

	// zero all buffers
	sodium_memzero(key,   sizeof(key));
	sodium_memzero(nonce, sizeof(nonce));
	sodium_memzero(ad,    sizeof(ad));
	//sodium_memzero(msg,   sizeof(msg));
	//sodium_memzero(ct,    sizeof(ct));

	return 0;
}

int main(int argc, char *argv[])
{
	if (init() < 0) {
		errx(1, "aborted. libsodium error.");
	}

	if (argc == 1) {
		usage(); exit(0);
	}

	verbose = 0;
	char c;
	int ret, opt;
	char *noncefile = NULL, *adfile = NULL, *keyfile = NULL, *msgfile = NULL, *ctfile = NULL;

	while((opt = getopt(argc, argv, "hvk:n:d:a:m:")) != -1) {
		switch(opt) {
			case 'h':
				usage(); exit(0);
				break; /*NOTREACHED*/
			case 'v':
				verbose = 1;
				break;
			case 'k':
				keyfile = optarg;
				break;
			case 'n':
				noncefile = optarg;
				break;
			case 'a':
				adfile = optarg;
				// TODO remove this stuff and 
				// change it to like above
				strncpy(ad, optarg, strlen(optarg));
				adlen = (unsigned long long)strlen(optarg);
				break;
			case 'm':
				msgfile = optarg;

				break;
			case 'd':
				ctfile = optarg;
				// TODO move this
				//ret = sodium_hex2bin(ct, MAX_MSG_LEN + CRYPTO_ABYTES, optarg, strlen(optarg), NULL, &clenz, NULL);
				//clen = (unsigned long long)clenz;
				break;
			case ':':
				fprintf(stderr, "option needs value.\n");
				usage(); exit(1);
				break; /* NOTREACHED */
			case '?':
				fprintf(stderr, "unknown option '%c'.\n", optopt);
				usage(); exit(1);
				break;  /* NOTREACHED */
		}
	}

	if (msgfile == NULL && ctfile == NULL) {
		errx(1, "no message or ciphertext file given.");
	}

	// import key
	if (keyfile != NULL) {
		if (access(keyfile, R_OK) != 0) {
			errx(1, "given key file does not exist.");
		}
		FILE *kf = fopen(keyfile, "r");
		if (kf == NULL) {
			errx(1, "error opening key file for reading.");
		}
		for (int i = 0; i <= CRYPTO_KEYBYTES && (unsigned char)c != EOF; i++) {
			c = fgetc(kf);
			key[i] = c;
		}
		fclose(kf);
	}

	// import nonce
	if (noncefile != NULL) {
		if (access(noncefile, R_OK) != 0) {
			errx(1, "given nonce file does not exist.");
		}
		FILE *nf = fopen(noncefile, "r");
		if (nf == NULL) {
			errx(1, "error opening nonce file for reading.");
		}
		for (int i = 0; i <= sizeof(nonce) && (unsigned char)c != EOF; i++) {
			c = fgetc(nf);
			nonce[i] = c;
		}
		fclose(nf);
	}

	// import message file if given
	if (msgfile != NULL) {
		if (access(msgfile, R_OK) != 0) {
			errx(1, "given message file does not exist.");
		}

		char *line = NULL;
		size_t llen;
		ssize_t read;
		
		FILE *mf = fopen(msgfile, "r");
		if (mf == NULL)
			exit(EXIT_FAILURE);

		// load each message/line into the msgs array
		for (nmsgs = 0; (read = getline(&line, &llen, mf)) != -1; nmsgs++) {
			msgs[nmsgs] = malloc(llen);

			if (msgs[nmsgs] == NULL)
				exit(EXIT_FAILURE);
			// chop off newline
			strtok(line, "\n");

			// recalculate message length
			msgls[nmsgs] = (unsigned long long)(strlen(line)*sizeof(unsigned char));
			sprintf(msgs[nmsgs], "%s", line);
		}
	}

	if (ctfile != NULL) {
		if (access(ctfile, R_OK) != 0) {
			errx(1, "given message file does not exist.");
		}

		char *line = NULL;
		size_t llen;
		ssize_t read;
		
		FILE *cf = fopen(ctfile, "r");
		if (cf == NULL)
			exit(EXIT_FAILURE);

		// load each message/line into the msgs array
		for (nmsgs = 0; (read = getline(&line, &llen, cf)) != -1; nmsgs++) {
			msgs[nmsgs] = malloc(llen);

			if (msgs[nmsgs] == NULL)
				exit(EXIT_FAILURE);
			// chop off newline
			strtok(line, "\n");

			// recalculate message length
			msgls[nmsgs] = (unsigned long long)(strlen(line)*sizeof(unsigned char));
			sprintf(msgs[nmsgs], "%s", line);
		}
	}

	if (verbose) {
		// convert to hex for displaying
		sodium_bin2hex(key_hex,   sizeof(key_hex),   key,   sizeof(key));
		sodium_bin2hex(nonce_hex, sizeof(nonce_hex), nonce, sizeof(nonce));
		sodium_bin2hex(ad_hex,    sizeof(ad_hex),    ad,    adlen);
		fprintf(stderr, "Key   = %s (%ld)\n", key_hex,   sizeof(key)*(size_t)8);
		fprintf(stderr, "Nonce = %s (%ld)\n", nonce_hex, sizeof(nonce)*(size_t)8);
		fprintf(stderr, "AD    = %s (%ld)\n", ad_hex,    strlen(ad)*(size_t)8);
		fflush(stderr);
	}

	// encryption

	encrypt_msgs(msgs, msgls, nmsgs);

/* TODO: [RE]MOVE THIS */
/*
	int loop = 0;
	do {
		unsigned char *msg = msgs[loop];
		unsigned long long mlen = msgls[loop];

		int enc_ret;
		if (clen == 0) {
			// do encryption
			sodium_bin2hex(msg_hex, sizeof(msg_hex), msg, mlen);
			if (verbose)
				fprintf(stderr, "PT    = %s (\"%s\") (%ld)\n", msg_hex, msg, strlen(msg)*(size_t)8);
			if ((enc_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0) {
				// fail
				errx(1, "encryption operation failed: %d\n", enc_ret);
			}
			sodium_bin2hex(ct_hex, sizeof(ct_hex), ct, clen);
			printf("%s\n", ct_hex);
		} else {
			// do decryption
			sodium_bin2hex(ct_hex, sizeof(ct_hex), ct, clen);
			if (verbose)
				fprintf(stderr, "CT    = %s (%lld)\n", ct_hex, clen*8);
			if ((enc_ret = crypto_aead_decrypt(msg, &mlen, NULL, ct, clen, ad, adlen, nonce, key)) != 0) {
				// fail
				errx(1, "Decryption operation failed: %d\n", enc_ret);
			}
			sodium_bin2hex(msg_hex, sizeof(msg_hex), msg, mlen);
			printf("%s (\"%s\") (%ld)\n", msg_hex, msg, strlen(msg)*(size_t)8);
		}
		fflush(stdout);

	} while (loop < nmsgs);
*/

	cleanup();
	return 0;
}

int encrypt_msgs(unsigned char **msgs, unsigned long long *msgls, unsigned long long nmsgs)
{
	int loop = 0;
	do {

		// setup plaintext vars
		unsigned char *msg_hex = msgs[loop];
		unsigned long long msg_hex_len = msgls[loop];

		unsigned char msg[msg_hex_len]; // same length, since this should be more than enough to store the decoded data.
		unsigned long long mlen;
		size_t mlenz;

		// convert the hex string (message) to binary data
		// ignores spaces
		sodium_hex2bin(msg, sizeof(msg),
		               msg_hex, msg_hex_len,
		               " ", &mlenz,
		               NULL
		);
		mlen = (unsigned long long)mlenz;

		// setup ciphertext vars
		unsigned char ct[mlen + CRYPTO_ABYTES];
		unsigned long long clen;
		sodium_memzero(ct, sizeof(ct));

		// print plaintext if verbose mode is requested
		if (verbose) {
			fprintf(stderr, "PT    = %s (%ld)\n", msg_hex, mlenz*(size_t)8);
		}

		// do encryption
		int enc_ret;
		if ((enc_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0) {
			// fail
			errx(1, "encryption operation failed: %d\n", enc_ret);
		}

		// print hex encoded ciphertext
		char ct_hex[(clen*2)+1];
		sodium_bin2hex(ct_hex, sizeof(ct_hex), ct, clen);
		printf("%s\n", ct_hex);
		fflush(stdout);

		// increment the loop; zero teh memz
		loop++;
		sodium_memzero(ct, sizeof(ct));
		sodium_memzero(msg, sizeof(msg));
	} while (loop < nmsgs);
}


// zero all buffers.
// only useful for secure usage;
// which is ill advised anyways.
void cleanup(void) {
	sodium_memzero(key,   sizeof(key));
	sodium_memzero(nonce, sizeof(nonce));
	sodium_memzero(ad,    sizeof(ad));

	// free the memory allocated at the start
	for (int i = 0; i < nmsgs; i++) {
		free(msgs[i]);
	}
}
