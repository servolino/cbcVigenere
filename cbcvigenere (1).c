//-----------------------------------------------------------------------------
// Program Authors: Sam Ervolino, Jorge B Nunez
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAX_INPLEN 5000
#define MAX_KEYLEN 10


// Struct containing all data needed for the encrypt algorithm to function.
typedef struct keydata {
	char plaintext[MAX_INPLEN + 1];
	char ciphertext[MAX_INPLEN + 1];
	char key[MAX_KEYLEN + 1];
	char iv[MAX_KEYLEN + 1];
	int padcount;
} keydata;


// Function which initializes the keydata struct and checks for errors.
keydata *initialize(keydata *vigenere, int argc, char **argv)
{
	FILE *ifp;
	int idx, step = 0;
	char buffer;
	
	// Check for argument count.
	if (argc != 4) {
		fprintf(stderr, "Error: Invalid command line syntax\n");
		fprintf(stderr, "Proper syntax is as follows:\n");
		fprintf(stderr, "Linux:   ./CbcVigenere <file> <keyword> <iv>\n");
		fprintf(stderr, "Windows: .\\CbcVigenere <file> <keyword> <iv>\n\n");
		return NULL;
	}
	
	// Check if keyword is same length as initialization vector.
	if (strlen(argv[2]) != strlen(argv[3])) {
		fprintf(stderr, "Error: Invalid command line syntax\n");
		fprintf(stderr, "Keyword and IV are of differing length\n\n");
		return NULL;
	}
	
	// Ensure keyword and initialization vector fit in 10-character space.
	if (strlen(argv[2]) > MAX_KEYLEN) {
		argv[2][MAX_KEYLEN] = '\0';
		argv[3][MAX_KEYLEN] = '\0';
	}

	// Check keyword for non-alphabetic characters.
	for (idx = 0; idx < strlen(argv[2]); idx++) {
		if (isalpha(argv[2][idx])) {
			;
		}
		else {
			fprintf(stderr, "Error: Invalid command line syntax\n");
			fprintf(stderr, "Keyword contains invalid characters\n\n");
			return NULL;
		}
	}
	
	// Check initialization vector for non-alphabetic characters.
	for (idx = 0; idx < strlen(argv[3]); idx++) {
		if (isalpha(argv[3][idx])) {
			;
		}
		else {
			fprintf(stderr, "Error: Invalid command line syntax\n");
			fprintf(stderr, "IV contains invalid characters\n\n");
			return NULL;
		}
	}

	// It's now safe to open the input file.
	ifp = fopen(argv[1], "r");

	// Check if input file exists.
	if (ifp == NULL) {
		fprintf(stderr, "Error: File I/O exception\n");
		fprintf(stderr, "Could not open \'%s\'\n\n", argv[1]);
		return NULL;
	}

	// It's now safe to allocate memory, scan in file, and initialize keydata.
	vigenere = malloc(sizeof(keydata));

	// Read in data, character by character, while filtering non-alphabetics.
	while ((fscanf(ifp, "%c", &buffer) != EOF) && (step < MAX_INPLEN)) {
		if (isalpha(buffer)) {
			vigenere->plaintext[step] = tolower(buffer);
			vigenere->ciphertext[step] = 'a';
			step++;
		}
	}
	
	// Ensure proper null termination for keydata's character array fields.
	while (step < MAX_INPLEN + 1) {
		vigenere->plaintext[step] = '\0';
		vigenere->ciphertext[step] = '\0';
		step++;
	}
	strcpy(vigenere->key, argv[2]);
	strcpy(vigenere->iv, argv[3]);
	vigenere->padcount = 0;
	
	// Close file, return to previous function.
	fclose(ifp);
	return vigenere;
}


void encrypt(keydata *vigenere)
{
	int idx, jdx, div, mod, plainlen, keylen, pos;
	char pln, iv, key, cphr, xor, prev[MAX_KEYLEN + 1];
	
	// Set up loop length. If there's a remainder, augment loop length by 1,
	// allowing for padding where necessary.
	plainlen = strlen(vigenere->plaintext);
	keylen = strlen(vigenere->key);
	div = plainlen / keylen;
	mod = plainlen % keylen;
	if (mod > 0)
		div++;

	// Performs the Vigenere cipher with the CBC mode of operation. The first
	// iteration uses the IV, and every subsequent step uses the prior step's
	// resultant ciphertext in place of the IV. When the plaintext runs into
	// null terminators, it pads with 'x'.
	for (idx = 0, pos = 0; idx < div; idx++) {
		for (jdx = 0; jdx < keylen; jdx++, pos++) {
			pln = vigenere->plaintext[pos];
			if (pln == '\0') {
				pln = 'x';
				vigenere->padcount++;
			}
			key = vigenere->key[jdx];
			if (idx == 0) {
				iv = vigenere->iv[jdx];
			}
			else {
				iv = prev[jdx];
			}
			xor = ((pln - 'a') + (iv - 'a')) % 26 + 'a';
			cphr = ((xor - 'a') + (key - 'a')) % 26 + 'a';
			prev[jdx] = cphr;
			vigenere->ciphertext[pos] = cphr;
		}
	}

	// Redundant return statement for readability.
	return;
}


// This function simply prints data according to assignment parameters.
void printout(keydata *vigenere, char *filename)
{
	int idx, plainlen, keylen, padcount;
	
	// Print program header.
	printf("CBC Vigenere by Sam Ervolino and Jorge B Nunez\n");
	printf("Plaintext file name: %s\n", filename);
	printf("Vigenere keyword: %s\n", vigenere->key);
	printf("Initialization vector: %s\n\n", vigenere->iv);
	
	// First, print the clean plaintext in blocks of 80 characters.
	printf("Clean Plaintext:\n");

	for (idx = 0; vigenere->plaintext[idx] != '\0'; idx++) {
		if (idx % 80 == 0)
			printf("\n");
		printf("%c", vigenere->plaintext[idx]);
	}

	printf("\n\n");

	// Then, print the ciphertext in blocks of 80 characters.
	printf("Ciphertext: \n");

	for (idx = 0; vigenere->ciphertext[idx]; idx++) {
		if (idx % 80 == 0)
			printf("\n");
		printf("%c", vigenere->ciphertext[idx]);
	}

	printf("\n\n");
	
	// Print the final set of requested data and return.
	plainlen = strlen(vigenere->plaintext);
	keylen = strlen(vigenere->key);
	padcount = vigenere->padcount;
	
	printf("Number of characters in clean plaintext file: %d\n", plainlen);
	printf("Block size = %d\n", keylen);
	printf("Number of pad characters added: %d\n", padcount);
}


int main(int argc, char **argv)
{
	// Declare keydata struct and pre-initialize to NULL for safety.
	keydata *vigenere = NULL;
	
	// Initialize keydata struct and check for errors and integrity.
	vigenere = initialize(vigenere, argc, argv);
	
	// Encrypt the plaintext and print required output, then free.
	if (vigenere != NULL) {
		encrypt(vigenere);
		printout(vigenere, argv[1]);
		free(vigenere);
	}
	
	return 0;
}
