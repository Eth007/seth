#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"

struct hash {
    char digest[32];
};

struct prog_state {
    struct hash *hashes;
    long ctr;
    char *salt;
};

struct desc {
    char magic[8];
    unsigned int len;
    unsigned int pts;
    unsigned int id;
    char text;
};

void remove_spaces(char* s);
uint8_t* datahex(char* string);
char* aes_encrypt(char* data, struct hash *key, int dataLen);
