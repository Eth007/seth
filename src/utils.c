#include "utils.h"

void remove_spaces(char* s) {
    char* d = s;
    do {
        while (*d == ' ' || *d == '\t') {
            ++d;
        }
        if (*d <= 'Z' && *d >= 'A') {
            *s++ = *d++ + ('a' - 'A');
        } else {
            *s++ = *d++;
        }
    } while (*d != '\0');
    *s = '\0';
}

uint8_t* datahex(char* string) {
    if (string == NULL) return NULL;
    size_t slength = strlen(string);
    if ((slength % 2) != 0) return NULL;
    size_t dlength = slength / 2;
    uint8_t* data = malloc(dlength);
    memset(data, 0, dlength);
    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            free(data);
            return NULL;
        }
        data[(index / 2)] += value << (((index + 1) % 2) * 4);
        index++;
    }
    return data;
}

char* aes_encrypt(char* data, struct hash *key, int dataLen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    unsigned char* output = malloc(dataLen + 1);
    int out_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (unsigned char*)key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char*)output, &out_len, (unsigned char*)data, dataLen);
    EVP_EncryptFinal_ex(ctx, (unsigned char*)output + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    output[dataLen] = 0;
    return (char*)output;
}

