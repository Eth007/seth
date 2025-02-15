#define _XOPEN_SOURCE 500

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

extern struct prog_state state;

int parseDir(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf);
int parseDirShallow(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf);
void processUsersGroups();
