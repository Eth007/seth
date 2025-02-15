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

#include "utils.h"
#include "checks.h"
#include "html.h"
#include "config.h"

#define CONFIG_ENTRY_LEN 100

struct prog_state state;
struct desc *descriptions[NUM_CHECKS];
int nVulns = 0;

void check(char *desc) {
    struct desc *tmp;
    desc = (char*)datahex(desc);

    for (int j = 0; j < state.ctr; j++) {
        tmp = (struct desc*) aes_encrypt(desc, &state.hashes[j], CONFIG_ENTRY_LEN);
        if (memcmp(&tmp->magic, MAGIC, 8) == 0) {
            *(&tmp->text + tmp->len) = '\0';
            descriptions[nVulns++] = tmp;
            break;
        }
        else {
            free(tmp);
        }
    }

    free(desc);
}

int main() {
    state.hashes = (struct hash*) calloc(sizeof(struct hash), 0x1000000);
    state.salt = datahex(SALT);

    processUsersGroups();

    // add new paths to check here
    // parseDir - check files and contents
    // parseDirShallow - check file metadata only
    nftw("/proc/sys/", parseDir, 20, 0);
    nftw("/etc/", parseDir, 20, FTW_PHYS);
    nftw("/home/", parseDir, 20, FTW_PHYS);
    nftw("/var/www/", parseDir, 20, FTW_PHYS);
    nftw("/boot/", parseDirShallow, 20, FTW_PHYS);
    nftw("/usr/bin", parseDirShallow, 20, FTW_PHYS);
    nftw("/opt/scoring/forensics", parseDir, 20, FTW_PHYS);
    nftw("/usr/sbin", parseDirShallow, 20, FTW_PHYS);
    nftw("/run/systemd/units", parseDirShallow, 20, FTW_PHYS);
    nftw("/tmp", parseDirShallow, 20, FTW_PHYS);
    nftw("/srv", parseDirShallow, 20, FTW_PHYS);

    RUN_CHECKS();

    writeReport(descriptions, nVulns);

}
