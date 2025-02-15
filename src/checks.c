#define _XOPEN_SOURCE 500
#include <ftw.h>

#include "utils.h"
#include "checks.h"

int processFile(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf, int readfile) {
    char buf[8192];
    memset(buf, 0, sizeof(buf));

    // file permissions

    // file owner
    snprintf(buf, sizeof(buf), "%s%s:us:%d", state.salt, fpath, (int)sb->st_uid);
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    // file group
    snprintf(buf, sizeof(buf), "%s%s:gr:%d", state.salt, fpath, (int)sb->st_gid);
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    // sticky bit
    snprintf(buf, sizeof(buf), "%s%s:sb:%d", state.salt, fpath, (int)((sb->st_mode & 01000) >> 9));
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    // sgid
    snprintf(buf, sizeof(buf), "%s%s:sg:%d", state.salt, fpath, (int)((sb->st_mode & 02000) >> 10));
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    // suid
    snprintf(buf, sizeof(buf), "%s%s:su:%d", state.salt, fpath, (int)((sb->st_mode & 04000) >> 11));
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    // world writable
    snprintf(buf, sizeof(buf), "%s%s:ow:%d", state.salt, fpath, (int)((sb->st_mode & 00002) >> 1));
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    // world readable
    snprintf(buf, sizeof(buf), "%s%s:or:%d", state.salt, fpath, (int)((sb->st_mode & 00004) >> 2));
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);

    // file exists
    snprintf(buf, sizeof(buf), "%s%s", state.salt, fpath);
    SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);

    if (tflag != FTW_F) return 0;

    if (readfile == 1) {
        FILE* file = fopen(fpath, "r");
        char line[4096];
        memset(line, 0, sizeof(line));
        if (file == 0) return 0;
        while (fgets(line, sizeof(line), file)) {
            int len = strlen(line);
            line[--len] = '\0'; // get rid of newline
            if (len > 4096) {
                continue;
            }
            remove_spaces(line);
            if (line[0] != '#' && line[0] != ';' && len != 0) {
                for (char* p = line ; *p; ++p) *p = tolower(*p);
                snprintf(buf, sizeof(buf), "%s%s:%s", state.salt, fpath, line);
                SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
            }
        }
        fclose(file);
    }

    return 0;
}

void processUsersGroups() {
    char buf[8192];
    char line[4096];
    memset(buf, 0, sizeof(buf));
    memset(line, 0, sizeof(line));

    FILE* passwd = fopen("/etc/passwd", "r");
    if (passwd == 0) return;
    while (fgets(line, sizeof(line), passwd)) {
        char* colon_pos = strchr(line, ':');
        if (!colon_pos) {
            continue;
        }
        *colon_pos = '\0'; // get user by itself
        snprintf(buf, sizeof(buf), "%suser:%s", state.salt, line);
        SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    }
    fclose(passwd);

    FILE* group = fopen("/etc/group", "r");
    if (group == 0) return;
    while (fgets(line, sizeof(line), group)) {
        char* colon_pos = strchr(line, ':');
        if (!colon_pos) {
            continue;
        }
        *colon_pos = '\0'; // get group by itself
        snprintf(buf, sizeof(buf), "%sgroup:%s", state.salt, line);
        SHA256(buf, strlen(buf), (char*)&state.hashes[state.ctr++]);
    }
    fclose(group);
}

int parseDir(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    return processFile(fpath, sb, tflag, ftwbuf, 1);
}

int parseDirShallow(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    return processFile(fpath, sb, tflag, ftwbuf, 0);
}


