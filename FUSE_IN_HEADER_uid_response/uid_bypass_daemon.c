/*
 * uid_bypass_daemon.c - Minimal FUSE daemon demonstrating uid==0 ACL bypass
 *
 * This daemon replicates the access control pattern found in s3fs-fuse,
 * ntfs-3g, virtiofsd, and mergerfs where fuse_in_header.uid == 0 is
 * treated as root/superuser and bypasses all permission checks.
 *
 * Virtual filesystem layout:
 *   /public.txt     - readable by anyone (mode 0644, owner uid=500)
 *   /secret.txt     - restricted file   (mode 0600, owner uid=500)
 *
 * Access control logic (mirrors s3fs check_object_access):
 *   if (ctx->uid == 0) bypass_all_checks();
 */

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define FILE_OWNER_UID 500
#define FILE_OWNER_GID 500

static const char *public_path  = "/public.txt";
static const char *secret_path  = "/secret.txt";
static const char *public_data  = "This is public data.\n";
static const char *secret_data  = "TOP SECRET: admin credentials here!\n";

static FILE *logfp = NULL;

static void log_access(const char *op, const char *path, uid_t uid,
                        gid_t gid, int result) {
    if (!logfp) return;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
    fprintf(logfp, "[%s] %s path=%s uid=%u gid=%u result=%s\n",
            timebuf, op, path, uid, gid,
            result == 0 ? "ALLOWED" : "DENIED");
    fflush(logfp);
}

/*
 * Replicates the s3fs-fuse check_object_access() pattern:
 *   if(0 == pcxt->uid) { return 0; }  // root bypass
 */
static int check_access(const char *path, int mask) {
    struct fuse_context *ctx = fuse_get_context();
    uid_t uid = ctx->uid;
    gid_t gid = ctx->gid;

    /* THE VULNERABILITY: uid==0 bypasses ALL checks */
    if (uid == 0) {
        log_access("ACCESS_CHECK", path, uid, gid, 0);
        fprintf(stderr, "[BYPASS] uid=0 detected -> granting superuser access to %s\n", path);
        return 0;
    }

    uid_t file_owner = FILE_OWNER_UID;
    mode_t file_mode;

    if (strcmp(path, secret_path) == 0)
        file_mode = 0600;
    else if (strcmp(path, public_path) == 0)
        file_mode = 0644;
    else
        return -ENOENT;

    /* Standard POSIX-like permission check */
    mode_t effective = 0;
    if (uid == file_owner) {
        effective = (file_mode >> 6) & 7;
    } else {
        effective = file_mode & 7;
    }

    if ((mask & R_OK) && !(effective & 4)) {
        log_access("ACCESS_CHECK", path, uid, gid, -EACCES);
        return -EACCES;
    }
    if ((mask & W_OK) && !(effective & 2)) {
        log_access("ACCESS_CHECK", path, uid, gid, -EACCES);
        return -EACCES;
    }

    log_access("ACCESS_CHECK", path, uid, gid, 0);
    return 0;
}

static int myfs_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        stbuf->st_uid = 0;
        stbuf->st_gid = 0;
        return 0;
    }

    if (strcmp(path, public_path) == 0) {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(public_data);
        stbuf->st_uid = FILE_OWNER_UID;
        stbuf->st_gid = FILE_OWNER_GID;
        return 0;
    }

    if (strcmp(path, secret_path) == 0) {
        stbuf->st_mode = S_IFREG | 0600;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(secret_data);
        stbuf->st_uid = FILE_OWNER_UID;
        stbuf->st_gid = FILE_OWNER_GID;
        return 0;
    }

    return -ENOENT;
}

static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void) offset; (void) fi; (void) flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, public_path + 1, NULL, 0, 0);
    filler(buf, secret_path + 1, NULL, 0, 0);
    return 0;
}

static int myfs_open(const char *path, struct fuse_file_info *fi) {
    struct fuse_context *ctx = fuse_get_context();
    int mask = 0;

    if ((fi->flags & O_ACCMODE) == O_RDONLY)
        mask = R_OK;
    else if ((fi->flags & O_ACCMODE) == O_WRONLY)
        mask = W_OK;
    else
        mask = R_OK | W_OK;

    int ret = check_access(path, mask);
    if (ret != 0) {
        fprintf(stderr, "[DENIED] open(%s) by uid=%u gid=%u\n",
                path, ctx->uid, ctx->gid);
    }
    return ret;
}

static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void) fi;
    const char *data;
    size_t len;

    if (strcmp(path, public_path) == 0) {
        data = public_data;
    } else if (strcmp(path, secret_path) == 0) {
        data = secret_data;
    } else {
        return -ENOENT;
    }

    len = strlen(data);
    if ((size_t)offset >= len)
        return 0;

    if (offset + size > len)
        size = len - offset;
    memcpy(buf, data + offset, size);
    return size;
}

static int myfs_access(const char *path, int mask) {
    struct fuse_context *ctx = fuse_get_context();
    fprintf(stderr, "[ACCESS] path=%s uid=%u gid=%u mask=0x%x\n",
            path, ctx->uid, ctx->gid, mask);

    if (strcmp(path, "/") == 0)
        return 0;
    if (strcmp(path, public_path) != 0 && strcmp(path, secret_path) != 0)
        return -ENOENT;
    if (mask == F_OK)
        return 0;

    return check_access(path, mask);
}

static const struct fuse_operations myfs_ops = {
    .getattr  = myfs_getattr,
    .readdir  = myfs_readdir,
    .open     = myfs_open,
    .read     = myfs_read,
    .access   = myfs_access,
};

int main(int argc, char *argv[]) {
    logfp = fopen("/tmp/uid_bypass.log", "w");
    fprintf(stderr, "=== uid_bypass_daemon: demonstrating s3fs-style uid==0 ACL bypass ===\n");
    fprintf(stderr, "Files: /secret.txt (mode 0600, owner uid=%d) - only owner should read\n",
            FILE_OWNER_UID);
    fprintf(stderr, "Vulnerability: uid==0 in fuse_in_header bypasses ALL permission checks\n");
    return fuse_main(argc, argv, &myfs_ops, NULL);
}
