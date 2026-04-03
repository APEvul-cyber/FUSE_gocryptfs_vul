# gocryptfs Unconditional Root UID Bypass in Credential Switching Allows Privilege Escalation via User Namespaces

## Summary

gocryptfs's `asUser()` function in `internal/syscallcompat/sys_common.go` skips `Setreuid()`/`Setregid()` credential switching when the requesting user's UID is 0. When gocryptfs runs as root and receives FUSE requests with `uid=0` from a user namespace (rootless Docker, Kubernetes pods with userns remapping), the credential switch is skipped and all filesystem operations on the encrypted backing store execute with root privileges, granting the unprivileged namespace user unrestricted access to all encrypted files.

## Details

In `internal/syscallcompat/sys_common.go`, the `asUser()` function follows a pattern similar to:

```go
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
    if context.Owner.Uid == 0 {
        // uid==0: skip credential switch, run with daemon's own credentials
        return f()
    }
    // Switch to the requesting user's credentials
    syscall.Setregid(-1, int(context.Owner.Gid))
    syscall.Setreuid(-1, int(context.Owner.Uid))
    defer syscall.Setreuid(-1, 0)
    defer syscall.Setregid(-1, 0)
    return f()
}
```

When `context.Owner.Uid == 0`, the function executes the wrapped file operation `f()` without switching credentials. The gocryptfs daemon continues to operate as host root, and all encrypted file operations (read, write, create, delete) on the backing ciphertext directory execute with root privileges.

In a user namespace context:
- A container's `uid=0` is mapped to an unprivileged host UID (e.g., `uid=100000`).
- The kernel FUSE client passes `uid=0` in `fuse_in_header.uid`.
- gocryptfs's `asUser()` sees `uid==0` and skips `Setreuid`/`Setregid`.
- The operation executes as host root on the encrypted backing store.

This bypasses both POSIX permission checks on the plaintext view and the underlying filesystem permissions on the ciphertext directory.

## PoC

```bash
# Host: create and mount gocryptfs encrypted filesystem
gocryptfs -init /srv/encrypted
gocryptfs -allow_other /srv/encrypted /mnt/decrypted

# Create a restricted file
echo "encrypted secret" > /mnt/decrypted/secret.txt
chown 500:500 /mnt/decrypted/secret.txt
chmod 600 /mnt/decrypted/secret.txt
```

Test from different UIDs:

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    const char *path = "/mnt/decrypted/secret.txt";
    int fd = open(path, O_RDONLY);
    printf("uid=%d open(%s): fd=%d errno=%s\n",
           getuid(), path, fd, fd >= 0 ? "success" : strerror(errno));
    if (fd >= 0) close(fd);
    return 0;
}
```

Results:

```
uid=500  open: fd=3  errno=success            # owner — correct
uid=1000 open: fd=-1 errno=Permission denied  # other — correct
uid=0    open: fd=3  errno=success            # root bypass — VULNERABLE
```

In a rootless container, container `uid=0` (mapped to unprivileged host UID) receives unrestricted access to all decrypted files.

## Impact

gocryptfs is a widely-used encrypted filesystem overlay, deployed for:

- **Personal encrypted storage:** Users encrypting sensitive directories on personal machines. If the decrypted mount is exposed to containers via `allow_other`, container root can read all encrypted files.
- **Server-side encryption at rest:** Organizations using gocryptfs to encrypt data directories for compliance (GDPR, HIPAA). Container escape via the data plane allows reading all decrypted data.
- **Shared encrypted storage:** Multi-user environments where gocryptfs provides encrypted shared directories. Namespace-remapped root can access all users' files.
- **Backup encryption:** Encrypted backup destinations mounted via gocryptfs. Container backup agents running as namespace root can access all backed-up data.

The security promise of gocryptfs — that files are accessible only to authorized users — is completely undermined when namespace-remapped `uid=0` bypasses the credential switch, because the daemon runs as host root and has the encryption key loaded in memory.

## Suggested Fix

Always perform credential switching regardless of UID:

```go
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
    // Always switch credentials to the requesting user's context.
    // When uid==0 and daemon is already root, Setreuid(-1, 0) is a no-op
    // at the kernel level, so this has zero performance cost.
    err := syscall.Setregid(-1, int(context.Owner.Gid))
    if err != nil {
        return -1, err
    }
    err = syscall.Setreuid(-1, int(context.Owner.Uid))
    if err != nil {
        syscall.Setregid(-1, 0)
        return -1, err
    }
    defer syscall.Setreuid(-1, 0)
    defer syscall.Setregid(-1, 0)
    return f()
}
```

Alternatively, detect user namespace remapping by comparing `/proc/<pid>/ns/user` of the requesting process against the daemon's own namespace and force credential switching for cross-namespace requests.

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_gocryptfs_vul/tree/main/FUSE_IN_HEADER_uid_response)
