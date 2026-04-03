# asUser() skips credential switching for uid==0, bypassing permission isolation

gocryptfs's `asUser()` function in `internal/syscallcompat/sys_common.go` skips `Setreuid()`/`Setregid()` calls when `fuse_in_header.uid == 0`. When gocryptfs runs as root with `allow_other` and receives requests from a user namespace (rootless Docker, podman, Kubernetes with userns), a container process running as namespace-local `uid=0` (mapped to an unprivileged host UID) triggers the bypass and gains unrestricted access to all decrypted files.

This effectively defeats the purpose of per-user permission enforcement on the encrypted filesystem.

## Steps to Reproduce

1. Initialize and mount gocryptfs with `allow_other`:

```bash
gocryptfs -init /srv/encrypted
gocryptfs -allow_other /srv/encrypted /mnt/decrypted
```

2. Create a restricted file:

```bash
echo "sensitive content" > /mnt/decrypted/secret.txt
chown 500:500 /mnt/decrypted/secret.txt
chmod 600 /mnt/decrypted/secret.txt
```

3. From a rootless container (e.g., `podman run --userns=auto`), access the mount as container `uid=0`:

```bash
cat /mnt/decrypted/secret.txt
# Succeeds — should be denied
```

4. As a non-root user in the container:

```bash
su -s /bin/sh nobody -c "cat /mnt/decrypted/secret.txt"
# Correctly denied
```

## Expected Behavior

Container `uid=0` (mapped to an unprivileged host UID) should trigger a credential switch in `asUser()` and be subject to POSIX permission checks on the decrypted files. Access to files owned by other UIDs with mode `600` should be denied.

## Actual Behavior

`asUser()` detects `uid==0` and skips the `Setreuid()`/`Setregid()` calls. All file operations execute with gocryptfs's root credentials, and full read/write/delete access is granted to all decrypted files regardless of ownership.

## Affected Code

`internal/syscallcompat/sys_common.go`, `asUser()` function:

```go
if context.Owner.Uid == 0 {
    return f()
}
syscall.Setregid(-1, int(context.Owner.Gid))
syscall.Setreuid(-1, int(context.Owner.Uid))
defer syscall.Setreuid(-1, 0)
defer syscall.Setregid(-1, 0)
return f()
```

When `Uid == 0`, the function returns early without switching credentials.

## Suggested Fix

Always perform credential switching for all FUSE requests:

```go
// Always switch credentials. Setreuid(-1, 0) when already root
// is a kernel no-op, so this has no performance cost.
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
```

This ensures namespace-remapped `uid=0` processes do not inherit the daemon's root privileges.

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_gocryptfs_vul/tree/main/FUSE_IN_HEADER_uid_response)
