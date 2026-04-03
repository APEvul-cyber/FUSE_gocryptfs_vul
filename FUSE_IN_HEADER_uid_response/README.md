# FUSE_IN_HEADER:uid — uid==0 ACL Bypass in gocryptfs

## Vulnerability

gocryptfs unconditionally grants full access when `fuse_in_header.uid == 0`, bypassing all permission/ACL checks. In user namespace environments (rootless Docker, Kubernetes with userns), a container process running as namespace-local `uid=0` (mapped to an unprivileged host UID) triggers this bypass and gains unrestricted file access.

## Files

| File | Description |
|------|-------------|
| `FUSE_IN_HEADER_uid_response.txt` | Original PoC analysis |
| `poc_test.sh` | Main PoC test script |
| `uid_bypass_daemon.c` | Minimal FUSE daemon demonstrating the uid==0 bypass pattern |
| `poc_output.txt` | PoC execution output |
| `report_cve.md` | CVE report (GHSA style) |
| `report_issue.md` | GitHub Issue report |

## Environment Requirements

- Docker with `--privileged` or `--cap-add SYS_ADMIN --device /dev/fuse`
- Ubuntu 24.04 base image
- libfuse3-dev and fuse3 packages
- `gcc` and `pkg-config` for compiling the PoC daemon

## How to Run

### 1. Build the Docker Environment

```bash
docker build -t fuse-poc-env .
docker run --rm --privileged --device /dev/fuse \
  --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -it fuse-poc-env bash
```

### 2. Inside the Container

```bash
# Copy source files to expected locations
cp uid_bypass_daemon.c /src/uid_bypass_daemon.c
mkdir -p /results

# Compile the PoC daemon
gcc -Wall -o /tmp/uid_bypass_daemon /src/uid_bypass_daemon.c \
  $(pkg-config fuse3 --cflags --libs)

# Run the PoC
bash poc_test.sh
```

### 3. Expected Output

The script runs 6 tests:
- **TEST 1**: Owner (uid=500) reads secret.txt → ALLOWED (correct)
- **TEST 2**: Other user (uid=1000) reads secret.txt → DENIED (correct)
- **TEST 3**: Root (uid=0) reads secret.txt → **ALLOWED (VULNERABILITY)**
- **TEST 4**: Other user reads public.txt → ALLOWED (correct)
- **TEST 5**: User namespace escalation test
- **TEST 6**: Daemon access log analysis

```
[TEST 3] Root (uid=0) reads secret.txt:
  Expected: ALLOWED (uid==0 bypasses ALL ACL)
  Result:   ALLOWED -> 'TOP SECRET: admin credentials here!'
  *** VULNERABILITY: uid==0 bypassed ACL for non-owner root ***
```
