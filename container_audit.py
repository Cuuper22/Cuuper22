#!/usr/bin/env python3
"""
Container Security Audit v2 — Python rewrite
Philosophy: raw output first, interpretation second. No silent failures.
Every flagged file gets read and printed. Every check shows its command.
"""
import os, sys, re, json, socket, stat, struct, datetime, subprocess, ipaddress
from pathlib import Path

# ─── ANSI colors ────────────────────────────────────────────────────────────
RED = '\033[0;31m'; YEL = '\033[0;33m'; GRN = '\033[0;32m'
CYN = '\033[0;36m'; MAG = '\033[0;35m'; RST = '\033[0m'; BLD = '\033[1m'

# ─── Counters and log ───────────────────────────────────────────────────────
counts  = {'RISK': 0, 'WARN': 0, 'PASS': 0, 'INFO': 0}
risk_log = []

def _tag(label, color, msg):
    counts[label] = counts.get(label, 0) + 1
    print(f"  {color}[{label}]{RST}  {msg}")
    if label == 'RISK':
        risk_log.append(msg)

def RISK(m): _tag('RISK', RED, m)
def WARN(m): _tag('WARN', YEL, m)
def PASS(m): _tag('PASS', GRN, m)
def INFO(m): _tag('INFO', CYN, m)
def NOTE(m): print(f"  {MAG}[NOTE]{RST}  {m}")

def HDR(title):
    print(f"\n\n╔{'═'*62}╗")
    print(f"║  {title:<62}║")
    print(f"╚{'═'*62}╝")

def SUB(title):
    print(f"\n  ┌─ {title}")

def raw(text, indent="    "):
    """Print pre-captured text, indented, line by line."""
    if not text or not text.strip():
        print(f"{indent}(empty / no output)")
        return
    for line in text.rstrip().splitlines():
        print(f"{indent}{line}")

# ─── Core helpers ───────────────────────────────────────────────────────────

def run(cmd, timeout=8, show_cmd=True):
    """
    Run a shell command. Always prints the command and its full output (stdout+stderr).
    Returns (stdout_text, returncode). Never raises.
    """
    if show_cmd:
        print(f"\n    $ {cmd}")
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout, errors='replace'
        )
        combined = (r.stdout + r.stderr).strip()
        raw(combined if combined else "(no output)")
        if r.returncode != 0 and not combined:
            print(f"    [exit {r.returncode} — no output]")
        elif r.returncode != 0:
            print(f"    [exit {r.returncode}]")
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        print(f"    [TIMED OUT after {timeout}s]")
        return "", -1
    except Exception as e:
        print(f"    [EXEC ERROR: {e}]")
        return "", -1


def read_file(path, max_bytes=8192, label=None):
    """
    Read a file. Always prints `cat <path>` and the raw contents.
    Returns text or None on failure.
    """
    display = label or path
    print(f"\n    $ cat {display}")
    p = Path(path)
    try:
        data = p.read_bytes()
    except PermissionError:
        print("    [permission denied]")
        return None
    except FileNotFoundError:
        print("    [not found]")
        return None
    except Exception as e:
        print(f"    [read error: {e}]")
        return None

    # Null bytes → newlines (for /proc files)
    data_clean = data.replace(b'\x00', b'\n')
    try:
        text = data_clean.decode('utf-8')
    except UnicodeDecodeError:
        text = data_clean.decode('latin-1')

    if len(data) > max_bytes:
        raw(text[:max_bytes])
        print(f"    [... truncated — {len(data)} bytes total]")
    else:
        raw(text.strip())
    return text


def read_proc(path):
    """Convenience wrapper: read a /proc file and show it."""
    return read_file(path)


def tcp_probe(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False


def file_perms(path):
    """Return a human-readable permission string for a path."""
    try:
        s = os.stat(path)
        return f"{oct(s.st_mode)[-4:]}  uid={s.st_uid}  gid={s.st_gid}  size={s.st_size}"
    except:
        return "(stat failed)"


# ─── Capability decoder ─────────────────────────────────────────────────────
CAP_NAMES = {
    0:'CHOWN', 1:'DAC_OVERRIDE', 2:'DAC_READ_SEARCH', 3:'FOWNER', 4:'FSETID',
    5:'KILL', 6:'SETGID', 7:'SETUID', 8:'SETPCAP', 9:'LINUX_IMMUTABLE',
    10:'NET_BIND_SERVICE', 11:'NET_BROADCAST', 12:'NET_ADMIN', 13:'NET_RAW',
    14:'IPC_LOCK', 15:'IPC_OWNER', 16:'SYS_MODULE', 17:'SYS_RAWIO',
    18:'SYS_CHROOT', 19:'SYS_PTRACE', 20:'SYS_PACCT', 21:'SYS_ADMIN',
    22:'SYS_BOOT', 23:'SYS_NICE', 24:'SYS_RESOURCE', 25:'SYS_TIME',
    26:'SYS_TTY_CONFIG', 27:'MKNOD', 28:'LEASE', 29:'AUDIT_WRITE',
    30:'AUDIT_CONTROL', 31:'SETFCAP', 32:'MAC_OVERRIDE', 33:'MAC_ADMIN',
    34:'SYSLOG', 35:'WAKE_ALARM', 36:'BLOCK_SUSPEND', 37:'AUDIT_READ',
    38:'PERFMON', 39:'BPF', 40:'CHECKPOINT_RESTORE',
}
CAP_RISK = {
    21: 'full system admin — container escape vector',
    16: 'load kernel modules — rootkit installation',
    19: 'ptrace any process — read/write arbitrary process memory',
    13: 'raw sockets — packet injection and sniffing',
    12: 'network admin — modify routes/iptables/interfaces',
    17: 'raw I/O — direct disk and memory device access',
    7:  'setuid — become any user',
    6:  'setgid — become any group',
    18: 'chroot — escape jail or create new filesystem root',
    39: 'BPF — load eBPF programs, potential kernel bypass',
    8:  'setpcap — grant capabilities to other processes',
    2:  'DAC_READ_SEARCH — bypass all file-read permission checks',
}


def decode_capset(hex_str, label):
    """Decode a capability hex string, print each bit, return list of (bit, name, is_dangerous)."""
    print(f"\n    {BLD}{label}{RST} (raw hex: {hex_str})")
    try:
        val = int(hex_str, 16)
    except ValueError:
        print("    [could not parse hex]")
        return []

    if val == 0:
        print("      (none — empty set)")
        return []

    result = []
    for bit in range(41):
        if val & (1 << bit):
            name = CAP_NAMES.get(bit, f'UNKNOWN_{bit}')
            danger = bit in CAP_RISK
            reason = CAP_RISK.get(bit, '')
            marker = f"  *** DANGEROUS: {reason} ***" if danger else ""
            print(f"      bit {bit:2d}: CAP_{name}{marker}")
            result.append((bit, name, danger))
    return result


# ═══════════════════════════════════════════════════════════════════════════
# 1. RUNTIME DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def section_runtime():
    HDR("1. RUNTIME DETECTION")
    NOTE("Goal: understand the isolation boundary around this process.")
    NOTE("gVisor/runsc = userspace kernel; the synthetic uname version is not the real host kernel.")
    NOTE("If hypervisor flag is set, escaping the container only reaches a VM — not bare metal.")

    SUB("Operating system")
    run("cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null")
    uname_out, _ = run("uname -a")
    if '4.4.0' in uname_out:
        INFO("Kernel version 4.4.0 is the gVisor synthetic kernel — not the real host kernel")
    run("uname -m")

    SUB("Cgroup hierarchy — reveals runtime type")
    NOTE("Path format: docker/<id> = Docker, kubepods/<id> = Kubernetes, bare hash or 'wiggle' = gVisor/ACI")
    cgroup = read_file("/proc/1/cgroup")
    if cgroup:
        if 'docker'   in cgroup.lower(): WARN("Docker cgroup prefix detected")
        elif 'kubepods' in cgroup.lower(): WARN("Kubernetes cgroup prefix detected")
        elif 'lxc'    in cgroup.lower(): WARN("LXC cgroup prefix detected")
        else:
            if 'wiggle' in cgroup.lower() or 'runsc' in cgroup.lower():
                INFO("gVisor (runsc) sandbox detected — userspace kernel sits between container and host")
            else:
                INFO("Non-standard cgroup prefix — likely ACI, custom runtime, or gVisor")

    SUB("Container indicator files")
    NOTE("/.dockerenv is created by Docker in every container it starts.")
    for f in ['/.dockerenv', '/run/.containerenv', '/var/run/.containerenv']:
        if Path(f).exists():
            s = file_perms(f)
            WARN(f"Found: {f}  ({s})")
        else:
            PASS(f"Not present: {f}")

    SUB("Platform metadata: /container_info.json")
    NOTE("Platform-injected file. Raw JSON shown in full, then each field annotated.")
    content = read_file("/container_info.json")
    if content:
        try:
            data = json.loads(content)
            NOTE("Decoded fields:")
            for k, v in data.items():
                if k == 'creation_time':
                    try:
                        human = datetime.datetime.utcfromtimestamp(float(v)).strftime('%Y-%m-%d %H:%M:%S')
                        print(f"      {k} = {v}  →  {human} UTC")
                    except Exception:
                        print(f"      {k} = {v}  →  (could not decode as epoch)")
                else:
                    print(f"      {k} = {v}")
        except json.JSONDecodeError as e:
            WARN(f"JSON parse failed: {e} — raw content shown above")
    else:
        INFO("Not present")

    SUB("Hypervisor / VM detection")
    NOTE("'hypervisor' flag in CPU flags = CPU knows it's virtualised (KVM, Hyper-V, VMware, etc.)")
    NOTE("GOOD for security: even if the container is escaped, you land inside a VM, not on host hardware.")
    cpu_flags, _ = run("grep -m1 'flags' /proc/cpuinfo 2>/dev/null | head -c 300 || echo 'not readable'")
    if 'hypervisor' in cpu_flags.lower():
        PASS("Hypervisor flag present — VM boundary exists below this OS (container escape → VM guest only)")
    else:
        WARN("No hypervisor flag in CPU flags — may be bare metal, or virtualisation is hidden")
    run("ls /dev/vmbus* /dev/virtio* 2>/dev/null || echo 'none'")
    run("systemd-detect-virt 2>/dev/null || echo 'systemd-detect-virt: not available'")

    SUB("Namespace isolation: PID 1 vs self")
    NOTE("Each namespace type in Linux isolates a resource class.")
    NOTE("  mnt = filesystems   net = network stack   pid = process IDs")
    NOTE("  ipc = shared memory   uts = hostname   user = uid/gid mapping")
    NOTE("If this process shares a namespace inode with PID 1, that resource is NOT isolated.")

    ns_types = ['mnt', 'net', 'pid', 'ipc', 'uts', 'user']
    pid1_ns = {}
    self_ns = {}

    print("\n    $ readlink /proc/1/ns/*")
    for ns in ns_types:
        try:
            target = os.readlink(f'/proc/1/ns/{ns}')
            pid1_ns[ns] = target
            print(f"    /proc/1/ns/{ns:6s} → {target}")
        except Exception as e:
            pid1_ns[ns] = None
            print(f"    /proc/1/ns/{ns:6s} → [error: {e}]")

    print("\n    $ readlink /proc/self/ns/*")
    for ns in ns_types:
        try:
            target = os.readlink(f'/proc/self/ns/{ns}')
            self_ns[ns] = target
            print(f"    /proc/self/ns/{ns:6s} → {target}")
        except Exception as e:
            self_ns[ns] = None
            print(f"    /proc/self/ns/{ns:6s} → [error: {e}]")

    print()
    NOTE("Comparison — same inode = shared namespace = no isolation:")
    for ns in ns_types:
        p, s = pid1_ns.get(ns), self_ns.get(ns)
        if p and s:
            if p == s:
                WARN(f"  {ns:6s}: SHARED with PID1  ({p})")
            else:
                PASS(f"  {ns:6s}: ISOLATED  PID1={p}  self={s}")
        else:
            INFO(f"  {ns:6s}: could not compare  (PID1={p!r}  self={s!r})")


# ═══════════════════════════════════════════════════════════════════════════
# 2. IDENTITY AND PRIVILEGE
# ═══════════════════════════════════════════════════════════════════════════

def section_identity():
    HDR("2. IDENTITY AND PRIVILEGE")

    SUB("Current process identity")
    NOTE("This is who the audit script runs as — and who any agent in this container runs as.")
    run("id")
    run("groups")
    uid = os.getuid()
    if uid == 0:
        RISK("Running as root (uid=0): can read all files, write to any writable mount, exploit misconfigs")
    else:
        INFO(f"Running as uid={uid} — not root")

    SUB("PID 1 (container init) identity and command line")
    NOTE("PID1 is the entrypoint/process manager. Its identity and command line show what this container does.")
    NOTE("process_api is the Anthropic executor that receives and runs AI-generated code.")
    status = read_proc("/proc/1/status")
    if status:
        NOTE("Extracted key fields from /proc/1/status:")
        for line in status.splitlines():
            if any(line.startswith(k) for k in ['Name', 'Pid', 'Uid', 'Gid', 'NoNewPrivs', 'Seccomp']):
                print(f"      {line}")
        pid1_uid = next(
            (l.split()[1] for l in status.splitlines() if l.startswith('Uid:')), None
        )
        if pid1_uid == '0':
            WARN("PID1 runs as root (uid=0)")
        else:
            INFO(f"PID1 uid={pid1_uid}")

    # cmdline: null-separated args
    print("\n    $ cat /proc/1/cmdline | tr '\\0' ' '")
    try:
        cmdline = Path('/proc/1/cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
        raw(cmdline)
        NOTE("Parsed PID1 command line arguments:")
        for arg in cmdline.split():
            print(f"      {arg}")
    except Exception as e:
        print(f"    [error: {e}]")

    SUB("no_new_privileges flag")
    NOTE("=1 means SUID/SGID binaries are neutered — the kernel ignores the setuid bit on exec.")
    NOTE("=0 (or absent) means SUID binaries execute with their owner's privileges.")
    NOTE("Set via prctl(PR_SET_NO_NEW_PRIVS,1) or Docker --security-opt no-new-privileges.")
    self_status = read_proc("/proc/self/status")
    nnp = None
    if self_status:
        for line in self_status.splitlines():
            if 'NoNewPrivs' in line:
                nnp = line.split(':', 1)[1].strip() if ':' in line else None
    print(f"\n    NoNewPrivs value: {nnp!r}")
    if nnp == '1':
        PASS("no_new_privileges=1 — SUID escalation is blocked")
    elif nnp == '0':
        RISK("no_new_privileges=0 — SUID binaries can escalate to their owner's uid (usually root)")
    else:
        WARN(f"NoNewPrivs not found in /proc/self/status (gVisor may not expose it) — treat as unset")

    SUB("Seccomp syscall filter")
    NOTE("Restricts which of the ~400 Linux syscalls this process can invoke.")
    NOTE("  0 = disabled (all syscalls available)")
    NOTE("  1 = strict (only read/write/exit/sigreturn — breaks most programs)")
    NOTE("  2 = BPF filter (custom allow/deny list — Docker default blocks ~40 dangerous syscalls)")
    seccomp = None
    if self_status:
        for line in self_status.splitlines():
            if line.startswith('Seccomp:'):
                seccomp = line.split(':', 1)[1].strip()
    print(f"\n    Seccomp value: {seccomp!r}")
    if seccomp == '0':
        RISK("Seccomp=0 — all kernel syscalls available, no syscall-level containment")
    elif seccomp == '1':
        WARN("Seccomp=1 strict mode — very restrictive")
    elif seccomp == '2':
        PASS("Seccomp=2 BPF filter active — syscall filtering in place")
    else:
        WARN(f"Seccomp field absent or unexpected ({seccomp!r}) — gVisor may virtualise this")

    SUB("/etc/passwd — full user database")
    NOTE("Format: username:password:uid:gid:comment:home:shell")
    NOTE("'x' in password field = hash is in /etc/shadow.  uid=0 = root-level access.")
    passwd = read_file("/etc/passwd")
    if passwd:
        uid0 = [l for l in passwd.splitlines() if ':0:' in l and l.split(':')[2] == '0']
        if len(uid0) > 1:
            RISK(f"Multiple uid=0 accounts: {uid0}")
        elif uid0:
            INFO(f"uid=0 entry: {uid0[0]}")

    SUB("/etc/shadow — password hashes")
    NOTE("Readable shadow file = offline password cracking is possible.")
    NOTE("Format: username:hash:last_changed:min:max:warn:inactive:expire:reserved")
    NOTE("Hash prefixes: $1$=MD5  $2y$=bcrypt  $5$=SHA-256  $6$=SHA-512  $y$=yescrypt")
    NOTE("  * or ! in hash field = account locked / no password set (login disabled)")
    NOTE("  !! = password never set  (empty) = passwordless login (DANGEROUS)")
    shadow = read_file("/etc/shadow")
    if shadow:
        print()
        NOTE("Per-entry analysis:")
        HASH_TYPES = {
            '$1$':  'MD5 (weak — crackable in seconds on GPU)',
            '$2$':  'bcrypt',
            '$2a$': 'bcrypt',
            '$2b$': 'bcrypt',
            '$2y$': 'bcrypt (strong)',
            '$5$':  'SHA-256 (moderate)',
            '$6$':  'SHA-512 (strong)',
            '$y$':  'yescrypt (strong)',
            '$7$':  'scrypt (strong)',
        }
        any_hash = False
        for line in shadow.splitlines():
            if not line.strip():
                continue
            parts = line.split(':')
            if len(parts) < 2:
                print(f"      {line}  →  (unparseable)")
                continue
            user = parts[0]
            pw   = parts[1]
            if pw == '*':
                print(f"      {user:20s}  hash=*    →  locked account, no password login")
            elif pw in ('!', '!!') or pw.startswith('!'):
                print(f"      {user:20s}  hash={pw!r:6s} →  account disabled / password never set")
            elif pw == '':
                print(f"      {user:20s}  hash=''   →  EMPTY — passwordless login possible!")
                RISK(f"Empty password in /etc/shadow for user: {user}")
            elif pw.startswith('$'):
                any_hash = True
                prefix = next((p for p in HASH_TYPES if pw.startswith(p)), None)
                algo = HASH_TYPES.get(prefix, f"unknown prefix '{prefix}'") if prefix else "unknown hash format"
                print(f"      {user:20s}  hash={pw[:30]}...  →  {algo}")
                RISK(f"/etc/shadow readable and contains crackable hash for '{user}': {algo}")
            else:
                print(f"      {user:20s}  hash={pw[:30]}  →  unrecognised format")
        if not any_hash:
            INFO("No crackable hashes found — all accounts locked or login-disabled")
    else:
        PASS("/etc/shadow not readable (expected)")

    SUB("/etc/group — group memberships")
    read_file("/etc/group")

    SUB("Sudo configuration")
    NOTE("NOPASSWD = passwordless root. sudo -l lists what the current user can run.")
    sudo_out, sudo_rc = run("sudo -l 2>&1", timeout=5)
    if 'NOPASSWD' in sudo_out:
        RISK("NOPASSWD sudo rule — passwordless privilege escalation is available")
        for line in sudo_out.splitlines():
            if 'NOPASSWD' in line:
                RISK(f"  Rule: {line.strip()}")
    elif sudo_rc != 0 or any(x in sudo_out.lower() for x in ['not allowed', 'unknown', 'not found', 'command not found']):
        PASS("sudo not available or no rights for current user")


# ═══════════════════════════════════════════════════════════════════════════
# 3. CAPABILITIES
# ═══════════════════════════════════════════════════════════════════════════

def section_capabilities():
    HDR("3. LINUX CAPABILITIES")
    NOTE("Capabilities split root privileges into individual units.")
    NOTE("CapEff = active right now.  CapBnd = ceiling (max reachable via escalation).")
    NOTE("CapPrm = permitted set.  CapInh = inherited across exec.  CapAmb = ambient.")

    SUB("Raw capability hex from /proc/self/status")
    status_text = read_proc("/proc/self/status")
    cap_map = {}
    if status_text:
        for line in status_text.splitlines():
            if line.startswith('Cap'):
                key, _, val = line.partition(':')
                cap_map[key.strip()] = val.strip()

    eff_hex = cap_map.get('CapEff', '0000000000000000')
    bnd_hex = cap_map.get('CapBnd', '0000000000000000')
    prm_hex = cap_map.get('CapPrm', '0000000000000000')
    inh_hex = cap_map.get('CapInh', '0000000000000000')
    amb_hex = cap_map.get('CapAmb', '0000000000000000')

    print(f"\n    Raw hex values extracted:")
    for label, val in [('CapEff',eff_hex),('CapBnd',bnd_hex),('CapPrm',prm_hex),
                       ('CapInh',inh_hex),('CapAmb',amb_hex)]:
        print(f"      {label}: {val}")

    SUB("Decoded capability sets")
    eff_caps = decode_capset(eff_hex, "EFFECTIVE  — active right now")
    bnd_caps = decode_capset(bnd_hex, "BOUNDING   — ceiling; reachable via privilege escalation")
    prm_caps = decode_capset(prm_hex, "PERMITTED  — can be moved into effective set")
    inh_caps = decode_capset(inh_hex, "INHERITABLE — kept across execve()")
    amb_caps = decode_capset(amb_hex, "AMBIENT    — retained across execve() as non-root")

    print()
    eff_names = {n for _, n, _ in eff_caps}
    bnd_names = {n for _, n, _ in bnd_caps}

    dangerous_eff = [(bit, n) for bit, n, d in eff_caps if d]
    dangerous_bnd = [(bit, n) for bit, n, d in bnd_caps if d and n not in eff_names]

    for bit, name in dangerous_eff:
        RISK(f"Dangerous cap ACTIVE: CAP_{name} — {CAP_RISK[bit]}")
    for bit, name in dangerous_bnd:
        WARN(f"Dangerous cap in bounding set (escalation reachable): CAP_{name} — {CAP_RISK[bit]}")
    if not dangerous_eff and not dangerous_bnd:
        PASS("No dangerous capabilities active or reachable in bounding set")

    SUB("capsh --print (if available)")
    run("capsh --print 2>/dev/null || echo 'capsh not installed'")


# ═══════════════════════════════════════════════════════════════════════════
# 4. PRIVILEGE ESCALATION SURFACE
# ═══════════════════════════════════════════════════════════════════════════

def section_privesc():
    HDR("4. PRIVILEGE ESCALATION SURFACE")

    SUB("SUID binaries — full listing with permissions")
    NOTE("SUID bit = binary executes as its file owner (usually root), not the caller.")
    NOTE("Permission string: '-rwsr-xr-x' — the 's' in owner-execute position = SUID.")
    NOTE("With no_new_privs=1 these are neutralised. Without it, each is a potential escalation path.")
    NOTE("Reference: https://gtfobins.github.io — check each binary here.")
    suid_out, _ = run("find /usr /bin /sbin /opt /home -xdev -perm -4000 -type f 2>/dev/null | sort", timeout=30)
    if suid_out and suid_out.strip() not in ('', '(no output)'):
        for p in suid_out.splitlines():
            p = p.strip()
            if not p:
                continue
            try:
                s = os.stat(p)
                perm = oct(s.st_mode)
                # Check GTFObins known-dangerous ones
                known = {
                    'nmap', 'vim', 'vi', 'nano', 'less', 'more', 'bash', 'sh',
                    'python', 'python3', 'perl', 'ruby', 'find', 'awk', 'cp', 'mv',
                    'tar', 'zip', 'env', 'docker', 'pkexec',
                }
                bname = Path(p).name
                if any(k in bname for k in known):
                    RISK(f"SUID known-GTFObins: {p}  perms={perm}  owner_uid={s.st_uid}")
                else:
                    WARN(f"SUID: {p}  perms={perm}  owner_uid={s.st_uid}")
            except:
                WARN(f"SUID: {p}  (stat failed)")
    else:
        PASS("No SUID binaries found in /usr /bin /sbin /opt /home")

    SUB("SGID binaries — full listing")
    NOTE("SGID = executes with the file's group — can grant access to group-restricted resources.")
    run("find /usr /bin /sbin /opt /home -xdev -perm -2000 -type f 2>/dev/null | sort || echo 'none'", timeout=30)

    SUB("World-writable directories in system paths")
    NOTE("World-writable dir in a script's working path → file swap / race condition attacks.")
    run("find /usr /bin /sbin /lib /lib64 /etc -xdev -type d -perm -0002 2>/dev/null | head -20 || echo 'none'", timeout=30)
    run("find / -xdev -maxdepth 5 -type d -perm -0002 2>/dev/null "
        "| grep -vE '^/(proc|sys|tmp|dev|run)' | head -20 || echo 'none outside /tmp'", timeout=30)

    SUB("Writable PATH directories — contents shown for each")
    NOTE("Writable PATH dir = plant a fake binary (e.g., 'python3', 'curl') that runs in its place.")
    NOTE("We show ls -la of each writable dir so you can spot planted binaries now.")
    path_env = os.environ.get('PATH', '')
    print(f"\n    PATH={path_env}")
    any_writable = False
    for d in path_env.split(':'):
        if not d:
            continue
        if not Path(d).exists():
            INFO(f"  {d}  — does not exist")
            continue
        writable = os.access(d, os.W_OK)
        if writable:
            RISK(f"WRITABLE PATH dir: {d}")
            any_writable = True
            # Show contents so runner can spot planted binaries
            run(f"ls -la {d} 2>/dev/null | head -30")
        else:
            PASS(f"  {d}  — not writable")
    if not any_writable:
        PASS("No writable PATH directories found")

    SUB("Writable cron scripts — listing AND file contents")
    NOTE("Writable cron file = arbitrary code executes at next interval as cron's user (often root).")
    NOTE("We print each writable script's CONTENTS so you can see if it is already modified.")
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
                 '/etc/cron.weekly', '/etc/cron.monthly']
    found = False
    for d in cron_dirs:
        dp = Path(d)
        if not dp.exists():
            continue
        print(f"\n    $ ls -la {d}")
        run(f"ls -la {d} 2>/dev/null", show_cmd=False)
        for f in sorted(dp.iterdir()):
            if not f.is_file():
                continue
            writable = os.access(str(f), os.W_OK)
            if writable:
                RISK(f"WRITABLE cron script: {f}")
                found = True
                NOTE(f"Contents of {f}:")
                read_file(str(f), max_bytes=4096)
            else:
                INFO(f"  {f}  — not writable  ({file_perms(str(f))})")

    print(f"\n    $ cat /etc/crontab")
    run("cat /etc/crontab 2>/dev/null || echo 'absent'", show_cmd=False)
    run("crontab -l 2>/dev/null || echo '(no crontab for current user)'")
    if not found:
        PASS("No writable cron scripts found")

    SUB("Library injection vectors")
    NOTE("LD_PRELOAD / LD_LIBRARY_PATH inject a custom shared library loaded before all others.")
    NOTE("A malicious preloaded library can intercept any libc function call in any subsequent process.")
    run("echo \"LD_PRELOAD=${LD_PRELOAD:-(not set)}\"")
    run("echo \"LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-(not set)}\"")
    NOTE("Contents of /etc/ld.so.preload (system-wide preload list):")
    read_file("/etc/ld.so.preload")

    SUB("Writable /etc/passwd, /etc/shadow, /etc/sudoers")
    NOTE("Writing to /etc/passwd = add a root-uid account with no password.")
    NOTE("Writing to /etc/sudoers = grant passwordless sudo to any user.")
    for f in ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/sudoers.d']:
        p = Path(f)
        if not p.exists():
            INFO(f"Not present: {f}")
            continue
        if os.access(f, os.W_OK):
            RISK(f"WRITABLE: {f}  ({file_perms(f)})")
        else:
            PASS(f"Not writable: {f}  ({file_perms(f)})")


# ═══════════════════════════════════════════════════════════════════════════
# 5. FILESYSTEM AND MOUNTS
# ═══════════════════════════════════════════════════════════════════════════

def section_filesystem():
    HDR("5. FILESYSTEM AND MOUNTS")
    NOTE("Mount propagation 'shared' = writes propagate to the host. 'slave' = receives from host.")
    NOTE("9p = Plan 9 filesystem (gVisor uses this to expose host directories).")

    SUB("Full mount table (/proc/mounts)")
    NOTE("Fields: device  mountpoint  fstype  options  dump  pass")
    read_file("/proc/mounts")

    SUB("/proc/self/mountinfo — propagation details")
    NOTE("'shared:N' tag = mount events propagate outward to host. This is the key exfil indicator.")
    NOTE("'master:N' = slave mount — receives events from the host mount group N.")
    mountinfo = read_file("/proc/self/mountinfo")
    if mountinfo:
        for line in mountinfo.splitlines():
            parts = line.split()
            mountpoint = parts[4] if len(parts) > 4 else '?'
            if 'shared:' in line:
                RISK(f"Shared propagation at mountpoint: {mountpoint}")
                print(f"      full line: {line}")
            elif 'master:' in line:
                WARN(f"Slave mount at: {mountpoint}")
                print(f"      full line: {line}")

    SUB("/etc/hosts — full contents + writability")
    NOTE("Writable /etc/hosts = reroute internal hostnames to attacker-controlled addresses.")
    read_file("/etc/hosts")
    if os.access('/etc/hosts', os.W_OK):
        RISK("/etc/hosts is WRITABLE — DNS spoofing inside this container is possible")
    else:
        PASS("/etc/hosts is not writable")

    SUB("/etc/resolv.conf — DNS server configuration")
    NOTE("Which DNS server answers queries. Container-controlled DNS can redirect any domain lookup.")
    read_file("/etc/resolv.conf")

    SUB("Critical path writability")
    NOTE("Writable system dirs allow binary/library replacement and config tampering.")
    for p in ['/', '/etc', '/usr', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
              '/lib', '/lib64', '/usr/lib', '/tmp', '/var/tmp',
              '/mnt', '/home', '/root']:
        if not Path(p).exists():
            continue
        w = os.access(p, os.W_OK)
        if w:
            WARN(f"Writable: {p}  ({file_perms(p)})")
        else:
            PASS(f"Not writable: {p}")

    SUB("World-writable files in /etc and /usr")
    NOTE("World-writable files in system paths can be replaced by any user.")
    run("find /etc /usr -xdev -type f -perm -0002 2>/dev/null | head -30 || echo 'none'", timeout=30)

    SUB("Unusual or large files in /tmp and home dirs")
    NOTE("Dropped tools/payloads often land in /tmp, /var/tmp, or home directories.")
    run("find /tmp /var/tmp /home /root -xdev -type f -size +50k 2>/dev/null "
        "| xargs ls -lah 2>/dev/null | sort -k5 -h -r | head -20 || echo 'none'", timeout=30)

    SUB("Recent filesystem changes (past 24h) outside /proc /sys /tmp")
    run("find / -xdev -maxdepth 6 -newer /proc/1 -not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/tmp/*' -type f 2>/dev/null | head -30 || echo 'none or error'", timeout=30)


# ═══════════════════════════════════════════════════════════════════════════
# 6. KERNEL HARDENING
# ═══════════════════════════════════════════════════════════════════════════

def section_kernel():
    HDR("6. KERNEL HARDENING (/proc/sys/kernel)")
    NOTE("These values are set by the host kernel. In gVisor they may be synthetic or absent.")
    NOTE("Absence (file not found) is marked [NOT EXPOSED] — gVisor virtualises away many of these.")

    checks = [
        ('/proc/sys/kernel/perf_event_paranoid', 'perf_event_paranoid',
         {'2': ('PASS', 'perf restricted to own process'),
          '1': ('WARN', 'perf allowed for normal users — profiling attack surface'),
          '0': ('RISK', 'unrestricted perf — any process can profile any other'),
          '-1':('RISK', 'unrestricted perf + kernel symbol addresses exposed')}),
        ('/proc/sys/kernel/kptr_restrict', 'kptr_restrict (kernel pointer exposure)',
         {'2': ('PASS', 'kernel pointers hidden from all users'),
          '1': ('PASS', 'kernel pointers hidden from non-root'),
          '0': ('RISK', 'kernel pointers exposed — KASLR bypass aid')}),
        ('/proc/sys/kernel/dmesg_restrict', 'dmesg_restrict',
         {'1': ('PASS', 'dmesg restricted to CAP_SYSLOG'),
          '0': ('WARN', 'dmesg readable by all — may contain kernel addresses')}),
        ('/proc/sys/kernel/randomize_va_space', 'randomize_va_space (ASLR)',
         {'2': ('PASS', 'full ASLR — heap, stack, mmap all randomised'),
          '1': ('WARN', 'partial ASLR — heap not randomised'),
          '0': ('RISK', 'ASLR disabled — deterministic addresses, trivial to exploit')}),
        ('/proc/sys/kernel/yama/ptrace_scope', 'yama/ptrace_scope',
         {'3': ('PASS', 'ptrace completely disabled'),
          '2': ('PASS', 'only admins can ptrace'),
          '1': ('WARN', 'ptrace restricted to parent processes'),
          '0': ('RISK', 'any process can ptrace any same-uid process — memory scraping')}),
        ('/proc/sys/user/max_user_namespaces', 'max_user_namespaces',
         {'0': ('PASS', 'user namespaces disabled — unprivileged namespace attacks blocked')}),
        ('/proc/sys/net/ipv4/ip_forward', 'ip_forward',
         {'1': ('WARN', 'IP forwarding enabled — container can route packets'),
          '0': ('PASS', 'IP forwarding disabled')}),
    ]

    for path, label, rating_map in checks:
        print(f"\n    $ cat {path}")
        try:
            val = Path(path).read_text().strip()
            print(f"    {val}")
            if val in rating_map:
                severity, msg = rating_map[val]
                {'PASS': PASS, 'WARN': WARN, 'RISK': RISK, 'INFO': INFO}[severity](
                    f"{label}={val}: {msg}"
                )
            else:
                INFO(f"{label}={val} — not in known-value map")
        except FileNotFoundError:
            print("    [NOT EXPOSED — file not found; gVisor virtualises this away]")
            INFO(f"{label}: not exposed by this runtime")
        except PermissionError:
            print("    [permission denied]")
            WARN(f"{label}: exists but not readable")

    SUB("core_pattern — core dump destination")
    NOTE("A pattern starting with '|' means core dumps are PIPED TO A PROGRAM — dangerous.")
    NOTE("Core dumps contain full process memory including secrets and tokens.")
    print("\n    $ cat /proc/sys/kernel/core_pattern")
    try:
        core = Path('/proc/sys/kernel/core_pattern').read_text().strip()
        print(f"    {core}")
        if core.startswith('|'):
            RISK(f"core_pattern pipes to a program: '{core}' — crashes execute this binary as root")
        else:
            INFO(f"core_pattern: '{core}' — dumps written to path")
    except FileNotFoundError:
        print("    [NOT EXPOSED]")
    print(f"\n    $ ulimit -c")
    run("ulimit -c", show_cmd=False)


# ═══════════════════════════════════════════════════════════════════════════
# 7. NETWORK
# ═══════════════════════════════════════════════════════════════════════════

def parse_proc_net_tcp(path):
    """Parse /proc/net/tcp or /proc/net/tcp6. Returns list of (local, remote, state_name)."""
    state_names = {
        '01':'ESTABLISHED','02':'SYN_SENT','03':'SYN_RECV','04':'FIN_WAIT1',
        '05':'FIN_WAIT2','06':'TIME_WAIT','07':'CLOSE','08':'CLOSE_WAIT',
        '09':'LAST_ACK','0A':'LISTEN','0B':'CLOSING'
    }
    results = []
    try:
        lines = Path(path).read_text().strip().splitlines()[1:]  # skip header
    except:
        return []
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        def decode_addr(hex_addr):
            try:
                addr_part, port_part = hex_addr.split(':')
                # IPv4: 4-byte little-endian hex
                ip_bytes = bytes.fromhex(addr_part)[::-1]
                ip = socket.inet_ntoa(ip_bytes)
                port = int(port_part, 16)
                return f"{ip}:{port}"
            except:
                return hex_addr  # return raw if we can't decode
        local  = decode_addr(parts[1])
        remote = decode_addr(parts[2])
        state  = state_names.get(parts[3].upper(), f"state={parts[3]}")
        results.append((local, remote, state))
    return results


def section_network():
    HDR("7. NETWORK CONFIGURATION AND CONNECTIONS")

    SUB("Network interfaces")
    run("ip addr show 2>/dev/null || ifconfig 2>/dev/null")

    SUB("Routing table — default gateway is the lateral movement target")
    NOTE("The gateway IP is what we can reach via TCP. Neighbours are ±10 IPs around it.")
    run("ip route 2>/dev/null || route -n 2>/dev/null")

    # Extract gateway for later sections
    gw = ""
    try:
        route_raw = Path('/proc/net/route').read_text()
        for line in route_raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == '00000000':
                gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                break
    except:
        pass
    if gw:
        INFO(f"Extracted gateway from /proc/net/route: {gw}")
    else:
        INFO("Could not extract gateway from /proc/net/route")

    SUB("/proc/net/tcp — all TCP sockets with decoded addresses")
    NOTE("State LISTEN = accepting connections. ESTABLISHED = active session.")
    NOTE("Hex addresses in /proc/net/tcp are little-endian. Decoded here to dotted-decimal:port.")
    print(f"\n    $ decode /proc/net/tcp")
    read_proc("/proc/net/tcp")  # raw first
    NOTE("Decoded view:")
    tcp_conns = parse_proc_net_tcp('/proc/net/tcp')
    if tcp_conns:
        for local, remote, state in tcp_conns:
            line = f"    {local:25s} → {remote:25s}  [{state}]"
            print(line)
            if state == 'ESTABLISHED' and not remote.startswith('0.0.0.0') and not remote.startswith('127.'):
                WARN(f"Active outbound TCP: {local} → {remote}")
            elif state == 'LISTEN':
                WARN(f"Listening on: {local}")
    else:
        print("    (empty or not readable)")

    SUB("/proc/net/udp — UDP sockets")
    read_proc("/proc/net/udp")

    SUB("ss / netstat — listening services")
    run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'ss/netstat not available'")

    SUB("ARP table — neighbours already seen on this L2 segment")
    NOTE("Hosts here have communicated recently. These are lateral movement targets.")
    read_proc("/proc/net/arp")
    run("ip neigh show 2>/dev/null || arp -n 2>/dev/null || echo 'not available'")

    return gw  # returned so egress section can use it


# ═══════════════════════════════════════════════════════════════════════════
# 8. EGRESS AND TLS INSPECTION
# ═══════════════════════════════════════════════════════════════════════════

def section_egress():
    HDR("8. EGRESS TESTING AND TLS INSPECTION")
    NOTE("Testing: (1) can we open outbound TCP? (2) is TLS being intercepted (MITM)?")
    NOTE("TLS interception: the proxy terminates TLS, reads plaintext, re-encrypts to us.")
    NOTE("Evidence: cert issuer CN contains words like 'inspection', 'proxy', 'sandbox'.")
    NOTE("Expected issuers: DigiCert, Let's Encrypt, Amazon, GlobalSign, Sectigo.")

    targets = [
        ('ifconfig.me',      443, 'https://ifconfig.me',                    'IP echo — confirms egress and shows exit IP'),
        ('dns.google',       443, 'https://dns.google',                     'Google DNS-over-HTTPS'),
        ('1.1.1.1',           80, 'http://1.1.1.1',                         'Cloudflare plain HTTP'),
        ('api.anthropic.com',443, 'https://api.anthropic.com',              'Anthropic API'),
        ('github.com',       443, 'https://github.com',                     'GitHub'),
        ('pypi.org',         443, 'https://pypi.org',                       'Python Package Index'),
    ]

    SUB("TCP reachability probes — pure connect(), no HTTP")
    NOTE("Tells us which ports are open regardless of TLS or HTTP behaviour.")
    open_https = []
    for host, port, url, desc in targets:
        open_ = tcp_probe(host, port)
        if open_:
            RISK(f"TCP OPEN  {host}:{port}  ({desc})")
            if port == 443:
                open_https.append((host, port, desc))
        else:
            PASS(f"TCP BLOCKED  {host}:{port}  ({desc})")

    SUB("HTTP/HTTPS requests — full response headers and body excerpt")
    NOTE("curl -sv shows: TLS handshake, cert chain, HTTP response code, headers, body.")
    for host, port, url, desc in targets:
        print(f"\n  ── {desc} ──")
        # -s = silent progress, -S = show errors, -v = verbose (headers+TLS), -L = follow redirects
        run(f"curl -sSvL --max-time 8 '{url}' 2>&1 | head -80", timeout=12)

    SUB("TLS certificate chain inspection — openssl s_client")
    NOTE("Shows the full certificate chain Anthropic's TLS proxy presents.")
    NOTE("Check: does the Issuer on the leaf cert match the real CA, or is it a proxy CA?")
    NOTE("MITM indicators in issuer CN: 'inspection', 'proxy', 'sandbox', 'zscaler', 'netskope',")
    NOTE("  'bluecoat', 'forcepoint', 'cisco umbrella', 'anthropic', 'egress'.")
    mitm_keywords = [
        'inspection', 'proxy', 'intercept', 'sandbox', 'zscaler', 'netskope',
        'bluecoat', 'forcepoint', 'umbrella', 'egress', 'filter', 'anthropic ca',
        'internal ca', 'corporate', 'enterprise'
    ]
    for host, port, desc in open_https:
        print(f"\n  ── TLS chain: {host}:{port} ({desc}) ──")
        out, _ = run(
            f"echo Q | openssl s_client -connect {host}:{port} -showcerts "
            f"-servername {host} 2>&1",
            timeout=12
        )
        if out:
            print("\n    Subjects and Issuers extracted from chain:")
            for line in out.splitlines():
                if any(k in line.lower() for k in ['subject', 'issuer', 'verify', 'depth', 'cn=', 'o=']):
                    print(f"      {line.strip()}")
                    if any(kw in line.lower() for kw in mitm_keywords):
                        RISK(f"TLS MITM INDICATOR in cert: {line.strip()}")

    SUB("DNS resolution — which server answers, are results trustworthy?")
    NOTE("Comparing DNS answers. If internal names resolve to unexpected IPs, DNS is being hijacked.")
    for name in ['ifconfig.me', 'api.anthropic.com', 'github.com',
                 'kubernetes.default.svc.cluster.local']:
        out, _ = run(
            f"dig +short {name} 2>/dev/null || "
            f"python3 -c \"import socket; print(socket.gethostbyname('{name}'))\" 2>/dev/null || "
            f"getent hosts {name} 2>/dev/null || echo 'resolution failed'"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 9. ENVIRONMENT AND SECRETS
# ═══════════════════════════════════════════════════════════════════════════

# Patterns checked against BOTH key and value — purely for annotation, nothing is hidden
ANNOT_KEY_RE = re.compile(
    r'(key|token|secret|password|passwd|credential|auth|api|bearer|jwt|'
    r'access_tok|refresh_tok|private|signing|cert|tls|ssl|pw|pass)',
    re.IGNORECASE
)
ANNOT_VAL_RE = re.compile(
    r'(yes|true|enabled|debug|verbose|insecure|skip.?verify|no.?tls|'
    r'disable|0\.0\.0\.0|allow.?all|\*|none|false|no)',
    re.IGNORECASE
)


def _annotate_env_lines(lines):
    """
    Print every KEY=VALUE line.
    Lines that look interesting get a [RISK] marker; everything else prints plain.
    Checks BOTH key name AND value — not just key name.
    """
    for line in lines:
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, _, val = line.partition('=')
        flags = []
        if ANNOT_KEY_RE.search(key):
            flags.append(f"key name pattern")
        if val == '':
            flags.append("EMPTY VALUE — may mean unset secret or misconfigured blank")
        elif ANNOT_VAL_RE.search(val):
            flags.append(f"value pattern of interest ({val[:60]!r})")
        if flags:
            RISK(f"  {line}   ← {', '.join(flags)}")
        else:
            print(f"    {line}")


def section_environment():
    HDR("9. ENVIRONMENT AND SECRETS")
    NOTE("ALL environment variables are shown — no pre-filtering on key names.")
    NOTE("Improper config shows up in values too (wrong URLs, debug flags, blank secrets, etc.).")
    NOTE("Both key name AND value are checked for patterns of interest.")

    # ── Current process env ──────────────────────────────────────
    SUB("Current process environment — full, sorted, annotated")
    NOTE("Raw `env` output first, then annotation pass on every line.")
    out, _ = run("env | sort")
    own_env: dict[str, str] = {}
    if out:
        for line in out.splitlines():
            if '=' in line:
                k, _, v = line.partition('=')
                own_env[k] = v
        NOTE("Annotation pass — key name AND value both checked:")
        _annotate_env_lines(out.splitlines())

    # ── PID1 env ─────────────────────────────────────────────────
    SUB("PID1 environment — /proc/1/environ — full dump")
    NOTE("Raw null-separated bytes read directly, then null→newline, then sorted.")
    NOTE("PID1 env is set by the orchestrator at container launch — different from ours = injected.")
    print("\n    $ cat /proc/1/environ | tr '\\0' '\\n' | sort")
    pid1_env: dict[str, str] = {}
    try:
        pid1_raw  = Path('/proc/1/environ').read_bytes()
        pid1_text = pid1_raw.replace(b'\x00', b'\n').decode('utf-8', errors='replace').strip()
        raw('\n'.join(sorted(pid1_text.splitlines())))  # print sorted
        RISK("PID1 /proc/1/environ is readable — init process environment exposed to us")

        for line in pid1_text.splitlines():
            if '=' in line:
                k, _, v = line.partition('=')
                pid1_env[k] = v

        NOTE("Vars in PID1 NOT present in our env (injected at container start by orchestrator):")
        injected = {k: v for k, v in pid1_env.items()
                    if k not in own_env or own_env[k] != pid1_env[k]}
        if injected:
            for k, v in sorted(injected.items()):
                print(f"      {k}={v}")
                WARN(f"Injected/different in PID1: {k}={v}")
        else:
            INFO("PID1 env is identical to current process env (no extra injected vars)")

        NOTE("Full annotation pass on PID1 env:")
        _annotate_env_lines(pid1_text.splitlines())

    except PermissionError:
        print("    [permission denied]")
        PASS("PID1 /proc/1/environ not readable — as expected for isolated processes")
    except Exception as e:
        print(f"    [error: {e}]")

    # ── Per-process env scan ──────────────────────────────────────
    SUB("All visible process environments — full dump, deduplication against baseline")
    NOTE("Every readable /proc/PID/environ is shown in full.")
    NOTE("Lines already seen in our own env are marked [=baseline] to avoid noise.")
    NOTE("Lines unique to a PID are the interesting ones — they were set specifically for that process.")
    print("\n    $ for pid in /proc/[0-9]*/environ: read full env")

    baseline_lines = set(f"{k}={v}" for k, v in own_env.items())
    own_pid  = str(os.getpid())
    own_ppid = str(os.getppid())

    try:
        pids = sorted([p for p in os.listdir('/proc') if p.isdigit()], key=int)
        for pid in pids:
            try:
                cmd = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\x00', b' ') \
                          .decode('utf-8', errors='replace').strip()[:80]
            except:
                cmd = '?'

            env_path = Path(f'/proc/{pid}/environ')
            try:
                env_raw  = env_path.read_bytes()
                env_text = env_raw.replace(b'\x00', b'\n').decode('utf-8', errors='replace')
                env_lines = [l for l in env_text.splitlines() if l.strip()]

                print(f"\n    ── PID {pid}  ({cmd})")
                unique_count = 0
                for line in sorted(env_lines):
                    if line in baseline_lines:
                        print(f"      [=baseline] {line}")
                    else:
                        unique_count += 1
                        k, _, v = line.partition('=')
                        flags = []
                        if ANNOT_KEY_RE.search(k):
                            flags.append("key pattern")
                        if v == '':
                            flags.append("EMPTY VALUE")
                        elif ANNOT_VAL_RE.search(v):
                            flags.append(f"value pattern ({v[:40]!r})")
                        marker = f"  ← {', '.join(flags)}" if flags else ""
                        if flags:
                            RISK(f"  PID {pid} unique var: {line}{marker}")
                        else:
                            print(f"      [unique]    {line}")
                if unique_count == 0:
                    print(f"      (all vars match baseline — nothing unique for this PID)")

            except (PermissionError, FileNotFoundError):
                print(f"      [not readable]")
            except Exception as e:
                print(f"      [error: {e}]")

    except Exception as e:
        print(f"    [error iterating /proc: {e}]")


# ═══════════════════════════════════════════════════════════════════════════
# 10. SENSITIVE FILES AND CREDENTIALS
# ═══════════════════════════════════════════════════════════════════════════

def section_credentials():
    HDR("10. SENSITIVE FILES AND CREDENTIALS")

    SUB("Kubernetes service account token")
    k8s_token = Path('/var/run/secrets/kubernetes.io/serviceaccount/token')
    if k8s_token.exists():
        RISK("Kubernetes service account token found")
        content = read_file(str(k8s_token), max_bytes=2048)
        if content:
            try:
                import base64 as b64
                parts = content.strip().split('.')
                pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
                decoded = json.loads(b64.urlsafe_b64decode(pad))
                NOTE("Decoded JWT payload:")
                for k, v in decoded.items():
                    print(f"      {k}: {v}")
            except Exception as e:
                INFO(f"JWT decode failed: {e}")
        read_file('/var/run/secrets/kubernetes.io/serviceaccount/namespace')
    else:
        PASS("No Kubernetes service account token found")

    SUB("Cloud IMDS — 169.254.169.254")
    NOTE("Cloud metadata services at 169.254.169.254 return temporary cloud credentials.")
    NOTE("AWS: /latest/meta-data/iam/security-credentials/  GCP: /v1/instance/service-accounts/")
    if tcp_probe('169.254.169.254', 80, timeout=2):
        RISK("169.254.169.254:80 is reachable — cloud IMDS endpoint accessible")
        for cloud, url, extra_hdr in [
            ('AWS',   'http://169.254.169.254/latest/meta-data/', ''),
            ('Azure', "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "-H 'Metadata: true'"),
            ('GCP',   'http://metadata.google.internal/computeMetadata/v1/', "-H 'Metadata-Flavor: Google'"),
        ]:
            out, rc = run(f"curl -sf --max-time 3 {extra_hdr} '{url}'", timeout=5)
            if out and rc == 0:
                RISK(f"{cloud} IMDS reachable: {url}")
                raw(out[:500])
            else:
                PASS(f"{cloud} IMDS: no response")
    else:
        PASS("169.254.169.254 not reachable — no cloud IMDS access")

    SUB("Credential files — existence, permissions, and FULL CONTENTS")
    NOTE("Every readable file is shown in full (up to 4KB). This is the point: see what's actually there.")
    home = os.path.expanduser('~')
    cred_files = [
        '/run/secrets',
        f'{home}/.aws/credentials', f'{home}/.aws/config',
        f'{home}/.npmrc',
        f'{home}/.netrc',
        f'{home}/.gitconfig',
        f'{home}/.pip/pip.conf',
        f'{home}/.ssh/id_rsa', f'{home}/.ssh/id_ed25519',
        f'{home}/.ssh/id_ecdsa',
        f'{home}/.ssh/authorized_keys', f'{home}/.ssh/known_hosts',
        f'{home}/.ssh/config',
        '/root/.ssh/id_rsa', '/root/.ssh/id_ed25519',
        '/root/.ssh/authorized_keys', '/root/.ssh/known_hosts',
        '/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_ed25519_key',
        '/.env', '/app/.env', '/srv/.env', '/opt/.env', '/home/.env',
        '/.git/config', '/app/.git/config',
        '/etc/ssl/private',
        '/usr/etc/npmrc',
        '/etc/npmrc',
    ]
    for f in cred_files:
        p = Path(f)
        if not p.exists():
            continue
        if p.is_dir():
            print(f"\n    [directory] {f}")
            run(f"ls -la {f} 2>/dev/null | head -20")
            continue
        perms = file_perms(f)
        if os.access(f, os.R_OK):
            RISK(f"READABLE: {f}  ({perms})")
            read_file(f, max_bytes=4096)
        else:
            WARN(f"EXISTS (not readable): {f}  ({perms})")

    SUB("Docker socket")
    if Path('/var/run/docker.sock').exists():
        perms = file_perms('/var/run/docker.sock')
        if os.access('/var/run/docker.sock', os.W_OK):
            RISK(f"Docker socket WRITABLE: /var/run/docker.sock  ({perms})")
            NOTE("Escape: docker run -v /:/host --rm -it alpine chroot /host")
        else:
            WARN(f"Docker socket exists but not writable  ({perms})")
    else:
        PASS("Docker socket not mounted")

    SUB("SSH authorized_keys across all user home directories")
    run("awk -F: '{print $6}' /etc/passwd | sort -u | while read home; do "
        "f=\"$home/.ssh/authorized_keys\"; "
        "[ -f \"$f\" ] && echo \"=== $f ===\" && cat \"$f\" 2>/dev/null; "
        "done 2>/dev/null || echo 'none found'")


# ═══════════════════════════════════════════════════════════════════════════
# 11. PROCESSES AND IPC
# ═══════════════════════════════════════════════════════════════════════════

def section_processes():
    HDR("11. PROCESSES, IPC, AND COVERT CHANNELS")

    SUB("Process list — full view")
    NOTE("Shows all processes visible in this PID namespace. Unexpected entries = monitoring/backdoors.")
    run("ps auxf 2>/dev/null || ps -ef 2>/dev/null || echo 'ps not available'")

    SUB("/proc/[pid] inventory — status and cmdline for every visible PID")
    NOTE("We read /proc/$pid/status and cmdline for every PID we can see.")
    print("\n    $ ls /proc/ | grep -E '^[0-9]+$'")
    try:
        pids = sorted([p for p in os.listdir('/proc') if p.isdigit()], key=int)
        print(f"    Visible PIDs: {' '.join(pids)}")
        print()
        for pid in pids:
            try:
                status = Path(f'/proc/{pid}/status').read_text()
                cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\x00',b' ').decode('utf-8',errors='replace').strip()
                name   = next((l.split(':',1)[1].strip() for l in status.splitlines() if l.startswith('Name:')), '?')
                uid_l  = next((l for l in status.splitlines() if l.startswith('Uid:')), '')
                state_l= next((l.split(':',1)[1].strip() for l in status.splitlines() if l.startswith('State:')), '?')
                uid    = uid_l.split()[1] if uid_l else '?'
                print(f"    PID {pid:5s}: {name:20s}  uid={uid:5s}  state={state_l[:6]}  cmd={cmdline[:80]}")
            except:
                pass
    except Exception as e:
        print(f"    [error: {e}]")

    SUB("Zombie processes")
    NOTE("State 'Z' = zombie. Process exited but parent hasn't called wait(). Large count = bug.")
    run("ps aux 2>/dev/null | awk 'NR==1 || $8 ~ /Z/' || echo 'ps not available'")

    SUB("Named pipes (FIFOs) — potential covert IPC channels")
    NOTE("FIFOs in /tmp or /run can be used as covert communication channels between processes.")
    run("find /tmp /var/tmp /run /home /root -type p 2>/dev/null | xargs -r ls -la 2>/dev/null || echo 'none'")

    SUB("System V IPC — shared memory, semaphores, message queues")
    NOTE("Processes in the same IPC namespace can communicate via these. Show what's active.")
    read_proc("/proc/sysvipc/shm")
    read_proc("/proc/sysvipc/sem")
    read_proc("/proc/sysvipc/msg")

    SUB("POSIX shared memory (/dev/shm)")
    run("ls -laR /dev/shm 2>/dev/null || echo 'empty or not mounted'")

    SUB("Open file descriptors for PID 1")
    NOTE("Shows what files/sockets/pipes the init process has open.")
    run("ls -la /proc/1/fd 2>/dev/null | head -40 || echo 'permission denied'")


# ═══════════════════════════════════════════════════════════════════════════
# 12. LATERAL MOVEMENT
# ═══════════════════════════════════════════════════════════════════════════

def section_lateral():
    HDR("12. LATERAL MOVEMENT SURFACE")

    SUB("Gateway reachability — common service ports")
    NOTE("The gateway is the first hop. Open ports there = internal infrastructure we can reach.")
    gw = ""
    try:
        route_raw = Path('/proc/net/route').read_text()
        for line in route_raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == '00000000':
                gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                break
    except:
        pass

    if gw:
        INFO(f"Default gateway: {gw}")
        for port in [22, 80, 443, 2375, 2376, 8080, 8443, 6443, 2379, 3389]:
            if tcp_probe(gw, port, timeout=2):
                WARN(f"Gateway {gw}:{port} OPEN")
            else:
                PASS(f"Gateway {gw}:{port} closed")
    else:
        WARN("Could not determine gateway — skipping gateway probe")

    SUB("Subnet neighbour scan (±10 IPs around gateway, ports 22/80/443/8080)")
    NOTE("TCP connect only — no raw sockets needed. Reveals other containers on the same network.")
    if gw:
        parts = gw.rsplit('.', 1)
        base  = parts[0]
        last  = int(parts[1])
        found = []
        for offset in range(-10, 11):
            if offset == 0:
                continue
            octet = last + offset
            if not (1 <= octet <= 254):
                continue
            target = f"{base}.{octet}"
            for port in [22, 80, 443, 8080]:
                if tcp_probe(target, port, timeout=1):
                    WARN(f"Neighbour alive: {target}:{port}")
                    found.append(f"{target}:{port}")
        if not found:
            PASS(f"No neighbours responded on ports 22/80/443/8080 within ±10 of {gw}")
    else:
        INFO("Skipping neighbour scan — no gateway")

    SUB("Internal service name resolution")
    NOTE("Resolving common internal names. Successful resolution reveals internal network topology.")
    internal_names = [
        'kubernetes.default.svc.cluster.local',
        'kube-dns.kube-system.svc.cluster.local',
        'consul', 'vault', 'postgres', 'redis', 'elasticsearch',
        'kafka', 'rabbitmq', 'registry.internal', 'docker.internal',
    ]
    for name in internal_names:
        try:
            ip = socket.gethostbyname(name)
            WARN(f"Resolved: {name} → {ip}")
        except:
            PASS(f"No DNS: {name}")

    SUB("rsync daemon on :873")
    NOTE("Unauthenticated rsync modules allow pulling any file or pushing arbitrary payloads.")
    if tcp_probe('127.0.0.1', 873, timeout=2):
        RISK("rsync daemon on :873")
        run("rsync rsync://127.0.0.1/ 2>&1 || echo 'rsync error'")
    else:
        PASS("No rsync daemon on :873")


# ═══════════════════════════════════════════════════════════════════════════
# 13. TOOL INVENTORY
# ═══════════════════════════════════════════════════════════════════════════

def section_tools():
    HDR("13. TOOL INVENTORY")
    NOTE("Every present tool is a capability. We show path and version for each found binary.")
    NOTE("Risk levels: CRIT=direct system/cloud access, HIGH=exfil/pivot/debug, MED=support, LOW=minor")

    TOOLS = [
        # (name,  risk,   description)
        ('nmap',      'CRIT', 'network scanner — full port/service/OS detection'),
        ('masscan',   'CRIT', 'internet-speed scanner'),
        ('nc',        'HIGH', 'netcat — TCP listeners, file transfer, reverse shells'),
        ('netcat',    'HIGH', 'netcat alias'),
        ('ncat',      'HIGH', 'nmap netcat with TLS support'),
        ('socat',     'CRIT', 'multipurpose relay — TLS shells, port forward, pivoting'),
        ('curl',      'HIGH', 'HTTP client — exfil data, download payloads'),
        ('wget',      'HIGH', 'HTTP downloader'),
        ('python3',   'HIGH', 'full scripting — replaces all of the above'),
        ('python',    'HIGH', 'python alias'),
        ('python2',   'HIGH', 'legacy python'),
        ('perl',      'HIGH', 'full scripting language'),
        ('ruby',      'HIGH', 'full scripting language'),
        ('node',      'HIGH', 'Node.js — full network scripting'),
        ('npm',       'MED',  'package manager — can install tools at runtime'),
        ('pip3',      'MED',  'Python package manager'),
        ('bash',      'MED',  'shell'),
        ('sh',        'MED',  'POSIX shell'),
        ('zsh',       'MED',  'Z shell'),
        ('ssh',       'HIGH', 'SSH client — lateral movement'),
        ('scp',       'HIGH', 'secure copy — exfiltration'),
        ('sftp',      'HIGH', 'SFTP client'),
        ('git',       'MED',  'version control — push to remote = exfil'),
        ('docker',    'CRIT', 'Docker CLI — if socket writable, full host escape'),
        ('kubectl',   'CRIT', 'Kubernetes CLI — cluster control'),
        ('helm',      'MED',  'K8s package manager'),
        ('openssl',   'MED',  'crypto — generate certs, encrypt/decrypt, TLS client'),
        ('gpg',       'MED',  'GNU PGP — encryption and signing'),
        ('strace',    'HIGH', 'syscall tracer — reads all process I/O in real time'),
        ('ltrace',    'HIGH', 'library call tracer'),
        ('gdb',       'HIGH', 'debugger — arbitrary process memory read/write'),
        ('tcpdump',   'HIGH', 'packet capture — sniff all network traffic'),
        ('tshark',    'HIGH', 'Wireshark CLI — capture + decode protocols'),
        ('base64',    'LOW',  'encode/decode — data obfuscation'),
        ('xxd',       'LOW',  'hex dump — binary inspection'),
        ('od',        'LOW',  'octal dump'),
        ('jq',        'LOW',  'JSON processor'),
        ('rsync',     'MED',  'sync tool — can exfil entire file trees'),
        ('rclone',    'CRIT', 'cloud sync — direct upload to S3/GCS/Azure/etc'),
        ('aws',       'CRIT', 'AWS CLI — direct cloud resource access'),
        ('gcloud',    'CRIT', 'GCP CLI — direct cloud resource access'),
        ('az',        'CRIT', 'Azure CLI — direct cloud resource access'),
        ('mysql',     'MED',  'MySQL client'),
        ('psql',      'MED',  'PostgreSQL client'),
        ('redis-cli', 'MED',  'Redis client'),
    ]

    colors = {'CRIT': RED, 'HIGH': YEL, 'MED': CYN, 'LOW': GRN}
    found_tools = []

    for tool, risk, desc in TOOLS:
        path_out, rc = run(f"command -v {tool} 2>/dev/null", timeout=3, show_cmd=False)
        if path_out and rc == 0:
            ver_out, _ = run(f"{tool} --version 2>/dev/null | head -1", timeout=3, show_cmd=False)
            ver = ver_out.strip()[:60] if ver_out else ''
            color = colors.get(risk, RST)
            print(f"  {color}[{risk:4s}]{RST}  {tool:12s} → {path_out:35s} {ver}")
            found_tools.append((tool, risk, desc))

    print()
    NOTE("Flagging HIGH and CRIT tools as WARN findings:")
    for tool, risk, desc in found_tools:
        if risk in ('CRIT', 'HIGH'):
            WARN(f"{tool}: {desc}")


# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

def print_summary():
    HDR("AUDIT COMPLETE — SUMMARY")

    print(f"\n  {RED}[RISK]{RST}  {counts['RISK']:4d}   confirmed attack surface — act on these")
    print(f"  {YEL}[WARN]{RST}  {counts['WARN']:4d}   notable — may be exploitable depending on context")
    print(f"  {GRN}[PASS]{RST}  {counts['PASS']:4d}   checks confirmed secure")
    print(f"  {CYN}[INFO]{RST}  {counts['INFO']:4d}   informational notes")

    print(f"\n\n  {BLD}Full RISK finding list:{RST}")
    for i, item in enumerate(risk_log, 1):
        print(f"    {RED}●{RST}  {item}")

    print(f"\n  Filter commands (run on saved output):")
    print(f"    All RISK:  grep '\\[RISK\\]' <outfile>")
    print(f"    All WARN:  grep '\\[WARN\\]' <outfile>")
    print(f"    Section:   grep -A 200 '4\\. PRIVILEGE' <outfile>")


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

class Tee:
    """Write to both stdout and a file simultaneously."""
    def __init__(self, *files):
        self.files = files
    def write(self, data):
        for f in self.files:
            f.write(data)
    def flush(self):
        for f in self.files:
            f.flush()


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Container Security Audit v2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Sections:
  1=Runtime  2=Identity  3=Capabilities  4=PrivEsc  5=Filesystem
  6=Kernel   7=Network   8=Egress/TLS    9=Environment  10=Credentials
  11=Processes  12=Lateral  13=Tools

Examples:
  python3 container_audit.py
  python3 container_audit.py -o /tmp/audit.txt
  python3 container_audit.py -s 4,8,10        # run only sections 4, 8, 10
"""
    )
    parser.add_argument('-o', '--output', help='Output file (default: /tmp/audit_<host>_<ts>.txt)')
    parser.add_argument('-s', '--sections', help='Comma-separated section numbers (default: all)')
    args = parser.parse_args()

    host      = socket.gethostname()
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    outfile   = args.output or f"/tmp/audit_{host}_{timestamp}.txt"

    # Tee stdout to file
    real_stdout = sys.stdout
    try:
        fh = open(outfile, 'w', encoding='utf-8', errors='replace')
        sys.stdout = Tee(real_stdout, fh)
    except Exception as e:
        print(f"Warning: could not open output file {outfile}: {e}", file=real_stdout)
        fh = None

    print(f"\n  ████████████████████████████████████████████████████")
    print(f"  ██      CONTAINER SECURITY AUDIT REPORT v2       ██")
    print(f"  ████████████████████████████████████████████████████")
    print(f"\n  Host    : {host}")
    print(f"  Date    : {datetime.datetime.now()}")
    print(f"  User    : {os.popen('id').read().strip()}")
    print(f"  PID     : {os.getpid()}")
    print(f"  Script  : {sys.argv[0]}")
    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Output  : {outfile}")
    print(f"\n  Severity labels:")
    print(f"    {RED}[RISK]{RST} = confirmed attack surface — act on these")
    print(f"    {YEL}[WARN]{RST} = notable — may be exploitable depending on context")
    print(f"    {GRN}[PASS]{RST} = check ran, result is secure")
    print(f"    {CYN}[INFO]{RST} = neutral, context for interpreting results")
    print(f"    {MAG}[NOTE]{RST} = explanation of what the check means")
    print(f"  ████████████████████████████████████████████████████")

    all_sections = [
        section_runtime,     # 1
        section_identity,    # 2
        section_capabilities,# 3
        section_privesc,     # 4
        section_filesystem,  # 5
        section_kernel,      # 6
        section_network,     # 7
        section_egress,      # 8
        section_environment, # 9
        section_credentials, # 10
        section_processes,   # 11
        section_lateral,     # 12
        section_tools,       # 13
    ]

    if args.sections:
        try:
            indices  = [int(x.strip()) - 1 for x in args.sections.split(',')]
            selected = [all_sections[i] for i in indices if 0 <= i < len(all_sections)]
        except ValueError:
            print(f"  [ERROR] Invalid --sections value: {args.sections!r}")
            sys.exit(1)
    else:
        selected = all_sections

    for fn in selected:
        try:
            fn()
        except KeyboardInterrupt:
            print(f"\n  {YEL}[INTERRUPTED]{RST}  Ctrl-C caught — printing partial summary")
            break
        except Exception as e:
            import traceback
            print(f"\n  {RED}[SECTION ERROR]{RST}  {fn.__name__}: {e}")
            traceback.print_exc()

    print_summary()
    print(f"\n=== AUDIT END {datetime.datetime.now()} ===")
    print(f"Output saved to: {outfile}")

    if fh:
        sys.stdout = real_stdout
        fh.close()


if __name__ == '__main__':
    main()
