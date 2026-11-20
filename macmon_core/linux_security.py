"""Linux security audit for AegisForge (`aegis security` on Linux).

Read-only by default. Every check reads files or runs a read-only command
through a ``Host`` object, so the whole audit runs against a FAKE root in the
tests (no real /etc, /sys or /proc is touched there). Nothing is ever changed
unless the caller passes ``--apply``, and even then only the low-risk fixes in
``fix_plan`` run (never SSH or firewall: a wrong edit there locks the owner out).

Each check returns a dict::

    {"id", "name", "status": pass|warn|fail|unknown, "detail", "fix_hint",
     "items": [...], "weight": int, "source": str}

``unknown`` means "could not be read as this user" (most often: needs root).
It costs no points but is counted in ``coverage`` so a half-blind audit never
reads as a confident 100/100.
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess

STATUS_ORDER = {"fail": 0, "warn": 1, "unknown": 2, "pass": 3}

# Ports that are a red flag when reachable from the network (same table as the
# macOS scan, kept local so this module imports without rich/psutil).
SUSPICIOUS_PORTS = {
    4444: "Metasploit default", 6666: "IRC botnet", 6667: "IRC botnet",
    1337: "Common backdoor", 31337: "Back Orifice", 12345: "NetBus trojan",
    27374: "SubSeven trojan",
}

SECUREBOOT_VAR = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"


# ── What the audit reads (injectable) ─────────────────────────────────────

class Host:
    """The machine as the audit sees it.

    ``root`` prefixes every file path (tests point it at a temp dir), ``run``
    executes a read-only command and returns ``(rc, stdout, stderr)``,
    ``which`` resolves a binary. Defaults are the real machine."""

    def __init__(self, root: str = "/", run=None, which=None, env_path: str | None = None,
                 euid: int | None = None):
        self.root = root
        self._run = run
        self._which = which
        self.env_path = os.environ.get("PATH", "") if env_path is None else env_path
        self.euid = os.geteuid() if euid is None and hasattr(os, "geteuid") else (euid or 0)

    # files
    def p(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def read(self, path: str, default: str | None = None) -> str | None:
        try:
            with open(self.p(path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return default

    def read_bytes(self, path: str) -> bytes | None:
        try:
            with open(self.p(path), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(self.p(path))

    def readable(self, path: str) -> bool:
        return os.access(self.p(path), os.R_OK)

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(self.p(path)))
        except OSError:
            return []

    def glob(self, pattern: str) -> list[str]:
        """Glob under root; returns paths WITHOUT the root prefix."""
        base = self.p(pattern)
        out = []
        for m in sorted(glob.glob(base)):
            rel = os.path.relpath(m, self.root)
            out.append("/" + rel.replace(os.sep, "/"))
        return out

    def lstat(self, path: str):
        try:
            return os.lstat(self.p(path))
        except OSError:
            return None

    def stat(self, path: str):
        try:
            return os.stat(self.p(path))
        except OSError:
            return None

    # commands
    def which(self, name: str) -> str | None:
        if self._which is not None:
            return self._which(name)
        return shutil.which(name)

    def cmd(self, argv: list[str], timeout: float = 20) -> tuple[int, str, str]:
        if self._run is not None:
            return self._run(argv)
        if not self.which(argv[0]):
            return 127, "", f"{argv[0]}: not found"
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                               stdin=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C", LANG="C"))
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        except OSError as e:
            return 126, "", str(e)


def _chk(cid, name, status, detail, fix_hint="", items=None, weight=5, source=""):
    return {"id": cid, "name": name, "status": status, "detail": detail, "fix_hint": fix_hint,
            "items": list(items or []), "weight": weight, "source": source}


def _permission_error(rc: int, out: str, err: str) -> bool:
    t = (out + " " + err).lower()
    return rc != 0 and ("operation not permitted" in t or "permission denied" in t
                        or "must be root" in t or "you need to be root" in t)


# ── 1. Firewall (nftables / ufw / firewalld) ──────────────────────────────

_NFT_INPUT_RE = re.compile(r"hook\s+input\b[^;\n]*;\s*policy\s+(\w+)", re.I)


def parse_nft_json(text: str) -> list[dict]:
    """`nft -j list ruleset` -> [{table, family, policy, rules}] for every
    filter chain hooked on INPUT."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    items = data.get("nftables", []) if isinstance(data, dict) else []
    chains, rules = [], {}
    for it in items:
        if not isinstance(it, dict):
            continue
        ch = it.get("chain")
        if isinstance(ch, dict) and ch.get("hook") == "input" and ch.get("type", "filter") == "filter":
            chains.append({"family": ch.get("family"), "table": ch.get("table"), "name": ch.get("name"),
                           "policy": (ch.get("policy") or "accept").lower()})
        r = it.get("rule")
        if isinstance(r, dict):
            k = (r.get("family"), r.get("table"), r.get("chain"))
            rules[k] = rules.get(k, 0) + 1
    for c in chains:
        c["rules"] = rules.get((c["family"], c["table"], c["name"]), 0)
    return chains


def parse_nft_conf(text: str) -> list[str]:
    """Policies of every `hook input` chain declared in an nftables.conf."""
    return [m.lower() for m in _NFT_INPUT_RE.findall(text or "")]


def check_firewall(h: Host) -> dict:
    name, cid, w = "Firewall", "firewall", 20
    hint_none = ("Enable a default-deny input policy (nftables `policy drop` on the input hook, "
                 "or `sudo ufw default deny incoming && sudo ufw enable`) -- keep your SSH port open first")
    live = None
    if h.which("nft"):
        rc, out, err = h.cmd(["nft", "-j", "list", "ruleset"])
        if rc == 0:
            live = parse_nft_json(out)
    if live is not None and live:
        closed = [c for c in live if c["policy"] in ("drop", "reject")]
        if closed:
            c = closed[0]
            return _chk(cid, name, "pass", f"nftables: input policy {c['policy']} "
                        f"({c['family']} {c['table']}, {c['rules']} rule(s))", weight=w, source="nft live")
        return _chk(cid, name, "warn", f"nftables input chain(s) accept by default "
                    f"({sum(c['rules'] for c in live)} rule(s))", hint_none, weight=w, source="nft live")
    # ufw
    ufw_conf = h.read("/etc/ufw/ufw.conf") or ""
    if re.search(r"^\s*ENABLED\s*=\s*yes", ufw_conf, re.M):
        pol = re.search(r'^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(\w+)', h.read("/etc/default/ufw") or "", re.M)
        p = (pol.group(1) if pol else "DROP").lower()
        st = "pass" if p in ("drop", "reject") else "warn"
        return _chk(cid, name, st, f"ufw enabled, default input {p}", "" if st == "pass" else hint_none,
                    weight=w, source="ufw config")
    # firewalld
    if h.which("firewall-cmd"):
        rc, out, _ = h.cmd(["firewall-cmd", "--state"])
        if rc == 0 and out.strip() == "running":
            return _chk(cid, name, "pass", "firewalld running", weight=w, source="firewalld")
    # nftables.conf (readable as any user) + the service that loads it
    conf_pols = parse_nft_conf(h.read("/etc/nftables.conf") or "")
    enabled = False
    if conf_pols:
        rc, out, _ = h.cmd(["systemctl", "is-enabled", "nftables"])
        enabled = out.strip() == "enabled"
    if live is not None and not live:
        # we COULD read the live ruleset and there is no input chain at all
        return _chk(cid, name, "fail", "no input filtering in the live ruleset", hint_none, weight=w,
                    source="nft live")
    if conf_pols:
        drop = any(p in ("drop", "reject") for p in conf_pols)
        if drop and enabled:
            return _chk(cid, name, "pass", "nftables.conf: input policy drop, loaded at boot "
                        "(live ruleset needs root to read)", weight=w, source="nftables.conf")
        if drop:
            return _chk(cid, name, "warn", "nftables.conf has a drop policy but the nftables service "
                        "is not enabled", "sudo systemctl enable --now nftables", weight=w, source="nftables.conf")
        return _chk(cid, name, "warn", "nftables.conf input policy accepts by default", hint_none, weight=w,
                    source="nftables.conf")
    if h.euid != 0:
        return _chk(cid, name, "warn", "no firewall configuration found (nftables.conf, ufw, firewalld); "
                    "run as root to read the live ruleset", hint_none, weight=w, source="config")
    return _chk(cid, name, "fail", "no firewall: no input filtering configured", hint_none, weight=w,
                source="nft live")


# ── 2. Listening sockets ──────────────────────────────────────────────────

_SS_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def _split_addr(addr: str) -> tuple[str, int | None]:
    host, _, port = addr.rpartition(":")
    host = host.strip("[]")
    host = host.split("%", 1)[0]
    try:
        return host, int(port)
    except ValueError:
        return host, None


def _exposed(host: str) -> bool:
    if host in ("*", "", "0.0.0.0", "::"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_loopback or ip.is_multicast)


def parse_ss(text: str) -> list[dict]:
    """`ss -H -ltnup` -> [{proto, addr, port, exposed, process, pid}]."""
    out = []
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto, state = f[0], f[1]
        if not ((proto == "tcp" and state == "LISTEN") or (proto == "udp" and state == "UNCONN")):
            continue
        host, port = _split_addr(f[4])
        if port is None:
            continue
        m = _SS_PROC_RE.search(line)
        out.append({"proto": proto, "addr": host or "*", "port": port, "exposed": _exposed(host),
                    "process": m.group(1) if m else "", "pid": int(m.group(2)) if m else None})
    return out


def check_listening(h: Host, firewall_closed: bool) -> dict:
    name, cid, w = "Listening Ports", "listening", 10
    rc, out, err = h.cmd(["ss", "-H", "-ltnup"])
    if rc != 0:
        return _chk(cid, name, "unknown", "ss unavailable: cannot list listening sockets", weight=w, source="ss")
    socks = parse_ss(out)
    exposed = [s for s in socks if s["exposed"]]
    seen, items = set(), []
    for s in exposed:
        key = (s["proto"], s["addr"], s["port"])
        if key in seen:
            continue
        seen.add(key)
        who = f"{s['process']} (pid {s['pid']})" if s["process"] else "owner hidden (needs root)"
        items.append(f"{s['proto']} {s['addr']}:{s['port']} -- {who}")
    bad = [s for s in exposed if s["port"] in SUSPICIOUS_PORTS]
    detail = f"{len(socks)} listening, {len(seen)} reachable beyond loopback"
    if bad:
        return _chk(cid, name, "fail", detail + "; suspicious port(s): " +
                    ", ".join(f"{s['port']} ({SUSPICIOUS_PORTS[s['port']]})" for s in bad),
                    "Identify and stop the process bound to the suspicious port", items, w, "ss")
    if seen and not firewall_closed:
        return _chk(cid, name, "warn", detail + " and no default-deny firewall in front of them",
                    "Bind services to 127.0.0.1, or enable a default-deny firewall", items, w, "ss")
    if seen:
        detail += " (filtered by the default-deny firewall)"
    return _chk(cid, name, "pass", detail, "", items, w, "ss")


# ── 3. SSH server ─────────────────────────────────────────────────────────

SSHD_DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
                 "kbdinteractiveauthentication": "yes", "permitemptypasswords": "no"}


def sshd_effective(h: Host, path: str = "/etc/ssh/sshd_config") -> tuple[dict, int]:
    """Global sshd settings as sshd resolves them: FIRST value wins, Include is
    expanded in place (relative to /etc/ssh), a Match block runs to the end of
    its file. Returns (settings, number of Match blocks seen)."""
    vals: dict[str, str] = {}
    matches = [0]

    def parse(p: str, depth: int):
        if depth > 8:
            return
        text = h.read(p)
        if text is None:
            return
        in_match = False
        for raw in text.splitlines():
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            parts = re.split(r"[\s=]+", s, maxsplit=1)
            k = parts[0].lower()
            v = parts[1].strip() if len(parts) > 1 else ""
            if k == "match":
                in_match = True
                matches[0] += 1
                continue
            if in_match:
                continue
            if k == "include":
                for pat in v.split():
                    pat = pat if pat.startswith("/") else "/etc/ssh/" + pat
                    for f in h.glob(pat):
                        parse(f, depth + 1)
                continue
            vals.setdefault(k, v.split()[0].lower() if v else "")

    parse(path, 0)
    return vals, matches[0]


def _sshd_running(h: Host) -> bool | None:
    for unit in ("ssh", "sshd"):
        rc, out, _ = h.cmd(["systemctl", "is-active", unit])
        if out.strip() == "active":
            return True
    return False if h.which("systemctl") else None


def check_ssh(h: Host) -> dict:
    name, cid, w = "SSH Server", "ssh", 15
    if not h.exists("/etc/ssh/sshd_config") and not h.exists("/usr/sbin/sshd"):
        return _chk(cid, name, "pass", "OpenSSH server not installed", weight=w, source="sshd_config")
    if not h.readable("/etc/ssh/sshd_config"):
        return _chk(cid, name, "unknown", "sshd_config not readable as this user", weight=w, source="sshd_config")
    vals, nmatch = sshd_effective(h)
    eff = dict(SSHD_DEFAULTS)
    eff.update({k: v for k, v in vals.items() if k in SSHD_DEFAULTS})
    running = _sshd_running(h)
    state = "running" if running else ("not running" if running is False else "state unknown")
    notes = [f"sshd {state}", f"PermitRootLogin {eff['permitrootlogin']}",
             f"PasswordAuthentication {eff['passwordauthentication']}"]
    if nmatch:
        notes.append(f"{nmatch} Match block(s) override settings for some clients (not scored)")
    detail = "; ".join(notes)
    if eff["permitemptypasswords"] == "yes":
        return _chk(cid, name, "fail", detail + "; EMPTY passwords allowed", "Set `PermitEmptyPasswords no`",
                    weight=w, source="sshd_config")
    if eff["permitrootlogin"] == "yes":
        return _chk(cid, name, "fail", detail, "Set `PermitRootLogin prohibit-password` (keys only) or `no`",
                    weight=w, source="sshd_config")
    pw = eff["passwordauthentication"] == "yes" or eff["kbdinteractiveauthentication"] == "yes"
    if pw and running is not False:
        return _chk(cid, name, "warn", detail + "; passwords accepted",
                    "Use keys only: `PasswordAuthentication no` + `KbdInteractiveAuthentication no` "
                    "(check your key login works first)", weight=w, source="sshd_config")
    return _chk(cid, name, "pass", detail, weight=w, source="sshd_config")


# ── 4. Mandatory access control (AppArmor / SELinux) ──────────────────────

def check_mac(h: Host) -> dict:
    name, cid, w = "AppArmor / SELinux", "apparmor", 10
    aa = h.read("/sys/module/apparmor/parameters/enabled")
    if aa is not None:
        if aa.strip().upper().startswith("Y"):
            prof = h.read("/sys/kernel/security/apparmor/profiles")
            if prof is not None:
                enf = sum(1 for l in prof.splitlines() if l.rstrip().endswith("(enforce)"))
                cmp_ = sum(1 for l in prof.splitlines() if l.rstrip().endswith("(complain)"))
                return _chk(cid, name, "pass", f"AppArmor enabled: {enf} profile(s) enforced, {cmp_} complain",
                            weight=w, source="apparmor")
            return _chk(cid, name, "pass", "AppArmor enabled (profile list needs root)", weight=w, source="apparmor")
        return _chk(cid, name, "fail", "AppArmor is built in but disabled",
                    "Remove `apparmor=0` from the kernel command line and install apparmor", weight=w,
                    source="apparmor")
    se = h.read("/sys/fs/selinux/enforce")
    if se is not None:
        if se.strip() == "1":
            return _chk(cid, name, "pass", "SELinux enforcing", weight=w, source="selinux")
        return _chk(cid, name, "warn", "SELinux permissive", "sudo setenforce 1 (and SELINUX=enforcing)",
                    weight=w, source="selinux")
    return _chk(cid, name, "warn", "no mandatory access control (AppArmor or SELinux) active",
                "Install and enable AppArmor (`sudo apt install apparmor apparmor-profiles`)", weight=w,
                source="apparmor")


# ── 5. Updates (apt) ──────────────────────────────────────────────────────

_PERIODIC_RE = re.compile(r'APT::Periodic::(Unattended-Upgrade|Update-Package-Lists)\s+"(\d+)"')


def apt_periodic(h: Host) -> dict:
    """APT::Periodic values after apt's lexical-order override (last wins)."""
    vals = {}
    for f in h.listdir("/etc/apt/apt.conf.d"):
        text = h.read("/etc/apt/apt.conf.d/" + f) or ""
        for line in text.splitlines():
            s = line.split("//", 1)[0]
            for k, v in _PERIODIC_RE.findall(s):
                vals[k] = int(v)
    return vals


def parse_apt_sim(text: str) -> tuple[int, list[str]]:
    """`apt-get -s upgrade` -> (pending count, security package names)."""
    total, sec = 0, []
    for line in (text or "").splitlines():
        if not line.startswith("Inst "):
            continue
        total += 1
        if re.search(r"-security|Debian-Security|Ubuntu.*-security", line, re.I):
            sec.append(line.split()[1])
    return total, sec


def check_updates(h: Host, now: float | None = None) -> dict:
    import time as _t
    name, cid, w = "Security Updates", "updates", 15
    if not h.which("apt-get"):
        return _chk(cid, name, "unknown", "not an apt-based system (update check not implemented here)",
                    weight=w, source="apt")
    per = apt_periodic(h)
    auto = per.get("Unattended-Upgrade", 0) >= 1 and h.exists("/usr/bin/unattended-upgrade")
    rc, out, err = h.cmd(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=90)
    total, sec = parse_apt_sim(out) if rc == 0 else (None, [])
    newest = 0.0
    for f in h.glob("/var/lib/apt/lists/*Release"):
        st = h.stat(f)
        if st:
            newest = max(newest, st.st_mtime)
    age_d = ((now or _t.time()) - newest) / 86400 if newest else None
    notes = ["unattended-upgrades ON" if auto else "unattended-upgrades OFF"]
    if total is not None:
        notes.append(f"{total} upgradable, {len(sec)} security")
    else:
        notes.append("pending list unavailable")
    if age_d is not None:
        notes.append(f"package lists {age_d:.0f} day(s) old")
    detail = "; ".join(notes)
    hint = "sudo apt-get update && sudo apt-get upgrade" + ("" if auto else "; enable unattended-upgrades "
                                                            "(`aegis security --apply`)")
    if sec and not auto:
        return _chk(cid, name, "fail", detail, hint, sec[:20], w, "apt")
    if sec or not auto or (age_d is not None and age_d > 7):
        return _chk(cid, name, "warn", detail, hint, sec[:20], w, "apt")
    return _chk(cid, name, "pass", detail, "", [], w, "apt")


# ── 6. Disk encryption (LUKS) ─────────────────────────────────────────────

DATA_MOUNTS = ("/", "/home", "/persist")


def lsblk_mounts(text: str) -> dict:
    """lsblk -J tree -> {mountpoint: {"dev", "fstype", "encrypted"}} (encrypted =
    the device or one of its ancestors is a dm-crypt mapping)."""
    try:
        tree = json.loads(text).get("blockdevices", [])
    except (ValueError, AttributeError, TypeError):
        return {}
    out = {}

    def walk(node, crypt_above):
        crypt = crypt_above or node.get("type") == "crypt"
        mps = node.get("mountpoints")
        if mps is None:
            mps = [node.get("mountpoint")]
        for mp in mps or []:
            if mp and mp not in out:
                out[mp] = {"dev": node.get("name"), "fstype": node.get("fstype"), "encrypted": crypt}
        for c in node.get("children") or []:
            walk(c, crypt)

    for n in tree:
        walk(n, False)
    return out


def check_encryption(h: Host) -> dict:
    name, cid, w = "Disk Encryption", "encryption", 10
    rc, out, _ = h.cmd(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"])
    if rc != 0:
        rc, out, _ = h.cmd(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])
    if rc != 0:
        return _chk(cid, name, "unknown", "lsblk unavailable", weight=w, source="lsblk")
    mounts = lsblk_mounts(out)
    rows = [(mp, mounts[mp]) for mp in DATA_MOUNTS if mp in mounts]
    if not rows:
        return _chk(cid, name, "unknown", "root filesystem not found in lsblk", weight=w, source="lsblk")
    plain = [f"{mp} on {m['dev']} ({m['fstype'] or '?'}): not encrypted" for mp, m in rows if not m["encrypted"]]
    if not plain:
        return _chk(cid, name, "pass", "data filesystems on LUKS: " + ", ".join(mp for mp, _ in rows),
                    weight=w, source="lsblk")
    return _chk(cid, name, "warn", f"{len(plain)} of {len(rows)} data filesystem(s) unencrypted",
                "Use LUKS full-disk encryption at the next install (a lost or stolen disk is readable as is)",
                plain, w, "lsblk")


# ── 7. Failed logins (journal) ────────────────────────────────────────────

_FAIL_RE = re.compile(r"Failed password|Invalid user|authentication failure|incorrect password attempt|"
                      r"maximum authentication attempts", re.I)
_FROM_RE = re.compile(r"from (\S+) port")


def check_failed_logins(h: Host) -> dict:
    name, cid, w = "Failed Logins (24h)", "failed_logins", 5
    if not h.which("journalctl"):
        return _chk(cid, name, "unknown", "journalctl unavailable", weight=w, source="journal")
    # An unprivileged user outside adm / systemd-journal reads only its OWN
    # journal and journalctl says nothing about it (measured: no hint, rc 0,
    # empty output -- an empty result would read as "0 failed logins"). So
    # decide from the system journal files themselves.
    if h.euid != 0:
        sysj = h.glob("/var/log/journal/*/system*.journal") + h.glob("/run/log/journal/*/system*.journal")
        if not any(h.readable(f) for f in sysj):
            return _chk(cid, name, "unknown", "system journal not readable as this user "
                        "(root or the adm / systemd-journal group)", weight=w, source="journal")
    total, ips = 0, {}
    for comm in ("sshd", "sudo", "login"):
        rc, out, err = h.cmd(["journalctl", "--no-pager", "-o", "cat", "--since=-24h", f"_COMM={comm}"])
        if "not seeing messages from other users" in (out + err) or _permission_error(rc, out, err):
            return _chk(cid, name, "unknown", "system journal not readable as this user "
                        "(root or the adm / systemd-journal group)", weight=w, source="journal")
        if rc != 0:
            continue
        for line in out.splitlines():
            if _FAIL_RE.search(line):
                total += 1
                m = _FROM_RE.search(line)
                if m:
                    ips[m.group(1)] = ips.get(m.group(1), 0) + 1
    top = sorted(ips.items(), key=lambda kv: -kv[1])[:5]
    items = [f"{ip}: {n} attempt(s)" for ip, n in top]
    detail = f"{total} failed login attempt(s) in 24 h"
    if total >= 200:
        return _chk(cid, name, "fail", detail + " -- looks like brute force",
                    "Block the sources (fail2ban) and make SSH key-only", items, w, "journal")
    if total >= 20:
        return _chk(cid, name, "warn", detail, "Review the sources; consider fail2ban", items, w, "journal")
    return _chk(cid, name, "pass", detail, "", items, w, "journal")


# ── 8. sudoers drop-ins ───────────────────────────────────────────────────

def check_sudoers(h: Host) -> dict:
    name, cid, w = "sudoers", "sudoers", 5
    bad, notes, nopass = [], [], []
    files = [("/etc/sudoers", h.lstat("/etc/sudoers"))] + \
        [("/etc/sudoers.d/" + f, h.lstat("/etc/sudoers.d/" + f)) for f in h.listdir("/etc/sudoers.d")]
    if files[0][1] is None and len(files) == 1:
        return _chk(cid, name, "pass", "sudo not configured", weight=w, source="sudoers")
    unreadable = 0
    for path, st in files:
        if st is None:
            continue
        base = os.path.basename(path)
        if path.startswith("/etc/sudoers.d/") and ("." in base or base.endswith("~")):
            notes.append(f"{path}: ignored by sudo (name contains '.' or ends with '~')")
        if st.st_uid != 0:
            bad.append(f"{path}: owned by uid {st.st_uid}, not root")
        if st.st_mode & 0o022:
            bad.append(f"{path}: mode {stat.S_IMODE(st.st_mode):04o} is group/world writable (want 0440)")
        text = h.read(path)
        if text is None:
            unreadable += 1
            continue
        for line in text.splitlines():
            s = line.split("#", 1)[0].strip()
            if re.search(r"NOPASSWD:\s*ALL\s*$", s) and re.search(r"=\s*\(\s*(ALL|root)", s):
                nopass.append(f"{path}: {s}")
    detail = f"{len(files)} file(s)"
    if unreadable:
        detail += f", {unreadable} unreadable as this user (content needs root)"
    if bad:
        return _chk(cid, name, "fail", detail + "; unsafe ownership/mode",
                    "sudo chown root:root <file> && sudo chmod 0440 <file> (`aegis security --apply`)",
                    bad + notes, w, "sudoers")
    if nopass:
        return _chk(cid, name, "warn", detail + f"; {len(nopass)} rule(s) grant every command without a password",
                    "Restrict NOPASSWD to the exact commands that need it", nopass + notes, w, "sudoers")
    return _chk(cid, name, "pass", detail, "", notes, w, "sudoers")


# ── 9. World-writable directories in PATH ─────────────────────────────────

def check_path(h: Host) -> dict:
    name, cid, w = "PATH Integrity", "path", 5
    bad, warn = [], []
    for d in (h.env_path or "").split(os.pathsep):
        if d in ("", ".") or not d.startswith("/"):
            warn.append(f"'{d or '(empty)'}': relative entry (runs whatever is in the current directory)")
            continue
        st = h.stat(d)
        if st is None or not stat.S_ISDIR(st.st_mode):
            continue
        if st.st_mode & stat.S_IWOTH:
            if st.st_mode & stat.S_ISVTX:
                warn.append(f"{d}: world-writable (sticky)")
            else:
                bad.append(f"{d}: world-writable -- anyone can plant a command here")
    n = len((h.env_path or "").split(os.pathsep))
    if bad:
        return _chk(cid, name, "fail", f"{len(bad)} world-writable director(y/ies) in PATH",
                    "chmod o-w on those directories (`aegis security --apply`)", bad + warn, w, "PATH")
    if warn:
        return _chk(cid, name, "warn", f"{len(warn)} risky PATH entr(y/ies)", "Remove them from PATH",
                    warn, w, "PATH")
    return _chk(cid, name, "pass", f"{n} PATH entries, none writable by others", weight=w, source="PATH")


# ── 10. Secure Boot + kernel lockdown ─────────────────────────────────────

def secure_boot_state(h: Host) -> bool | None:
    if not h.exists("/sys/firmware/efi"):
        return None
    raw = h.read_bytes("/" + SECUREBOOT_VAR)
    if not raw or len(raw) < 5:
        return False
    return raw[4] == 1


def check_boot(h: Host) -> dict:
    name, cid, w = "Secure Boot / Lockdown", "secureboot", 5
    lock = h.read("/sys/kernel/security/lockdown")
    mode = None
    if lock:
        m = re.search(r"\[(\w+)\]", lock)
        mode = m.group(1) if m else None
    sb = secure_boot_state(h)
    lk = f"kernel lockdown: {mode}" if mode else "kernel lockdown: unavailable"
    if sb is None:
        return _chk(cid, name, "warn", "legacy BIOS boot (no Secure Boot); " + lk,
                    "Boot in UEFI mode with Secure Boot to block unsigned boot code", weight=w, source="efi")
    if sb:
        return _chk(cid, name, "pass", "Secure Boot enabled; " + lk, weight=w, source="efi")
    return _chk(cid, name, "warn", "Secure Boot disabled; " + lk,
                "Enable Secure Boot in the firmware setup (needs a signed shim + kernel)", weight=w, source="efi")


# ── 11. fail2ban ──────────────────────────────────────────────────────────

def check_fail2ban(h: Host, ssh: dict, listening: dict) -> dict:
    name, cid, w = "fail2ban", "fail2ban", 5
    if h.which("fail2ban-client") or h.exists("/usr/bin/fail2ban-server"):
        rc, out, _ = h.cmd(["systemctl", "is-active", "fail2ban"])
        if out.strip() == "active":
            return _chk(cid, name, "pass", "installed and running", weight=w, source="fail2ban")
        return _chk(cid, name, "warn", "installed but not running", "sudo systemctl enable --now fail2ban",
                    weight=w, source="fail2ban")
    ssh_exposed = any(":22 " in (i + " ") or "sshd" in i for i in listening.get("items", []))
    pw = "passwords accepted" in ssh.get("detail", "")
    if ssh_exposed and pw:
        return _chk(cid, name, "warn", "not installed while SSH accepts passwords from the network",
                    "sudo apt install fail2ban (or make SSH key-only)", weight=w, source="fail2ban")
    return _chk(cid, name, "pass", "not installed (not needed: SSH is key-only or not exposed)", weight=w,
                source="fail2ban")


# ── 12/13. Processes (shared with the macOS scan, psutil-based) ───────────

def check_processes() -> list[dict]:
    try:
        from .security import _find_remote_tools, _find_suspicious_processes
    except Exception:
        return []
    out = []
    try:
        sus = _find_suspicious_processes()
        out.append(_chk("processes", "Suspicious Processes", "fail" if sus else "pass",
                        f"{len(sus)} suspicious process(es)" if sus else "None found",
                        "Inspect and stop them (`aegis ps`)", sus, 15, "psutil"))
    except Exception:
        pass
    try:
        rt = _find_remote_tools()
        out.append(_chk("remote_tools", "Remote Access Tools", "warn" if rt else "pass",
                        f"{len(rt)} remote tool(s) running" if rt else "None running",
                        "Close remote-access tools you are not using", rt, 5, "psutil"))
    except Exception:
        pass
    return out


# ── The audit ─────────────────────────────────────────────────────────────

def score(checks: list[dict]) -> int:
    s = 100
    for c in checks:
        if c["status"] == "fail":
            s -= c.get("weight", 5)
        elif c["status"] == "warn":
            s -= c.get("weight", 5) // 2
    return max(0, s)


def audit(h: Host | None = None, with_processes: bool = True) -> dict:
    """Run every check; returns {score, coverage, checks, findings, root}."""
    h = h or Host()
    fw = check_firewall(h)
    lst = check_listening(h, fw["status"] == "pass")
    ssh = check_ssh(h)
    checks = [fw, lst, ssh, check_mac(h), check_updates(h), check_encryption(h), check_failed_logins(h),
              check_sudoers(h), check_path(h), check_boot(h), check_fail2ban(h, ssh, lst)]
    if with_processes:
        checks += check_processes()
    known = [c for c in checks if c["status"] != "unknown"]
    return {"platform": "Linux", "score": score(checks), "coverage": f"{len(known)}/{len(checks)}",
            "root": h.euid == 0, "checks": checks,
            # the macOS scan's shape, so app/webui consumers read both the same way
            "findings": [{"name": c["name"], "status": c["status"], "detail": c["detail"],
                          "fix_hint": c["fix_hint"], "items": c["items"]} for c in checks]}


# ── --apply: the LOW-RISK fixes only ──────────────────────────────────────

AUTO_UPGRADES_FILE = "/etc/apt/apt.conf.d/20auto-upgrades"
AUTO_UPGRADES_TEXT = ('APT::Periodic::Update-Package-Lists "1";\n'
                      'APT::Periodic::Unattended-Upgrade "1";\n')


def fix_plan(result: dict, h: Host | None = None) -> list[dict]:
    """What `--apply` would change. Each step: {id, what, undo, kind, args}.
    SSH and firewall are NEVER here: a wrong edit locks the owner out, so they
    stay as hints for a human."""
    h = h or Host()
    plan = []
    by = {c["id"]: c for c in result.get("checks", [])}
    up = by.get("updates")
    if up and "unattended-upgrades OFF" in up["detail"] and h.exists("/usr/bin/unattended-upgrade"):
        plan.append({"id": "updates", "kind": "write", "args": [AUTO_UPGRADES_FILE, AUTO_UPGRADES_TEXT],
                     "what": f"enable unattended security upgrades ({AUTO_UPGRADES_FILE})",
                     "undo": f"restore {AUTO_UPGRADES_FILE}.aegis-bak (or delete the file)"})
    pth = by.get("path")
    if pth and pth["status"] == "fail":
        for it in pth["items"]:
            if "world-writable --" in it:
                d = it.split(":", 1)[0]
                st = h.stat(d)
                old = f"{stat.S_IMODE(st.st_mode):04o}" if st else "?"
                plan.append({"id": "path", "kind": "chmod_o-w", "args": [d], "what": f"chmod o-w {d}",
                             "undo": f"chmod {old} {d}"})
    sud = by.get("sudoers")
    if sud and sud["status"] == "fail":
        for it in sud["items"]:
            if "group/world writable" in it or "not root" in it:
                f = it.split(":", 1)[0]
                if any(s["args"] == [f] for s in plan if s["id"] == "sudoers"):
                    continue
                st = h.stat(f)
                old = f"{stat.S_IMODE(st.st_mode):04o} uid {st.st_uid}" if st else "?"
                plan.append({"id": "sudoers", "kind": "sudoers_fix", "args": [f],
                             "what": f"chown root:root + chmod 0440 {f}", "undo": f"was {old}"})
    return plan


def apply_plan(plan: list[dict], h: Host | None = None) -> list[str]:
    """Execute a fix plan. Requires root; returns one line per step."""
    h = h or Host()
    if h.euid != 0:
        return ["refused: --apply needs root (run it with sudo)"]
    out = []
    for step in plan:
        try:
            if step["kind"] == "write":
                path, text = step["args"]
                real = h.p(path)
                if os.path.exists(real):
                    shutil.copy2(real, real + ".aegis-bak")
                with open(real, "w", encoding="utf-8") as fh:
                    fh.write(text)
            elif step["kind"] == "chmod_o-w":
                real = h.p(step["args"][0])
                os.chmod(real, stat.S_IMODE(os.stat(real).st_mode) & ~stat.S_IWOTH)
            elif step["kind"] == "sudoers_fix":
                real = h.p(step["args"][0])
                os.chown(real, 0, 0)
                os.chmod(real, 0o440)
            out.append(f"done: {step['what']}  (undo: {step['undo']})")
        except OSError as e:
            out.append(f"FAILED: {step['what']}: {e}")
    return out


# ── CLI ───────────────────────────────────────────────────────────────────

def _only(result: dict, ids: tuple[str, ...]) -> dict:
    r = dict(result)
    r["checks"] = [c for c in result["checks"] if c["id"] in ids]
    return r


def run(scan: bool = True, json_out: bool = False, apply: bool = False, only: tuple[str, ...] = ()):
    result = audit(with_processes=not only or bool(set(only) & {"processes", "remote_tools"}))
    if only:
        result = _only(result, only)
    plan = fix_plan(result)
    if json_out:
        result = dict(result, fix_plan=plan)
        if apply:
            result["applied"] = apply_plan(plan)
        print(json.dumps(result, default=str))
        return result
    from rich.table import Table
    from .utils import console
    col = "green" if result["score"] >= 80 else "yellow" if result["score"] >= 50 else "red"
    t = Table(title=f"Security Score: {result['score']}/100  (checked {result['coverage']})", border_style=col)
    t.add_column("Check", style="cyan", width=24)
    t.add_column("Status", width=8)
    t.add_column("Details", overflow="fold")
    lab = {"pass": "[green]PASS[/]", "warn": "[yellow]WARN[/]", "fail": "[red]FAIL[/]", "unknown": "[dim]N/A[/]"}
    for c in sorted(result["checks"], key=lambda c: STATUS_ORDER.get(c["status"], 9)):
        t.add_row(c["name"], lab.get(c["status"], "?"), c["detail"])
    console.print(t)
    for c in result["checks"]:
        if c["items"] and c["status"] in ("fail", "warn"):
            console.print(f"\n[bold]{c['name']}:[/]")
            for it in c["items"][:12]:
                console.print(f"  > {it}", markup=False)
    hints = [c for c in result["checks"] if c["status"] in ("fail", "warn") and c["fix_hint"]]
    if hints:
        console.print("\n[bold]Fixes:[/]")
        for i, c in enumerate(hints, 1):
            console.print(f"  {i}. {c['name']}: {c['fix_hint']}", markup=False)
    if any(c["status"] == "unknown" for c in result["checks"]) and not result["root"]:
        console.print("\n[dim]Some checks need root to read (N/A). `sudo aegis security --scan` reads them all.[/]")
    if plan:
        console.print("\n[bold]`--apply` would change (low-risk fixes only; SSH and firewall are never automatic):[/]")
        for s in plan:
            console.print(f"  - {s['what']}   [dim](undo: {s['undo']})[/]")
        if apply:
            for line in apply_plan(plan):
                console.print("  " + line, markup=False)
    elif apply:
        console.print("\n[green]Nothing to apply automatically.[/]")
    return result
