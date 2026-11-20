"""Linux parity: security audit, startup / uninstall, health rows, the guard
(safe autonomous remediation) and the systemd --user scheduler.

Every Linux path is FAKED: a temp directory stands in for /, a dict stands in
for the commands. Nothing here reads the real /etc, /sys or /proc, and no real
process is ever signalled -- so the suite runs identically on macOS, Linux and
Windows runners.
"""
import json
import os
import stat
import sys

import pytest

from macmon_core import guard, linux_security as ls, linux_system as lsys

POSIX = os.name == "posix"


# ── fakes ────────────────────────────────────────────────────────────────

def make_host(tmp_path, files=None, cmds=None, euid=1000, path_env="/usr/bin:/bin", which=None):
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    for rel, content in (files or {}).items():
        p = root / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
    cmds = dict(cmds or {})

    def run(argv):
        for n in range(len(argv), 0, -1):
            k = tuple(argv[:n])
            if k in cmds:
                return cmds[k]
        return (127, "", f"{argv[0]}: not found")

    def _which(name):
        if which is not None:
            return which(name)
        return f"/usr/bin/{name}" if any(k[0] == name for k in cmds) else None

    return ls.Host(root=str(root), run=run, which=_which, env_path=path_env, euid=euid)


NFT_DROP = json.dumps({"nftables": [
    {"metainfo": {"version": "1.1"}},
    {"table": {"family": "inet", "name": "filter", "handle": 1}},
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter",
               "hook": "input", "prio": 0, "policy": "drop"}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": []}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "expr": []}},
]})
NFT_ACCEPT = NFT_DROP.replace('"policy": "drop"', '"policy": "accept"')


# ── firewall ─────────────────────────────────────────────────────────────

def test_firewall_live_drop_passes(tmp_path):
    h = make_host(tmp_path, cmds={("nft", "-j", "list"): (0, NFT_DROP, "")})
    c = ls.check_firewall(h)
    assert c["status"] == "pass" and "drop" in c["detail"] and "2 rule" in c["detail"]


def test_firewall_live_accept_warns(tmp_path):
    h = make_host(tmp_path, cmds={("nft", "-j", "list"): (0, NFT_ACCEPT, "")})
    assert ls.check_firewall(h)["status"] == "warn"


def test_firewall_nonroot_reads_config_and_service(tmp_path):
    conf = "table inet f {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}\n"
    cmds = {("nft", "-j", "list"): (1, "", "Operation not permitted"),
            ("systemctl", "is-enabled", "nftables"): (0, "enabled\n", "")}
    h = make_host(tmp_path, files={"/etc/nftables.conf": conf}, cmds=cmds)
    c = ls.check_firewall(h)
    assert c["status"] == "pass" and c["source"] == "nftables.conf"
    # same file, service disabled: a drop policy that never loads is NOT a firewall
    cmds[("systemctl", "is-enabled", "nftables")] = (1, "disabled\n", "")
    h = make_host(tmp_path, files={"/etc/nftables.conf": conf}, cmds=cmds)
    assert ls.check_firewall(h)["status"] == "warn"


def test_firewall_nothing_root_fails_nonroot_warns(tmp_path):
    h = make_host(tmp_path, cmds={("nft", "-j", "list"): (0, json.dumps({"nftables": []}), "")}, euid=0)
    assert ls.check_firewall(h)["status"] == "fail"
    h = make_host(tmp_path, cmds={}, euid=1000)
    c = ls.check_firewall(h)
    assert c["status"] == "warn" and "root" in c["detail"]


def test_firewall_ufw(tmp_path):
    h = make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=yes\n",
                                   "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="DROP"\n'})
    assert ls.check_firewall(h)["status"] == "pass"
    h = make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=yes\n",
                                   "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="ACCEPT"\n'})
    assert ls.check_firewall(h)["status"] == "warn"


# ── listening sockets ────────────────────────────────────────────────────

SS = """\
udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:* users:(("chrome",pid=10,fd=1))
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=11,fd=2))
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=12,fd=3))
tcp LISTEN 0 128 127.0.0.1:9111 0.0.0.0:* users:(("python3",pid=13,fd=4))
tcp LISTEN 0 128 [::1]:631 [::]:*
tcp LISTEN 0 128 *:8080 *:*
"""


def test_parse_ss_exposure():
    rows = ls.parse_ss(SS)
    exp = {(r["addr"], r["port"]) for r in rows if r["exposed"]}
    assert exp == {("0.0.0.0", 22), ("*", 8080)}          # multicast + loopback are not exposure
    assert {r["process"] for r in rows if r["port"] == 22} == {"sshd"}


def test_listening_status(tmp_path):
    h = make_host(tmp_path, cmds={("ss", "-H", "-ltnup"): (0, SS, "")})
    assert ls.check_listening(h, firewall_closed=True)["status"] == "pass"
    assert ls.check_listening(h, firewall_closed=False)["status"] == "warn"
    bad = SS + 'tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=99,fd=3))\n'
    h = make_host(tmp_path, cmds={("ss", "-H", "-ltnup"): (0, bad, "")})
    c = ls.check_listening(h, firewall_closed=True)
    assert c["status"] == "fail" and "4444" in c["detail"]


# ── SSH ──────────────────────────────────────────────────────────────────

def _ssh_cmds(active=True):
    return {("systemctl", "is-active", "ssh"): (0 if active else 3, "active\n" if active else "inactive\n", "")}


def test_sshd_first_value_wins_and_match_ends_at_eof(tmp_path):
    files = {
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
                                "PasswordAuthentication yes\n",
        # a Match block inside an included file must not swallow the next file
        "/etc/ssh/sshd_config.d/05-lan.conf": "Match Address 10.0.0.0/8\n    PermitRootLogin prohibit-password\n",
        "/etc/ssh/sshd_config.d/50-site.conf": "PasswordAuthentication no\nPermitRootLogin no\n"
                                               "KbdInteractiveAuthentication no\n",
    }
    h = make_host(tmp_path, files=files, cmds=_ssh_cmds())
    vals, nmatch = ls.sshd_effective(h)
    assert vals["permitrootlogin"] == "no" and vals["passwordauthentication"] == "no" and nmatch == 1
    c = ls.check_ssh(h)
    assert c["status"] == "pass" and "Match" in c["detail"]


def test_ssh_root_login_fails_and_passwords_warn(tmp_path):
    h = make_host(tmp_path, files={"/etc/ssh/sshd_config": "PermitRootLogin yes\n"}, cmds=_ssh_cmds())
    assert ls.check_ssh(h)["status"] == "fail"
    # OpenSSH default: passwords ON -> warn while sshd runs
    h = make_host(tmp_path, files={"/etc/ssh/sshd_config": "# defaults\n"}, cmds=_ssh_cmds())
    assert ls.check_ssh(h)["status"] == "warn"
    h = make_host(tmp_path, files={"/etc/ssh/sshd_config": "PermitEmptyPasswords yes\n"}, cmds=_ssh_cmds())
    assert ls.check_ssh(h)["status"] == "fail"


def test_ssh_not_installed(tmp_path):
    assert ls.check_ssh(make_host(tmp_path))["status"] == "pass"


# ── MAC framework ────────────────────────────────────────────────────────

def test_apparmor(tmp_path):
    assert ls.check_mac(make_host(tmp_path, files={"/sys/module/apparmor/parameters/enabled": "Y\n"}))["status"] == "pass"
    assert ls.check_mac(make_host(tmp_path, files={"/sys/module/apparmor/parameters/enabled": "N\n"}))["status"] == "fail"
    prof = "/usr/bin/man (enforce)\nfoo (complain)\nbar (enforce)\n"
    c = ls.check_mac(make_host(tmp_path, files={"/sys/module/apparmor/parameters/enabled": "Y\n",
                                                "/sys/kernel/security/apparmor/profiles": prof}))
    assert "2 profile(s) enforced" in c["detail"]


def test_no_mac_framework_warns(tmp_path):
    assert ls.check_mac(make_host(tmp_path))["status"] == "warn"


# ── updates ──────────────────────────────────────────────────────────────

APT_SIM = """NOTE: This is only a simulation!
Inst openssl [3.5.1-1] (3.5.4-1~deb13u1 Debian-Security:13/stable-security [amd64])
Inst vim [2:9.1-1] (2:9.1-2 Debian:13/stable [amd64])
Conf openssl (3.5.4-1~deb13u1 Debian-Security:13/stable-security [amd64])
"""


def _apt_host(tmp_path, periodic, sim=APT_SIM, uu=True):
    tmp_path = tmp_path / f"apt{len(list(tmp_path.iterdir()))}"   # a fresh fake root per host
    tmp_path.mkdir()
    files = {f"/etc/apt/apt.conf.d/{k}": v for k, v in periodic.items()}
    if uu:
        files["/usr/bin/unattended-upgrade"] = "#!/bin/sh\n"
    files["/var/lib/apt/lists/deb.example_InRelease"] = "x"
    return make_host(tmp_path, files=files, cmds={("apt-get", "-s"): (0, sim, "")})


def test_apt_sim_parse():
    assert ls.parse_apt_sim(APT_SIM) == (2, ["openssl"])


def test_updates_lexical_override_and_status(tmp_path):
    on = {"20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";\n'}
    off_later = dict(on, **{"99local": 'APT::Periodic::Unattended-Upgrade "0";\n'})
    assert ls.apt_periodic(_apt_host(tmp_path, off_later))["Unattended-Upgrade"] == 0
    assert ls.check_updates(_apt_host(tmp_path, off_later))["status"] == "fail"     # security pending + auto off
    assert ls.check_updates(_apt_host(tmp_path, on))["status"] == "warn"            # pending, auto will take it
    clean = "NOTE: This is only a simulation!\n"
    assert ls.check_updates(_apt_host(tmp_path, on, sim=clean))["status"] == "pass"
    # a commented-out line is not configuration
    commented = {"20auto-upgrades": '// APT::Periodic::Unattended-Upgrade "1";\n'}
    assert "OFF" in ls.check_updates(_apt_host(tmp_path, commented, sim=clean))["detail"]


def test_updates_not_apt(tmp_path):
    assert ls.check_updates(make_host(tmp_path))["status"] == "unknown"


# ── disk encryption ──────────────────────────────────────────────────────

LSBLK_PLAIN = json.dumps({"blockdevices": [{"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoints": [None],
    "children": [{"name": "nvme0n1p2", "type": "part", "fstype": "ext4", "mountpoints": ["/"]},
                 {"name": "nvme0n1p4", "type": "part", "fstype": "ext4", "mountpoints": ["/home", "/persist"]}]},
    # an unmounted second disk (another OS) is never a finding
    {"name": "sda", "type": "disk", "children": [{"name": "sda2", "type": "part", "fstype": "ntfs",
                                                   "mountpoints": []}]}]})
LSBLK_LUKS = json.dumps({"blockdevices": [{"name": "nvme0n1", "type": "disk", "children": [
    {"name": "nvme0n1p3", "type": "part", "fstype": "crypto_LUKS", "children": [
        {"name": "cryptroot", "type": "crypt", "fstype": "ext4", "mountpoint": "/"}]}]}]})


LSBLK_LUKS_LVM = json.dumps({"blockdevices": [{"name": "sda", "type": "disk", "children": [
    {"name": "sda3", "type": "part", "fstype": "crypto_LUKS", "children": [
        {"name": "sda3_crypt", "type": "crypt", "fstype": "LVM2_member", "mountpoints": [None], "children": [
            {"name": "vg-root", "type": "lvm", "fstype": "ext4", "mountpoints": ["/"]}]}]}]}]})


def test_lsblk_tree():
    m = ls.lsblk_mounts(LSBLK_LUKS)
    assert m["/"]["encrypted"] is True
    # LVM inside LUKS: the mount sits on an lvm node, its ANCESTOR is the crypt
    assert ls.lsblk_mounts(LSBLK_LUKS_LVM)["/"]["encrypted"] is True
    m = ls.lsblk_mounts(LSBLK_PLAIN)
    assert m["/"]["encrypted"] is False and m["/persist"]["dev"] == "nvme0n1p4"


def test_encryption_check(tmp_path):
    key = ("lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS")
    c = ls.check_encryption(make_host(tmp_path, cmds={key: (0, LSBLK_PLAIN, "")}))
    assert c["status"] == "warn" and len(c["items"]) == 3
    assert ls.check_encryption(make_host(tmp_path, cmds={key: (0, LSBLK_LUKS, "")}))["status"] == "pass"


# ── failed logins ────────────────────────────────────────────────────────

def test_failed_logins_unreadable_journal_is_unknown_not_zero(tmp_path):
    """Measured on a real box: an unprivileged journalctl returns rc 0 and NO
    output (no hint) -- that must read as unknown, never as '0 attempts'."""
    files = {"/var/log/journal/abc/system.journal": "x"}
    h = make_host(tmp_path, files=files, cmds={("journalctl",): (0, "", "")})
    if POSIX and os.geteuid() != 0:
        os.chmod(os.path.join(h.root, "var/log/journal/abc/system.journal"), 0)
        assert ls.check_failed_logins(h)["status"] == "unknown"


def test_failed_logins_counts_and_sources(tmp_path):
    lines = "\n".join(["Failed password for root from 203.0.113.7 port 4242 ssh2"] * 25 +
                      ["Accepted publickey for x from 198.51.100.1 port 1 ssh2"])
    h = make_host(tmp_path, cmds={("journalctl", "--no-pager", "-o", "cat", "--since=-24h", "_COMM=sshd"):
                                  (0, lines, ""), ("journalctl",): (0, "", "")}, euid=0)
    c = ls.check_failed_logins(h)
    assert c["status"] == "warn" and c["items"][0].startswith("203.0.113.7: 25")


# ── sudoers / PATH ───────────────────────────────────────────────────────

@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_sudoers_mode_and_nopasswd(tmp_path):
    h = make_host(tmp_path, files={"/etc/sudoers": "root ALL=(ALL:ALL) ALL\n",
                                   "/etc/sudoers.d/90-x": "bob ALL=(ALL) NOPASSWD: ALL\n"}, euid=0)
    me = os.getuid()
    c = ls.check_sudoers(h)
    if me != 0:
        assert c["status"] == "fail" and any("not root" in i for i in c["items"])
    os.chmod(os.path.join(h.root, "etc/sudoers.d/90-x"), 0o666)
    c = ls.check_sudoers(h)
    assert c["status"] == "fail" and any("writable" in i for i in c["items"])


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_path_world_writable_and_fix_plan(tmp_path):
    h = make_host(tmp_path, files={"/opt/bin/.keep": "", "/usr/bin/.keep": "", "/tmp/.keep": ""},
                  path_env="/usr/bin:/opt/bin:/tmp:.", euid=1000)
    os.chmod(os.path.join(h.root, "opt/bin"), 0o777)
    os.chmod(os.path.join(h.root, "tmp"), 0o1777)
    # the audit sees the FAKE root's dirs through Host.stat
    h.env_path = "/usr/bin:/opt/bin:/tmp:."
    c = ls.check_path(h)
    assert c["status"] == "fail"
    assert any(i.startswith("/opt/bin: world-writable --") for i in c["items"])
    assert any("sticky" in i for i in c["items"]) and any("relative" in i for i in c["items"])
    plan = ls.fix_plan({"checks": [c]}, h)
    assert [s["what"] for s in plan] == ["chmod o-w /opt/bin"] and "0777" in plan[0]["undo"]
    # never as a normal user
    assert ls.apply_plan(plan, h)[0].startswith("refused")
    assert stat.S_IMODE(os.stat(os.path.join(h.root, "opt/bin")).st_mode) == 0o777


def test_fix_plan_never_touches_ssh_or_firewall(tmp_path):
    res = {"checks": [ls._chk("ssh", "SSH", "fail", "PermitRootLogin yes"),
                      ls._chk("firewall", "Firewall", "fail", "none")]}
    assert ls.fix_plan(res, make_host(tmp_path)) == []


# ── secure boot ──────────────────────────────────────────────────────────

def test_secure_boot(tmp_path):
    on = make_host(tmp_path, files={"/sys/firmware/efi/.keep": "", "/" + ls.SECUREBOOT_VAR: bytes([6, 0, 0, 0, 1]),
                                    "/sys/kernel/security/lockdown": "none [integrity] confidentiality\n"})
    c = ls.check_boot(on)
    assert c["status"] == "pass" and "integrity" in c["detail"]
    tmp2 = tmp_path / "b"
    tmp2.mkdir()
    off = make_host(tmp2, files={"/sys/firmware/efi/.keep": "", "/" + ls.SECUREBOOT_VAR: bytes([6, 0, 0, 0, 0])})
    assert ls.check_boot(off)["status"] == "warn"
    tmp3 = tmp_path / "c"
    tmp3.mkdir()
    assert "legacy BIOS" in ls.check_boot(make_host(tmp3))["detail"]


def test_score_weights():
    checks = [ls._chk("a", "A", "fail", "", weight=20), ls._chk("b", "B", "warn", "", weight=10),
              ls._chk("c", "C", "unknown", "", weight=50), ls._chk("d", "D", "pass", "", weight=5)]
    assert ls.score(checks) == 75


# ── startup / uninstall / health rows ────────────────────────────────────

def test_autostart_merge_override_and_broken(tmp_path, monkeypatch):
    sysd = tmp_path / "xdg"
    (sysd / "autostart").mkdir(parents=True)
    (sysd / "autostart" / "a.desktop").write_text("[Desktop Entry]\nName=A\nExec=/nonexistent/a-bin --x\n")
    (sysd / "autostart" / "b.desktop").write_text("[Desktop Entry]\nName=B\nExec=env FOO=1 bbin %U\n"
                                                  "OnlyShowIn=GNOME;\n")
    home = tmp_path / "home"
    (home / ".config/autostart").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_DIRS", str(sysd))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("HOME", str(home))
    h = ls.Host(root="/", run=lambda a: (1, "", ""), which=lambda n: None)
    items = {i["id"]: i for i in lsys.autostart_entries(h, desktop="XFCE")}
    assert items["a.desktop"]["broken"] and items["a.desktop"]["enabled"]
    assert lsys.exec_binary("env FOO=1 bbin %U") == "bbin"
    assert not items["b.desktop"]["enabled"]          # OnlyShowIn=GNOME on XFCE
    msg = lsys.disable_item(items["a.desktop"], h)
    assert "override" in msg
    items = {i["id"]: i for i in lsys.autostart_entries(h, desktop="XFCE")}
    assert items["a.desktop"]["scope"] == "user" and not items["a.desktop"]["enabled"] and items["a.desktop"]["ours"]
    assert "enabled" in lsys.enable_item(items["a.desktop"], h)
    items = {i["id"]: i for i in lsys.autostart_entries(h, desktop="XFCE")}
    assert items["a.desktop"]["scope"] == "system" and items["a.desktop"]["enabled"]


def test_protected_and_system_units_are_never_changed(tmp_path):
    calls = []
    h = ls.Host(root=str(tmp_path), run=lambda a: calls.append(a) or (0, "", ""), which=lambda n: "/x")
    ssh = {"kind": "unit", "id": "ssh.service", "scope": "system", "protected": True}
    assert lsys.disable_item(ssh, h).startswith("refused")
    other = {"kind": "unit", "id": "foo.service", "scope": "system", "protected": False}
    assert "sudo systemctl disable" in lsys.disable_item(other, h)
    assert calls == []
    user = {"kind": "unit", "id": "foo.service", "scope": "user", "protected": False}
    lsys.disable_item(user, h)
    assert calls == [["systemctl", "--user", "disable", "foo.service"]]


def test_uninstall_plan_user_level_only():
    assert lsys.uninstall_plan({"manager": "flatpak", "id": "org.x.Y", "scope": "user"})["run"][:3] == \
        ["flatpak", "uninstall", "--user"]
    for m in ("apt", "pip"):
        p = lsys.uninstall_plan({"manager": m, "id": "x", "scope": "system"})
        assert p["run"] is None and p["print"]


def test_health_rows(tmp_path):
    files = {"/proc/pressure/memory": "some avg10=1.00 avg60=12.50 avg300=3.00 total=1\n"
                                      "full avg10=0.00 avg60=0.40 avg300=0.10 total=1\n",
             "/proc/vmstat": "nr_free_pages 1\noom_kill 2\n",
             "/sys/class/hwmon/hwmon2/name": "amdgpu\n",
             "/sys/class/hwmon/hwmon2/temp2_input": "103000\n", "/sys/class/hwmon/hwmon2/temp2_label": "junction\n",
             "/sys/class/hwmon/hwmon2/temp2_crit": "110000\n",
             "/sys/class/hwmon/hwmon5/name": "k10temp\n", "/sys/class/hwmon/hwmon5/temp1_input": "55000\n"}
    h = make_host(tmp_path, files=files, cmds={("systemctl", "--failed"): (0, "x.service loaded failed failed X\n", ""),
                                               ("systemctl", "--user"): (1, "", "")})
    rows = {r["name"]: r for r in lsys.health_checks(h)}
    assert rows["Memory Pressure (PSI)"]["status"] == "warn"
    assert rows["OOM Kills (since boot)"]["value"] == 2
    t = rows["Temperatures"]
    # 103 C junction against ITS OWN crit (110): warn at crit-10, not the generic 90 fail
    assert t["status"] == "warn" and "junction" in t["detail"]
    assert rows["Failed systemd Units"]["status"] == "warn"


# ── the guard ────────────────────────────────────────────────────────────

class FakeSig(guard.Signaller):
    def __init__(self):
        self.calls, self.nice = [], {}

    def same(self, pid, ct):
        return True

    def renice(self, pid, inc):
        self.calls.append(("renice", pid))
        old = self.nice.get(pid, 0)
        self.nice[pid] = old + inc
        return old

    def set_nice(self, pid, value):
        self.calls.append(("set_nice", pid, value))
        self.nice[pid] = value

    def suspend(self, pid):
        self.calls.append(("suspend", pid))

    def resume(self, pid):
        self.calls.append(("resume", pid))

    def terminate(self, pid):
        self.calls.append(("terminate", pid))


def proc(pid=500, name="tracker-miner-fs-3", cpu=99.0, user="me", cmd="", ct=1000.0, rss=10**8):
    return {"pid": pid, "ppid": 1000, "name": name, "cpu": cpu, "user": user, "cmd": cmd or name, "ct": ct, "rss": rss}


def cfg(**kw):
    c = dict(guard.DEFAULTS)
    c.update(kw)
    return c


def run_guard(c, samples, table=None, units=None, start=0, g=None, sig=None):
    sig = sig or FakeSig()
    g = {} if g is None else g
    out = []
    for i in range(samples):
        out += guard.step(table or [proc()], c, g, now=start + 60 * i, sig=sig, self_pids=set(),
                          units_of=lambda pid: units or [], me="me")
    return out, sig, g


@pytest.mark.parametrize("name,cmd,units,user,why", [
    ("chrome", "", [], "me", "protected name"),
    ("code", "", [], "me", "protected name"),
    ("telegram-desktop", "", [], "me", "protected name"),
    ("ollama", "", [], "me", "protected name"),
    ("adb", "", [], "me", "protected name"),
    ("python3", "python3 /opt/x/scrcpy-bridge/run.py", [], "me", "protected command"),
    ("tracker-miner-fs-3", "", ["sentinel-agent.service"], "me", "protected unit"),
    ("tracker-miner-fs-3", "", [], "root", "another user"),
    ("python3", "python3 job.py", [], "me", "not in the allow-list"),
])
def test_guard_never_touches(name, cmd, units, user, why):
    ok, reason = guard.eligible(proc(name=name, cmd=cmd or name, user=user), cfg(), set(), units, "me")
    assert not ok and why in reason
    out, sig, _ = run_guard(cfg(guard_mode="act"), 10, [proc(name=name, cmd=cmd or name, user=user)], units)
    assert sig.calls == [] and out == []


def test_guard_allow_list_target_is_eligible():
    assert guard.eligible(proc(), cfg(), set(), [], "me") == (True, "")
    assert guard.eligible(proc(), cfg(guard_protect_extra=["tracker*"]), set(), [], "me")[0] is False


def test_guard_dry_run_never_acts():
    out, sig, _ = run_guard(cfg(guard_mode="dry-run"), 30)
    assert sig.calls == []
    assert [e["kind"] for e in out] == ["would"] and "dry-run" in out[0]["msg"]


def test_guard_act_logs_dry_run_first_then_climbs_the_ladder():
    out, sig, g = run_guard(cfg(guard_mode="act", guard_sustain=3, guard_step_samples=3), 9)
    kinds = [(e["kind"], e["step"]) for e in out]
    # sustain 3 -> would renice (sample 3), renice (4); 3 more hot samples -> would suspend, suspend
    assert kinds[:2] == [("would", "renice"), ("act", "renice")]
    assert ("would", "suspend") in kinds and ("act", "suspend") in kinds
    assert kinds.index(("would", "suspend")) < kinds.index(("act", "suspend"))
    assert [c[0] for c in sig.calls] == ["renice", "suspend"]
    assert "terminate" not in [c[0] for c in sig.calls]


def test_guard_suspend_is_always_resumed_and_kill_stays_off():
    c = cfg(guard_mode="act", guard_sustain=1, guard_step_samples=0, guard_suspend_max_s=120)
    out, sig, g = run_guard(c, 12)
    names = [x[0] for x in sig.calls]
    assert "suspend" in names and "resume" in names and names.index("resume") > names.index("suspend")
    assert "terminate" not in names
    assert any(e["kind"] == "kill-off" for e in out)


def test_guard_kill_only_when_opted_in():
    c = cfg(guard_mode="act", guard_sustain=1, guard_step_samples=0, guard_suspend_max_s=60, guard_allow_kill=True)
    _, sig, _ = run_guard(c, 14)
    assert ("terminate", 500) in sig.calls


def test_guard_rate_limit():
    c = cfg(guard_mode="act", guard_sustain=1, guard_step_samples=0, guard_max_actions_per_hour=1)
    table = [proc(pid=500 + i, ct=1000.0 + i) for i in range(4)]
    out, sig, _ = run_guard(c, 3, table=table)
    assert len([x for x in sig.calls if x[0] == "renice"]) == 1
    assert any(e["kind"] == "rate" for e in out)


def test_guard_pid_reuse_is_never_acted_on():
    class Reused(FakeSig):
        def same(self, pid, ct):
            return False
    _, sig, _ = run_guard(cfg(guard_mode="act", guard_sustain=1), 5, sig=Reused())
    assert sig.calls == []


def test_guard_off_resumes_and_undo_restores():
    c = cfg(guard_mode="act", guard_sustain=1, guard_step_samples=0, guard_suspend_max_s=10**6)
    out, sig, g = run_guard(c, 4)
    assert ("suspend", 500) in sig.calls and ("resume", 500) not in sig.calls
    sig2 = FakeSig()
    lines = guard.undo(g, sig2)
    assert ("resume", 500) in sig2.calls and ("set_nice", 500, 0) in sig2.calls and len(lines) == 2
    # and turning the guard off resumes on the next pass
    _, sig, g = run_guard(c, 4)
    guard.step([proc()], cfg(guard_mode="off"), g, now=10**5, sig=sig, self_pids=set(), units_of=lambda p: [], me="me")
    assert ("resume", 500) in sig.calls


def test_guard_cooldown_resets_the_dry_run():
    c = cfg(guard_mode="act", guard_sustain=2)
    sig, g = FakeSig(), {}
    hot, cold = [proc(cpu=99)], [proc(cpu=1)]
    for i, t in enumerate([hot, hot, cold, hot, hot]):
        guard.step(t, c, g, now=60 * i, sig=sig, self_pids=set(), units_of=lambda p: [], me="me")
    assert sig.calls == []   # each episode logged its own dry-run; never acted on a stale one


def test_guard_default_mode_keeps_macos_unchanged():
    from macmon_core.platform_compat import IS_LINUX
    assert guard.DEFAULTS["guard_mode"] == ("dry-run" if IS_LINUX else "off")
    assert guard.DEFAULTS["guard_allow_kill"] is False


# ── sentinel: config layering, notify hook, systemd units ────────────────

def test_conf_layers_system_then_user(tmp_path, monkeypatch):
    from macmon_core import sentinel
    sysconf, userconf = tmp_path / "sys.json", tmp_path / "user.json"
    sysconf.write_text(json.dumps({"guard_mode": "act", "ram_pct": 80}))
    userconf.write_text(json.dumps({"ram_pct": 70}))
    monkeypatch.setattr(sentinel, "SYSTEM_CONF", sysconf)
    monkeypatch.setattr(sentinel, "CONF", userconf)
    c = sentinel._conf()
    assert c["guard_mode"] == "act" and c["ram_pct"] == 70 and c["guard_cpu_pct"] == 80.0


def test_notify_cmd_template(tmp_path, monkeypatch):
    from macmon_core import sentinel
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"], seen["env"] = argv, kw.get("env", {})

        class R:
            returncode = 0
        return R()
    tool = tmp_path / "notif"
    tool.write_text("#!/bin/sh\n")
    monkeypatch.setattr(sentinel.subprocess, "run", fake_run)
    ok = sentinel._notify_cmd({"notify_cmd": [str(tool), "{title}", "{body}", "{urgency}", "icon"],
                               "notify_env": {"APPNAME": "Aegis"}}, "T", "B 'q'", "low")
    assert ok and seen["argv"] == [str(tool), "T", "B 'q'", "low", "icon"] and seen["env"]["APPNAME"] == "Aegis"
    assert sentinel._notify_cmd({"notify_cmd": ["/no/such/tool"]}, "T", "B", "low") is False


def test_systemd_units_text():
    from macmon_core import sentinel
    svc, tmr = sentinel._systemd_units(["/opt/my tools/aegis", "sentinel", "--sample"])
    assert "Type=oneshot" in svc and "ExecStart='/opt/my tools/aegis' sentinel --sample" in svc
    assert "OnUnitActiveSec=60s" in tmr and "WantedBy=timers.target" in tmr
    assert sentinel._UNIT_MARK in svc and sentinel._UNIT_MARK in tmr


def test_status_snapshot_is_atomic_json(tmp_path, monkeypatch):
    from macmon_core import sentinel
    monkeypatch.setattr(sentinel, "STATUS", tmp_path / "status.json")
    sentinel._write_status({"cpu": 5, "ram": 50}, {"mode": "act"}, {"at": 1, "score": 90}, [("disk", "low")], 100)
    d = json.loads((tmp_path / "status.json").read_text())
    assert d["guard"]["mode"] == "act" and d["security"]["score"] == 90 and d["last_alert"]["msg"] == "low"
    assert not (tmp_path / "status.tmp").exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux routing")
def test_linux_cli_routes_security_to_the_linux_audit():
    import subprocess
    r = subprocess.run([sys.executable, "macmon.py", "security", "--json"], capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), timeout=180)
    d = json.loads(r.stdout)
    assert d["platform"] == "Linux" and 0 <= d["score"] <= 100 and d["checks"]
