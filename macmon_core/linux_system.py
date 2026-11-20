"""Linux parity for `aegis startup`, `aegis uninstall` and the Linux rows of
`aegis health`.

Same doctrine as linux_security: every read goes through a ``Host`` (fake root
+ fake command runner in the tests), and nothing changes without an explicit
flag. Changes are always REVERSIBLE and USER-LEVEL:

  * startup --disable on an XDG autostart entry writes a ``Hidden=true``
    override in ~/.config/autostart (enable removes it); on a systemd USER unit
    it runs ``systemctl --user disable`` (enable re-enables it). System units
    are never touched: the exact sudo command is printed instead.
  * uninstall removes only user-level installs (flatpak --user, pipx) and
    moves leftovers to the Trash; apt / pip commands are printed, not run.
"""
from __future__ import annotations

import configparser
import os
import re
import shlex

from .linux_security import Host

AEGIS_MARK = "# aegis: disabled by `aegis startup --disable` (enable restores it)"

# Units a startup action must never touch, whatever the user asks.
PROTECTED_UNITS = ("ssh*", "sshd*", "systemd-*", "dbus*", "networkmanager*", "wpa_supplicant*",
                   "lightdm*", "gdm*", "sddm*", "display-manager*", "polkit*", "udisks2*",
                   "pipewire*", "wireplumber*", "pulseaudio*", "xdg-*", "gvfs*", "at-spi*")


def _fnmatch_any(name: str, pats) -> bool:
    import fnmatch
    n = (name or "").lower()
    return any(fnmatch.fnmatchcase(n, p.lower()) for p in pats)


# ── startup: XDG autostart + systemd units ───────────────────────────────

def _home(h: Host) -> str:
    return os.environ.get("HOME", os.path.expanduser("~"))


def _user_autostart_dir(h: Host) -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(_home(h), ".config")
    return os.path.join(base, "autostart")


def _system_autostart_dirs() -> list[str]:
    dirs = os.environ.get("XDG_CONFIG_DIRS") or "/etc/xdg"
    return [os.path.join(d, "autostart") for d in dirs.split(":") if d]


def parse_desktop(text: str) -> dict:
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    try:
        cp.read_string(text or "")
    except configparser.Error:
        return {}
    if not cp.has_section("Desktop Entry"):
        return {}
    return dict(cp.items("Desktop Entry"))


def exec_binary(exec_line: str) -> str:
    """First real program of an Exec= line (skips `env VAR=x`, `sh -c` keeps sh)."""
    try:
        toks = shlex.split(exec_line or "")
    except ValueError:
        toks = (exec_line or "").split()
    toks = [t for t in toks if not t.startswith("%")]
    if toks and os.path.basename(toks[0]) == "env":
        toks = toks[1:]
        while toks and ("=" in toks[0] or toks[0].startswith("-")):
            toks = toks[1:]
    return toks[0] if toks else ""


_SUSPICIOUS_EXEC = (re.compile(r"(^|[\s/])(/tmp|/var/tmp|/dev/shm)/"), re.compile(r"/\.[^/\s]+/[^/\s]*$"),
                    re.compile(r"(curl|wget)[^|]*\|\s*(ba|z|da)?sh\b"), re.compile(r"base64\s+(-d|--decode)"))


def autostart_entries(h: Host, desktop: str | None = None) -> list[dict]:
    """Merged XDG autostart (user dir overrides system dirs by file name)."""
    desktop = (desktop if desktop is not None else os.environ.get("XDG_CURRENT_DESKTOP", "")).upper()
    cur = [d for d in desktop.split(":") if d]
    seen = {}
    for d, scope in [(x, "system") for x in reversed(_system_autostart_dirs())] + [(_user_autostart_dir(h), "user")]:
        for f in h.listdir(d):
            if not f.endswith(".desktop"):
                continue
            text = h.read(os.path.join(d, f)) or ""
            e = parse_desktop(text)
            if not e:
                continue
            seen[f] = {"file": f, "path": os.path.join(d, f), "scope": scope, "entry": e,
                       "ours": AEGIS_MARK in text, "overrides": seen.get(f, {}).get("path")}
    out = []
    for f, it in sorted(seen.items()):
        e = it["entry"]
        hidden = e.get("Hidden", "false").lower() == "true"
        gnome_off = e.get("X-GNOME-Autostart-enabled", "true").lower() == "false"
        only = [x.upper() for x in e.get("OnlyShowIn", "").split(";") if x]
        nots = [x.upper() for x in e.get("NotShowIn", "").split(";") if x]
        applies = (not only or any(c in only for c in cur)) and not any(c in nots for c in cur)
        binary = exec_binary(e.get("Exec", ""))
        if binary.startswith("/"):
            found = h.exists(binary)
        else:
            found = bool(binary) and bool(h.which(binary))
        tryexec = e.get("TryExec")
        skipped = bool(tryexec) and not (h.exists(tryexec) if tryexec.startswith("/") else h.which(tryexec))
        out.append({"kind": "autostart", "name": e.get("Name", f), "id": f, "scope": it["scope"],
                    "path": it["path"], "enabled": not hidden and not gnome_off and applies,
                    "applies": applies, "exec": e.get("Exec", ""),
                    "broken": bool(binary) and not found and not skipped, "ours": it["ours"],
                    "suspicious": any(rx.search(e.get("Exec", "")) for rx in _SUSPICIOUS_EXEC)})
    return out


def parse_unit_files(text: str) -> list[tuple[str, str]]:
    out = []
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) >= 2 and "." in f[0]:
            out.append((f[0], f[1]))
    return out


def systemd_units(h: Host) -> list[dict]:
    out = []
    for scope, extra in (("system", []), ("user", ["--user"])):
        rc, txt, _ = h.cmd(["systemctl", *extra, "list-unit-files", "--type=service", "--type=timer",
                            "--state=enabled", "--no-legend", "--no-pager", "--plain"])
        if rc != 0:
            continue
        for unit, state in parse_unit_files(txt):
            out.append({"kind": "unit", "name": unit, "id": unit, "scope": scope, "enabled": state == "enabled",
                        "path": "", "exec": "", "broken": False, "ours": False, "suspicious": False,
                        "protected": _fnmatch_any(unit, PROTECTED_UNITS)})
    return out


def failed_units(h: Host) -> list[str]:
    out = []
    for scope, extra in (("system", []), ("user", ["--user"])):
        rc, txt, _ = h.cmd(["systemctl", *extra, "--failed", "--no-legend", "--no-pager", "--plain"])
        if rc != 0:
            continue
        for line in txt.splitlines():
            f = line.split()
            if f and "." in f[0]:
                out.append(f"{f[0]} ({scope})")
    return out


def startup_items(h: Host | None = None) -> list[dict]:
    h = h or Host()
    return autostart_entries(h) + systemd_units(h)


def _find_item(items: list[dict], ident: str) -> list[dict]:
    i = ident.lower()
    exact = [x for x in items if x["id"].lower() in (i, i + ".desktop", i + ".service", i + ".timer")]
    return exact or [x for x in items if i in x["id"].lower() or i in x["name"].lower()]


def disable_item(item: dict, h: Host | None = None) -> str:
    """Reversible disable. Returns a one-line outcome."""
    h = h or Host()
    if item["kind"] == "autostart":
        dst = os.path.join(_user_autostart_dir(h), item["id"])
        if item["scope"] == "user" and not item["ours"]:
            text = h.read(dst) or ""
            bak = dst + ".aegis-bak"
            with open(bak, "w", encoding="utf-8") as fh:
                fh.write(text)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(f"{AEGIS_MARK}\n[Desktop Entry]\nType=Application\nName={item['name']}\n"
                     f"Exec={item['exec']}\nHidden=true\n")
        return f"disabled {item['id']} (override {dst})"
    if item.get("protected"):
        return f"refused: {item['id']} is a protected system unit"
    if item["scope"] == "user":
        rc, out, err = h.cmd(["systemctl", "--user", "disable", item["id"]])
        return f"disabled user unit {item['id']}" if rc == 0 else f"failed: {err.strip() or out.strip()}"
    return f"system unit: run `sudo systemctl disable {item['id']}` yourself (aegis never changes system units)"


def enable_item(item: dict, h: Host | None = None) -> str:
    h = h or Host()
    if item["kind"] == "autostart":
        dst = os.path.join(_user_autostart_dir(h), item["id"])
        bak = dst + ".aegis-bak"
        if os.path.exists(bak):
            os.replace(bak, dst)
            return f"restored {item['id']} from its backup"
        if item.get("ours") or AEGIS_MARK in (h.read(dst) or ""):
            os.remove(dst)
            return f"enabled {item['id']} (removed the aegis override)"
        return f"{item['id']} is not disabled by aegis: edit {item['path']} (Hidden=false)"
    if item.get("protected"):
        return f"refused: {item['id']} is a protected system unit"
    if item["scope"] == "user":
        rc, out, err = h.cmd(["systemctl", "--user", "enable", item["id"]])
        return f"enabled user unit {item['id']}" if rc == 0 else f"failed: {err.strip() or out.strip()}"
    return f"system unit: run `sudo systemctl enable {item['id']}` yourself"


def run_startup(list_items=False, disable=None, enable=None, delete=None, broken=False, audit=False,
                force_yes=False, h: Host | None = None):
    from rich.table import Table
    from .utils import confirm_action, console
    h = h or Host()
    items = startup_items(h)
    if disable or enable:
        ident = disable or enable
        found = _find_item(items, ident)
        if len(found) != 1:
            console.print(f"[yellow]{len(found)} item(s) match {ident!r}: be more specific[/]")
            for x in found[:10]:
                console.print(f"  {x['id']} ({x['kind']}, {x['scope']})", markup=False)
            return
        it = found[0]
        if disable and not force_yes and not confirm_action(f"Disable {it['id']} ({it['kind']}, {it['scope']})?"):
            return
        console.print((disable_item if disable else enable_item)(it, h), markup=False)
        return
    if delete:
        console.print("[yellow]On Linux, aegis only disables startup items (reversible): use --disable.[/]")
        return
    if broken:
        rows = [x for x in items if x["broken"]]
        fails = failed_units(h)
        console.print(f"[bold]{len(rows)} broken autostart entr(y/ies), {len(fails)} failed unit(s)[/]")
        for x in rows:
            console.print(f"  {x['id']}: program not found ({x['exec']})", markup=False)
        for u in fails:
            console.print(f"  {u}: failed (`systemctl status`)", markup=False)
        return
    if audit:
        rows = [x for x in items if x["suspicious"]]
        console.print(f"[bold]{len(rows)} suspicious startup item(s)[/]")
        for x in rows:
            console.print(f"  {x['path']}: {x['exec']}", markup=False)
        return
    t = Table(title=f"Startup items ({len(items)})")
    for c in ("Item", "Kind", "Scope", "State"):
        t.add_column(c)
    for x in items:
        st = "on" if x["enabled"] else "off"
        if x["broken"]:
            st += " (broken)"
        if x.get("protected"):
            st += " (protected)"
        t.add_row(x["id"], x["kind"], x["scope"], st)
    console.print(t)


# ── uninstall: apt / flatpak / pipx / pip --user ─────────────────────────

def installed_apps(h: Host | None = None) -> list[dict]:
    h = h or Host()
    out = []
    rc, txt, _ = h.cmd(["apt-mark", "showmanual"])
    if rc == 0:
        out += [{"manager": "apt", "id": l.strip(), "name": l.strip(), "scope": "system"}
                for l in txt.splitlines() if l.strip()]
    rc, txt, _ = h.cmd(["flatpak", "list", "--app", "--columns=application,name,installation"])
    if rc == 0:
        for l in txt.splitlines():
            f = l.split("\t")
            if len(f) >= 3:
                out.append({"manager": "flatpak", "id": f[0], "name": f[1], "scope": f[2]})
    rc, txt, _ = h.cmd(["pipx", "list", "--short"])
    if rc == 0:
        out += [{"manager": "pipx", "id": l.split()[0], "name": l.split()[0], "scope": "user"}
                for l in txt.splitlines() if l.strip()]
    for site in h.glob(os.path.join(_home(h), ".local/lib/python3*/site-packages")):
        for d in h.listdir(site):
            if d.endswith(".dist-info"):
                nm = d[:-len(".dist-info")].rsplit("-", 1)[0]
                out.append({"manager": "pip", "id": nm, "name": nm, "scope": "user"})
    return out


def leftovers(name: str, flatpak_id: str = "", h: Host | None = None) -> list[str]:
    h = h or Host()
    home = _home(h)
    cands = [os.path.join(home, ".config", name), os.path.join(home, ".cache", name),
             os.path.join(home, ".local/share", name)]
    if flatpak_id:
        cands.append(os.path.join(home, ".var/app", flatpak_id))
    return [c for c in cands if h.exists(c)]


def uninstall_plan(app: dict) -> dict:
    m, i = app["manager"], app["id"]
    if m == "flatpak" and app.get("scope") == "user":
        return {"run": ["flatpak", "uninstall", "--user", "-y", i], "print": None}
    if m == "flatpak":
        return {"run": None, "print": f"sudo flatpak uninstall -y {i}"}
    if m == "pipx":
        return {"run": ["pipx", "uninstall", i], "print": None}
    if m == "pip":
        return {"run": None, "print": f"python3 -m pip uninstall {i}"}
    return {"run": None, "print": f"sudo apt remove {i}"}


def run_uninstaller(app_name=None, scan_only=False, list_apps=False, permanent=False, force_yes=False,
                    h: Host | None = None):
    from rich.table import Table
    from .utils import confirm_action, console
    h = h or Host()
    apps = installed_apps(h)
    if list_apps or not app_name:
        t = Table(title=f"Installed apps ({len(apps)})")
        for c in ("Name", "Manager", "Scope"):
            t.add_column(c)
        for a in sorted(apps, key=lambda a: (a["manager"], a["name"].lower())):
            t.add_row(a["name"], a["manager"], a["scope"])
        console.print(t)
        return
    q = app_name.lower()
    found = [a for a in apps if q in (a["id"].lower(), a["name"].lower())] or \
            [a for a in apps if q in a["id"].lower() or q in a["name"].lower()]
    if len(found) != 1:
        console.print(f"[yellow]{len(found)} install(s) match {app_name!r}[/]")
        for a in found[:10]:
            console.print(f"  {a['name']} ({a['manager']}, {a['id']})", markup=False)
        return
    a = found[0]
    left = leftovers(a["name"].lower(), a["id"] if a["manager"] == "flatpak" else "", h)
    plan = uninstall_plan(a)
    console.print(f"[bold]{a['name']}[/] ({a['manager']}, {a['scope']})")
    console.print("  remove: " + (" ".join(plan["run"]) if plan["run"] else plan["print"] + "  (run it yourself)"),
                  markup=False)
    for p in left:
        console.print(f"  leftover: {p}", markup=False)
    if scan_only:
        return
    if not force_yes and not confirm_action("Proceed?"):
        return
    if plan["run"]:
        rc, out, err = h.cmd(plan["run"])
        console.print("  " + ("removed" if rc == 0 else f"failed: {(err or out).strip()[:200]}"), markup=False)
    from .uninstaller import _trash_or_rm
    from pathlib import Path
    for p in left:
        ok = _trash_or_rm(Path(p), permanent=permanent)
        console.print(f"  {'trashed' if ok else 'kept'}: {p}", markup=False)


# ── health: the Linux rows ───────────────────────────────────────────────

def parse_psi(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        f = line.split()
        if not f:
            continue
        kv = dict(x.split("=", 1) for x in f[1:] if "=" in x)
        try:
            out[f[0]] = float(kv.get("avg60", "nan"))
        except ValueError:
            pass
    return out


def hwmon_temps(h: Host) -> list[dict]:
    """Every hwmon temperature: {chip, label, c, crit}."""
    out = []
    for d in h.glob("/sys/class/hwmon/hwmon*"):
        chip = (h.read(d + "/name") or "").strip() or os.path.basename(d)
        for f in h.listdir(d):
            m = re.match(r"^temp(\d+)_input$", f)
            if not m:
                continue
            raw = (h.read(f"{d}/{f}") or "").strip()
            if not raw.lstrip("-").isdigit():
                continue
            n = m.group(1)
            label = (h.read(f"{d}/temp{n}_label") or "").strip() or f"temp{n}"
            crit_raw = (h.read(f"{d}/temp{n}_crit") or "").strip()
            crit = int(crit_raw) / 1000 if crit_raw.lstrip("-").isdigit() else None
            out.append({"chip": chip, "label": label, "c": int(raw) / 1000,
                        "crit": crit if crit and 40 <= crit <= 150 else None})
    return out


def _temp_status(t: dict) -> str:
    warn, fail = (t["crit"] - 10, t["crit"]) if t["crit"] else (80.0, 90.0)
    if t["chip"] == "nvme" and not t["crit"]:
        warn, fail = 70.0, 80.0
    return "fail" if t["c"] >= fail else "warn" if t["c"] >= warn else "pass"


def health_checks(h: Host | None = None) -> list[dict]:
    """The Linux rows appended to `aegis health`."""
    h = h or Host()
    checks = []
    psi = parse_psi(h.read("/proc/pressure/memory") or "")
    if psi:
        some, full = psi.get("some", 0.0), psi.get("full", 0.0)
        st = "fail" if some > 30 or full > 10 else "warn" if some > 10 or full > 2 else "pass"
        checks.append({"name": "Memory Pressure (PSI)", "status": st,
                       "detail": f"stalled {some:.1f}% (some) / {full:.1f}% (full), 60 s avg",
                       "fix_hint": "Close the heaviest apps (`aegis ps --sort ram`)", "value": some})
    vm = h.read("/proc/vmstat") or ""
    m = re.search(r"^oom_kill (\d+)", vm, re.M)
    if m:
        n = int(m.group(1))
        checks.append({"name": "OOM Kills (since boot)", "status": "warn" if n else "pass",
                       "detail": f"{n} process(es) killed by the out-of-memory killer",
                       "fix_hint": "`journalctl -k | grep -i oom` shows which; add swap or RAM", "value": n})
    seen_dev = set()
    st_root = h.stat("/")
    if st_root:
        seen_dev.add(st_root.st_dev)
    for mp in ("/home", "/persist"):
        st = h.stat(mp)
        if not st or st.st_dev in seen_dev:
            continue
        seen_dev.add(st.st_dev)
        try:
            vfs = os.statvfs(h.p(mp))
        except OSError:
            continue
        total, free = vfs.f_blocks * vfs.f_frsize, vfs.f_bavail * vfs.f_frsize
        if not total:
            continue
        gb, pct = free / 1024 ** 3, 100.0 * free / total
        checks.append({"name": f"Disk Free {mp}", "status": "fail" if gb < 2 or pct < 5 else
                       "warn" if gb < 10 or pct < 15 else "pass",
                       "detail": f"{gb:.1f} GB free ({100 - pct:.0f}% used)",
                       "fix_hint": "Run `aegis clean --all` or `aegis bigfiles " + mp + "`", "value": gb})
    temps = hwmon_temps(h)
    if temps:
        worst = sorted(temps, key=lambda t: ({"fail": 0, "warn": 1, "pass": 2}[_temp_status(t)], -t["c"]))[0]
        hottest = max(temps, key=lambda t: t["c"])
        st = _temp_status(worst)
        show = worst if st != "pass" else hottest
        checks.append({"name": "Temperatures", "status": st,
                       "detail": f"{len(temps)} sensors; {show['chip']} {show['label']} {show['c']:.0f} C"
                                 + (f" (crit {show['crit']:.0f})" if show["crit"] else ""),
                       "fix_hint": "Check airflow and fan curves; clean dust filters", "value": show["c"]})
    fails = failed_units(h)
    checks.append({"name": "Failed systemd Units", "status": "fail" if len(fails) > 3 else
                   "warn" if fails else "pass",
                   "detail": ", ".join(fails[:4]) + (" ..." if len(fails) > 4 else "") if fails else "none",
                   "fix_hint": "`systemctl status <unit>` then fix or disable it", "value": len(fails)})
    return checks

