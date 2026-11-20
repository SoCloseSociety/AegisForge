"""The guard: SAFE autonomous remediation of runaway processes.

Called once per sentinel sample (`aegis sentinel --sample`), on the process
table the sampler already took. Safe by default, by construction:

  * ALLOW-LIST: the guard may only ever touch a process whose name matches
    ``guard_allow`` (default: a few background indexers / thumbnailers known to
    run away). Everything else is observed, never acted on.
  * PROTECT-LISTS win over the allow-list: process names (``guard_protect`` +
    ``guard_protect_extra``), command-line substrings (``guard_protect_cmd`` +
    the engine's never-touch list), systemd units read from the cgroup
    (``guard_protect_units``), PID 1 / kernel threads, aegis itself and its
    parents, and any process of another user.
  * LADDER, mildest first, each step REVERSIBLE: renice (+10) -> suspend
    (SIGSTOP, ALWAYS resumed after ``guard_suspend_max_s``) -> terminate
    (SIGTERM, OFF unless ``guard_allow_kill``).
  * A RENICE ONLY WHEN IT CAN BE UNDONE: lowering a nice value back needs root,
    or on Linux an RLIMIT_NICE that allows it (it is 0 by default for a desktop
    user). When the original value could not be restored the guard skips the
    renice (logged once) and goes straight to the pause, which can always be
    undone. An undo that still fails KEEPS its record and says so.
  * NOTHING STAYS PAUSED: the pause is recorded (``persist``, atomic, under a
    lock in the sampler) BEFORE the SIGSTOP is sent -- no record, no SIGSTOP --
    an independent resume is scheduled with the OS where it can be (systemd
    ``--user`` timer), and every pass SWEEPS: a stopped allow-listed process of
    this user that has no pause record is resumed, in every mode, so a record
    lost to a killed sampler or a stale writer still ends in a resume.
  * DRY-RUN FIRST: in ``act`` mode a step only runs after the SAME step on the
    SAME process (pid + start time) was logged as "would" on an earlier
    sample. ``dry-run`` mode (the default) never acts at all.
  * RATE-LIMITED: at most ``guard_max_actions_per_hour`` actions per hour.
  * LOGGED + NOTIFIED: every would/act/resume line goes to the guard log and
    to the notifier the sentinel passes in.

`aegis guard --undo` resumes every suspended process and restores every nice
value the guard changed; whatever it could not undo is reported and kept.
"""
from __future__ import annotations

import fnmatch
import getpass
import os
import shutil
import signal
import subprocess
import time

from .platform_compat import IS_LINUX

LADDER = ("renice", "suspend", "kill")

GUARD_ALLOW = ["tracker-miner-fs*", "tracker-extract*", "localsearch*", "baloo_file*", "tumblerd",
               "zeitgeist-*", "gvfsd-metadata"]

GUARD_PROTECT = [
    # init, session, display, audio, network
    "systemd*", "init", "kthreadd", "xorg", "x", "xwayland", "*wayland*", "gnome-shell", "kwin*",
    "xfwm4", "xfce4-*", "xfdesktop", "xfsettingsd", "xfconfd", "lightdm*", "gdm*", "sddm*",
    "plasmashell", "pipewire*", "wireplumber", "pulseaudio", "dbus*", "networkmanager", "wpa_supplicant",
    "polkit*", "sshd", "ssh", "sudo", "su", "login", "agetty",
    # the owner's interactive apps
    "chrome", "chromium*", "google-chrome*", "firefox*", "brave*", "msedge*", "code", "code-*", "codium",
    "cursor", "electron", "telegram*", "discord*", "whatsapp*", "signal*", "slack*",
    # shells, terminals, multiplexers
    "bash", "zsh", "fish", "sh", "dash", "tmux*", "screen", "*terminal*", "alacritty", "kitty", "wezterm*",
    # services a fleet machine depends on
    "ollama*", "dockerd", "containerd*", "docker*", "wg", "wg-quick", "wireguard*", "openvpn",
    "tailscaled", "adb", "scrcpy*", "fastboot",
    # ourselves
    "aegis", "macmon",
]
GUARD_PROTECT_CMD = ["scrcpy", "uiautomator"]
GUARD_PROTECT_UNITS = ["sentinel*", "ollama*", "wg-quick*", "wireguard*", "lightdm*", "gdm*", "sddm*",
                       "display-manager*", "docker*", "containerd*", "ssh*", "networkmanager*",
                       "systemd-*", "dbus*", "polkit*", "pipewire*", "wireplumber*", "pulseaudio*",
                       "init.scope"]

DEFAULTS = {
    # Linux runs the guard in dry-run by default; macOS/Windows keep their
    # existing behaviour (guard off) unless the owner opts in.
    "guard_mode": "dry-run" if IS_LINUX else "off",
    "guard_allow": GUARD_ALLOW,
    "guard_protect": GUARD_PROTECT,
    "guard_protect_extra": [],
    "guard_protect_cmd": GUARD_PROTECT_CMD,
    "guard_protect_units": GUARD_PROTECT_UNITS,
    "guard_cpu_pct": 80.0,
    "guard_sustain": 3,
    "guard_rss_gb": 4.0,
    "guard_step_samples": 3,
    "guard_renice": 10,
    "guard_suspend_max_s": 300,
    "guard_allow_kill": False,
    "guard_max_actions_per_hour": 6,
}

MODES = ("off", "dry-run", "act")


def _list(cfg, key) -> list[str]:
    v = cfg.get(key, DEFAULTS.get(key))
    if isinstance(v, str):
        v = [x.strip() for x in v.split(",") if x.strip()]
    return [str(x).lower() for x in (v or [])]


def _num(cfg, key, cast=float):
    try:
        return cast(cfg.get(key, DEFAULTS[key]))
    except (TypeError, ValueError):
        return cast(DEFAULTS[key])


def mode_of(cfg) -> str:
    m = str(cfg.get("guard_mode", DEFAULTS["guard_mode"])).strip().lower()
    return m if m in MODES else "dry-run"


def _glob(name: str, pats) -> str | None:
    n = (name or "").lower()
    for p in pats:
        if fnmatch.fnmatchcase(n, p):
            return p
    return None


def cgroup_units(pid: int, root: str = "/") -> list[str]:
    """systemd units (.service / .scope) the process lives under, from /proc/<pid>/cgroup."""
    try:
        with open(os.path.join(root, f"proc/{pid}/cgroup"), encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        path = line.split(":", 2)[-1]
        for seg in path.split("/"):
            if seg.endswith((".service", ".scope")) and not seg.startswith("user@"):
                out.append(seg)
    return out


def eligible(p: dict, cfg: dict, self_pids=(), units=None, me: str | None = None) -> tuple[bool, str]:
    """May the guard EVER act on this process? (protections first, allow-list last)."""
    from . import aegis
    pid, name = int(p.get("pid") or 0), p.get("name") or ""
    if pid <= 1 or p.get("ppid") == 2:
        return False, "init or kernel thread"
    if pid in self_pids:
        return False, "aegis itself or one of its parents"
    hit = _glob(name, _list(cfg, "guard_protect") + _list(cfg, "guard_protect_extra"))
    if hit:
        return False, f"protected name ({hit})"
    nl = name.lower()
    if nl in aegis._NEVER_TOUCH_NAME_EXACT or nl.startswith(aegis._NEVER_TOUCH_NAME_PREFIX):
        return False, "protected name (engine never-touch)"
    cmd = (p.get("cmd") or "").lower()
    for s in _list(cfg, "guard_protect_cmd") + [x.lower() for x in aegis._NEVER_TOUCH_CMD]:
        if s and s in cmd:
            return False, f"protected command ({s})"
    me = me if me is not None else getpass.getuser()
    user = (p.get("user") or "").split("\\")[-1]
    if user and me and user != me:
        return False, f"another user's process ({user})"
    for u in (units if units is not None else cgroup_units(pid)):
        hit = _glob(u, _list(cfg, "guard_protect_units"))
        if hit:
            return False, f"protected unit ({u})"
    if not _glob(name, _list(cfg, "guard_allow")):
        return False, "not in the allow-list"
    return True, ""


class Signaller:
    """The only code that touches a real process. Tests pass a fake."""

    def same(self, pid: int, ct: float) -> bool:
        import psutil
        try:
            return abs(psutil.Process(pid).create_time() - ct) < 1.0
        except Exception:
            return False

    def renice(self, pid: int, inc: int) -> int:
        import psutil
        p = psutil.Process(pid)
        old = p.nice()
        p.nice(min(19, old + inc))
        return old

    def set_nice(self, pid: int, value: int):
        import psutil
        psutil.Process(pid).nice(value)

    def can_restore_nice(self, pid: int, value: int | None = None) -> bool:
        """Could this user set ``pid``'s nice back DOWN to ``value`` (default: its
        current nice) after a renice?

        Raising a nice value is always allowed; lowering it is not. root may;
        on Linux an unprivileged user may only go down to ``20 - RLIMIT_NICE``
        of the TARGET process (0 on a stock desktop, so: never). Everywhere
        else (macOS / BSD) only root may. Windows: no (the guard is off there)."""
        if os.name == "nt":
            return False
        try:
            if os.geteuid() == 0:
                return True
        except AttributeError:
            return False
        if not IS_LINUX:
            return False
        try:
            import psutil
            import resource
            proc = psutil.Process(pid)
            value = proc.nice() if value is None else value
            soft = proc.rlimit(psutil.RLIMIT_NICE)[0]
        except Exception:
            return False
        if soft == resource.RLIM_INFINITY:
            return True
        return 20 - int(value) <= int(soft)

    def schedule_resume(self, pid: int, after_s: int) -> bool:
        """An OS-side failsafe for a pause: a transient systemd --user timer that
        sends SIGCONT even if no sampler ever runs again. Best effort (Linux with
        systemd only); the persisted record + the sweep remain the primary path.
        SIGCONT to a running process is a no-op, so a late or duplicate one is harmless."""
        if not IS_LINUX or not shutil.which("systemd-run"):
            return False
        kill = shutil.which("kill") or "/bin/kill"
        try:
            r = subprocess.run(["systemd-run", "--user", "--quiet", "--collect", f"--on-active={int(after_s)}s",
                                "--timer-property=AccuracySec=5s", kill, "-CONT", str(int(pid))],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def suspend(self, pid: int):
        os.kill(pid, signal.SIGSTOP)

    def resume(self, pid: int):
        os.kill(pid, signal.SIGCONT)

    def terminate(self, pid: int):
        os.kill(pid, signal.SIGTERM)


def _self_pids() -> set[int]:
    out, pid = set(), os.getpid()
    try:
        import psutil
        p = psutil.Process(pid)
        while p is not None and len(out) < 64:
            out.add(p.pid)
            p = p.parent()
    except Exception:
        out.add(pid)
    return out


def _entry(kind, step, p_or_t, mode, reason="", now=None):
    return {"ts": int(now or time.time()), "kind": kind, "step": step, "pid": p_or_t.get("pid"),
            "name": (p_or_t.get("name") or "")[:40], "cpu": round(float(p_or_t.get("cpu") or 0), 1),
            "rss_mb": int((p_or_t.get("rss") or 0) / 1e6), "mode": mode, "reason": reason}


def _msg(e) -> str:
    verb = {"renice": "lower the priority of", "suspend": "pause", "kill": "stop"}.get(e["step"], e["step"])
    who = f"{e['name']} (pid {e['pid']}, {e['cpu']:.0f}% CPU)"
    if e["kind"] == "would":
        return f"Would {verb} {who} -- dry-run, nothing changed"
    if e["kind"] == "act":
        return {"renice": f"Lowered the priority of {who}",
                "suspend": f"Paused {who}; it resumes on its own",
                "kill": f"Stopped {who} (SIGTERM)"}.get(e["step"], f"{e['step']} {who}")
    if e["kind"] == "resume" and e["step"] == "sweep":
        return f"Resumed {e['name']} (pid {e['pid']}): it was left paused with no record of the pause"
    if e["kind"] == "resume":
        return f"Resumed {e['name']} (pid {e['pid']})"
    if e["kind"] == "skip" and e["step"] == "renice":
        return (f"Not lowering the priority of {who}: this user could not restore it afterwards "
                f"({e.get('reason') or 'no permission'}); the next step is a pause, which can always be undone")
    if e["kind"] == "kill-off":
        return f"{who} is still running away; stopping it is disabled (notify only)"
    if e["kind"] == "rate":
        return f"Hourly action budget used: {verb} {who} postponed"
    return f"{e['kind']} {e['step']} {who}"


def _gone(err: BaseException) -> bool:
    """The process no longer exists (so there is nothing left to undo)."""
    if isinstance(err, ProcessLookupError):
        return True
    try:
        import psutil
        return isinstance(err, psutil.NoSuchProcess)
    except Exception:
        return False


def step(table: list[dict], cfg: dict, g: dict, now: float, ram_critical: bool = False,
         sig: Signaller | None = None, self_pids=None, units_of=None, me: str | None = None,
         persist=None) -> list[dict]:
    """One guard pass. Mutates ``g`` and returns the log entries of this pass
    (each with a ``msg``). ``persist()`` writes ``g`` to durable storage; it is
    called BEFORE any SIGSTOP (a pause that cannot be recorded is not sent).
    The caller still persists ``g`` after the pass."""
    sig = sig or Signaller()
    mode = mode_of(cfg)
    out: list[dict] = []
    g.setdefault("streak", {})
    targets = g.setdefault("targets", {})
    acts = [t for t in g.setdefault("acts", []) if now - t < 3600]
    g["acts"] = acts

    def log(kind, st, who, reason=""):
        e = _entry(kind, st, who, mode, reason, now)
        e["msg"] = _msg(e)
        out.append(e)
        return e

    # 1. ALWAYS resume what we paused once its time is up (or the guard was turned off).
    max_s = _num(cfg, "guard_suspend_max_s", int)
    for key, t in list(targets.items()):
        if t.get("suspended_at") and (mode == "off" or now - t["suspended_at"] >= max_s):
            if sig.same(t["pid"], t["ct"]):
                try:
                    sig.resume(t["pid"])
                    log("resume", "suspend", t)
                except Exception as e:
                    if not _gone(e):   # still there, still stopped: keep the record, retry next pass
                        log("error", "resume", t, reason=repr(e)[:120])
                        continue
            t["suspended_at"] = None
            t["resumed_at"] = now

    # 2. SWEEP: a stopped (SIGSTOP, not a debugger's tracing stop) process the
    # guard could have paused, with no pause record, is a pause whose record was
    # lost (sampler killed mid-sample, stale writer). Resume it, in every mode.
    selfp = self_pids if self_pids is not None else _self_pids()
    recorded = {int(t["pid"]) for t in targets.values() if t.get("suspended_at")}
    for p in table:
        if str(p.get("status") or "").lower() != "stopped" or int(p.get("pid") or 0) in recorded:
            continue
        ok, _why = eligible(p, cfg, selfp, units_of(p["pid"]) if units_of else None, me)
        if not ok or not sig.same(p["pid"], float(p.get("ct") or 0)):
            continue
        try:
            sig.resume(p["pid"])
            log("resume", "sweep", p)
        except Exception as e:
            if not _gone(e):
                log("error", "sweep", p, reason=repr(e)[:120])
    if mode == "off":
        return out

    live = {f"{p.get('pid')}:{int(p.get('ct') or 0)}": p for p in table}
    for key in list(targets):
        if key not in live and not targets[key].get("suspended_at"):
            targets.pop(key)
    streak = {k: v for k, v in g["streak"].items() if k in live}
    cpu_pct, sustain = _num(cfg, "guard_cpu_pct"), _num(cfg, "guard_sustain", int)
    rss_lim = _num(cfg, "guard_rss_gb") * 1e9
    for key, p in live.items():
        hot = float(p.get("cpu") or 0) >= cpu_pct or (ram_critical and int(p.get("rss") or 0) >= rss_lim)
        streak[key] = streak.get(key, 0) + 1 if hot else 0
        if not hot and key in targets:
            targets[key]["would"] = None   # cooled down: a new episode logs its dry-run again
    g["streak"] = streak

    for key, n in sorted(streak.items(), key=lambda kv: -kv[1]):
        if n < sustain:
            continue
        p = live[key]
        ok, why = eligible(p, cfg, selfp, units_of(p["pid"]) if units_of else None, me)
        if not ok:
            continue
        t = targets.setdefault(key, {"pid": p["pid"], "ct": float(p.get("ct") or 0), "name": p.get("name"),
                                     "step": 0, "wait": 0, "would": None})
        t["cpu"], t["rss"] = p.get("cpu"), p.get("rss")
        if t.get("suspended_at"):
            continue
        if t["step"] and t["wait"] < _num(cfg, "guard_step_samples", int):
            t["wait"] += 1
            continue
        if t["step"] >= len(LADDER):
            continue
        nxt = LADDER[t["step"]]
        if nxt == "renice":
            try:
                restorable = sig.can_restore_nice(p["pid"])
            except Exception:
                restorable = False
            if not restorable:
                log("skip", "renice", p, reason="RLIMIT_NICE / not root")
                t["step"] += 1
                nxt = LADDER[t["step"]]
        if nxt == "kill" and cfg.get("guard_allow_kill", DEFAULTS["guard_allow_kill"]) is not True:
            if not t.get("kill_noted"):
                t["kill_noted"] = True
                log("kill-off", "kill", p)
            continue
        if mode == "dry-run" or t.get("would") != nxt:
            if t.get("would") != nxt:
                t["would"] = nxt
                log("would", nxt, p)
            continue
        if len(acts) >= _num(cfg, "guard_max_actions_per_hour", int):
            if t.get("rated") != nxt:
                t["rated"] = nxt
                log("rate", nxt, p)
            continue
        if not sig.same(p["pid"], t["ct"]):
            targets.pop(key, None)
            continue
        try:
            if nxt == "renice":
                t["orig_nice"] = sig.renice(p["pid"], _num(cfg, "guard_renice", int))
            elif nxt == "suspend":
                # Record FIRST: a sampler that dies right after the SIGSTOP must
                # leave a record a later pass resumes. No record, no SIGSTOP.
                t["suspended_at"] = now
                try:
                    if persist:
                        persist()
                except Exception:
                    t["suspended_at"] = None
                    raise
                try:   # best effort: the record + the sweep are the primary path
                    getattr(sig, "schedule_resume")(p["pid"], _num(cfg, "guard_suspend_max_s", int) + 120)
                except Exception:
                    pass
                try:
                    sig.suspend(p["pid"])
                except Exception:
                    t["suspended_at"] = None
                    raise
            else:
                sig.terminate(p["pid"])
        except Exception as e:  # AccessDenied / gone: log, never crash the sampler
            log("error", nxt, p, reason=repr(e)[:120])
            continue
        t["step"] += 1
        t["wait"] = 0
        t["would"] = None
        acts.append(now)
        log("act", nxt, p)
    return out


def undo(g: dict, sig: Signaller | None = None) -> list[str]:
    """Resume every process the guard paused and restore every nice it changed.

    A change that could NOT be undone (the process is still there, the call
    failed) keeps its record in ``g`` and yields a line starting with
    "could not" -- never a silent success."""
    sig = sig or Signaller()
    lines, kept = [], {}
    for key, t in list(g.get("targets", {}).items()):
        if not sig.same(t["pid"], t["ct"]):
            continue   # gone (or the pid was reused): nothing of ours left to undo
        failed = False
        if t.get("suspended_at"):
            try:
                sig.resume(t["pid"])
                t["suspended_at"] = None
                lines.append(f"resumed {t['name']} (pid {t['pid']})")
            except Exception as e:
                if not _gone(e):
                    failed = True
                    lines.append(f"could not resume {t['name']} (pid {t['pid']}): {e!r}"[:200])
        if "orig_nice" in t:
            try:
                sig.set_nice(t["pid"], t["orig_nice"])
                lines.append(f"restored nice {t['orig_nice']} on {t['name']} (pid {t['pid']})")
                t.pop("orig_nice")
            except Exception as e:
                if not _gone(e):
                    failed = True
                    lines.append(f"could not restore nice {t['orig_nice']} on {t['name']} (pid {t['pid']}): "
                                 f"{e!r} -- the record is kept"[:240])
        if failed:
            kept[key] = t
    g["targets"] = kept
    g["streak"] = {}
    return lines


def summary(g: dict, log_rows: list[dict], cfg: dict, now: float | None = None) -> dict:
    now = now or time.time()
    day = [r for r in log_rows if now - r.get("ts", 0) < 86400]
    return {"mode": mode_of(cfg),
            "acts_24h": sum(1 for r in day if r.get("kind") == "act"),
            "would_24h": sum(1 for r in day if r.get("kind") == "would"),
            "suspended": [t["name"] for t in g.get("targets", {}).values() if t.get("suspended_at")],
            "allow": _list(cfg, "guard_allow"), "kill": cfg.get("guard_allow_kill") is True,
            "last": (day[-1] if day else None)}
