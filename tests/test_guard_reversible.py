"""The guard's promise: every action is REVERSIBLE, and nothing it pauses can stay paused.

Two review blockers live here, each pinned by a test that was red before the fix:

  1. A paused (SIGSTOP) process could stay paused forever. The only thing that
     resumed it was a LATER sample reading ``suspended_at`` back from the state
     file, and that record reached the disk only at the very end of the sample
     (after a security audit that can take minutes), with a non-atomic write and
     no lock. Any death of the sampler in between (systemd timeout, OOM kill,
     logout), ``aegis sentinel --pause`` / uninstall, or a concurrent writer lost
     it -- and a stopped process reads 0 % CPU, so nothing ever went back to it.
  2. A renice could not be undone (Linux RLIMIT_NICE 0, macOS always for a
     non-root user), and ``undo`` swallowed the EPERM, said nothing, and dropped
     the original nice for good.
"""
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from macmon_core import guard


class FakeSig(guard.Signaller):
    """A Signaller that never touches a real process (restorable unless told otherwise)."""

    def __init__(self, restorable=True, set_nice_error=None):
        self.calls, self.nice = [], {}
        self.restorable, self.set_nice_error = restorable, set_nice_error

    def same(self, pid, ct):
        return True

    def can_restore_nice(self, pid, value=None):
        return self.restorable

    def renice(self, pid, inc):
        self.calls.append(("renice", pid))
        old = self.nice.get(pid, 0)
        self.nice[pid] = old + inc
        return old

    def set_nice(self, pid, value):
        self.calls.append(("set_nice", pid, value))
        if self.set_nice_error:
            raise self.set_nice_error
        self.nice[pid] = value

    def schedule_resume(self, pid, after_s):
        self.calls.append(("schedule_resume", pid, after_s))
        return True

    def suspend(self, pid):
        self.calls.append(("suspend", pid))

    def resume(self, pid):
        self.calls.append(("resume", pid))

    def terminate(self, pid):
        self.calls.append(("terminate", pid))


def proc(pid=500, name="tracker-miner-fs-3", cpu=99.0, user="me", ct=1000.0, status="running"):
    return {"pid": pid, "ppid": 1000, "name": name, "cpu": cpu, "user": user, "cmd": name, "ct": ct,
            "rss": 10**8, "status": status}


def cfg(**kw):
    c = dict(guard.DEFAULTS)
    c.update(kw)
    return c


ACT = dict(guard_mode="act", guard_sustain=1, guard_step_samples=0, guard_suspend_max_s=300)


def step(table, c, g, now, sig, **kw):
    return guard.step(table, c, g, now=now, sig=sig, self_pids=set(), units_of=lambda pid: [], me="me", **kw)


# ── 1. a pause is on disk BEFORE the SIGSTOP ─────────────────────────────

def test_suspend_record_is_persisted_before_the_sigstop():
    disk = []

    class Watch(FakeSig):
        def suspend(self, pid):
            # what a sampler killed RIGHT NOW would leave behind
            rec = disk[-1]["targets"] if disk else {}
            assert any(t.get("suspended_at") for t in rec.values()), "SIGSTOP sent before the record hit the disk"
            super().suspend(pid)

    sig, g = Watch(), {}
    for i in range(6):
        step([proc()], cfg(**ACT), g, 60 * i, sig, persist=lambda: disk.append(json.loads(json.dumps(g))))
    assert ("suspend", 500) in sig.calls


def test_no_sigstop_when_the_record_cannot_be_persisted():
    def broken():
        raise OSError("disk full")

    sig, g, out = FakeSig(), {}, []
    for i in range(6):
        out += step([proc()], cfg(**ACT), g, 60 * i, sig, persist=broken)
    assert ("suspend", 500) not in sig.calls
    assert any(e["kind"] == "error" and e["step"] == "suspend" for e in out)
    assert not any(t.get("suspended_at") for t in g["targets"].values())


def test_suspend_schedules_an_independent_resume():
    sig, g = FakeSig(), {}
    for i in range(6):
        step([proc()], cfg(**ACT), g, 60 * i, sig)
    names = [c[0] for c in sig.calls]
    assert names.index("schedule_resume") < names.index("suspend")
    assert [c for c in sig.calls if c[0] == "schedule_resume"][0][2] >= 300


def test_a_lost_record_is_swept_back_to_running():
    """The reproduced bug: after the suspend the state is lost, a fresh guard state samples
    the stopped process (0 % CPU) 30 times and must resume it."""
    sig = FakeSig()
    g = {}
    for i in range(6):
        step([proc()], cfg(**ACT), g, 60 * i, sig)
    assert ("suspend", 500) in sig.calls
    fresh, sig2, out = {}, FakeSig(), []
    for i in range(30):
        out += step([proc(cpu=0.0, status="stopped")], cfg(**ACT), fresh, 1000 + 60 * i, sig2)
    assert ("resume", 500) in sig2.calls
    assert any(e["kind"] == "resume" and e["step"] == "sweep" for e in out)


@pytest.mark.parametrize("mode", ["off", "dry-run", "act"])
def test_the_sweep_runs_in_every_mode(mode):
    sig = FakeSig()
    step([proc(cpu=0.0, status="stopped")], cfg(guard_mode=mode), {}, 0, sig)
    assert sig.calls == [("resume", 500)]


@pytest.mark.parametrize("p", [
    proc(name="chrome", cpu=0.0, status="stopped"),         # the owner's app, stopped by hand
    proc(name="python3", cpu=0.0, status="stopped"),        # not on the allow-list
    proc(user="root", cpu=0.0, status="stopped"),           # another user's
    proc(cpu=0.0, status="tracing-stop"),                   # a debugger holds it
])
def test_the_sweep_never_touches_anything_else(p):
    sig = FakeSig()
    step([p], cfg(guard_mode="act"), {}, 0, sig)
    assert sig.calls == []


def test_the_sweep_leaves_a_recorded_pause_to_its_timer():
    sig, g = FakeSig(), {}
    for i in range(6):
        step([proc()], cfg(**ACT), g, 60 * i, sig)
    t0 = [t["suspended_at"] for t in g["targets"].values() if t.get("suspended_at")][0]
    sig2 = FakeSig()
    step([proc(cpu=0.0, status="stopped")], cfg(**ACT), g, t0 + 60, sig2)
    assert sig2.calls == []                       # still inside its 300 s pause
    step([proc(cpu=0.0, status="stopped")], cfg(**ACT), g, t0 + 300, sig2)
    assert ("resume", 500) in sig2.calls


def test_a_failed_resume_keeps_the_record():
    class Stuck(FakeSig):
        def resume(self, pid):
            raise PermissionError(1, "Operation not permitted")
    sig, g = FakeSig(), {}
    for i in range(6):
        step([proc()], cfg(**ACT), g, 60 * i, sig)
    out = step([proc(cpu=0.0, status="stopped")], cfg(**ACT), g, 10**6, Stuck())
    assert any(t.get("suspended_at") for t in g["targets"].values())
    assert any(e["kind"] == "error" for e in out)
    lines = guard.undo(g, Stuck())
    assert any(line.startswith("could not") for line in lines) and g["targets"]


# ── the state file: atomic, locked, never clobbered by a stale writer ────

@pytest.fixture
def sentinel_tmp(tmp_path, monkeypatch):
    from macmon_core import sentinel
    monkeypatch.setattr(sentinel, "ASTATE", tmp_path / "sentinel.state")
    monkeypatch.setattr(sentinel, "CONF", tmp_path / "sentinel.conf")
    monkeypatch.setattr(sentinel, "SYSTEM_CONF", tmp_path / "none.json")
    monkeypatch.setattr(sentinel, "MACMON_DIR", tmp_path)
    return sentinel


def _suspended_state():
    return {"guard": {"targets": {"500:1000": {"pid": 500, "ct": 1000.0, "name": "tracker-miner-fs-3", "step": 2,
                                               "wait": 0, "would": None, "suspended_at": 1.0, "orig_nice": 0}},
                      "streak": {}, "acts": []}}


def test_state_write_is_atomic(sentinel_tmp):
    s = sentinel_tmp
    s._write_astate({"a": 1})
    assert json.loads(s.ASTATE.read_text()) == {"a": 1}
    assert [p.name for p in s.ASTATE.parent.iterdir() if p.name.startswith("sentinel.state.")] in ([], ["sentinel.state.lock"])


def test_final_sample_write_never_clobbers_the_guard_section(sentinel_tmp):
    """The sampler read the state at its start; `aegis guard --undo` ran meanwhile. The
    sampler's last write must keep the guard section that is on disk."""
    s = sentinel_tmp
    s._write_astate({"guard": {"targets": {}, "streak": {}, "acts": []}, "ram": 5})
    stale = _suspended_state()
    stale["ram"] = 99
    s._commit_astate(stale)
    d = json.loads(s.ASTATE.read_text())
    assert d["guard"]["targets"] == {} and d["ram"] == 99


@pytest.mark.skipif(os.name == "nt", reason="flock")
def test_undo_waits_for_the_state_lock(sentinel_tmp, monkeypatch):
    s = sentinel_tmp
    s._write_astate(_suspended_state())
    monkeypatch.setattr(guard, "Signaller", FakeSig)
    order = []
    with s._astate_lock():
        th = threading.Thread(target=lambda: (s.run_guard(undo=True), order.append("undo")))
        th.start()
        time.sleep(0.4)
        order.append("released")
    th.join(10)
    assert order == ["released", "undo"]
    assert json.loads(s.ASTATE.read_text())["guard"]["targets"] == {}


@pytest.mark.parametrize("fn", ["pause", "uninstall"])
def test_pause_and_uninstall_resume_first(sentinel_tmp, monkeypatch, fn):
    s = sentinel_tmp
    s._write_astate(_suspended_state())
    seen = []

    class Rec(FakeSig):
        def resume(self, pid):
            seen.append(("resume", pid))
    monkeypatch.setattr(guard, "Signaller", Rec)
    monkeypatch.setattr(s, "_schedule_remove", lambda: seen.append(("remove",)))
    getattr(s, fn)()
    assert seen[0] == ("resume", 500) and ("remove",) in seen
    assert json.loads(s.ASTATE.read_text())["guard"]["targets"] == {}


# ── 2. renice only when it can be undone; a failed restore is kept + said ─

def test_renice_is_skipped_when_it_cannot_be_restored():
    sig, g, out = FakeSig(restorable=False), {}, []
    for i in range(8):
        out += step([proc()], cfg(**ACT), g, 60 * i, sig)
    assert not [c for c in sig.calls if c[0] == "renice"]
    assert ("suspend", 500) in sig.calls          # straight to the reversible pause
    skips = [e for e in out if e["kind"] == "skip"]
    assert len(skips) == 1 and "restore" in skips[0]["msg"]


def test_dry_run_also_says_renice_is_skipped():
    sig, out = FakeSig(restorable=False), []
    g = {}
    for i in range(5):
        out += step([proc()], cfg(guard_mode="dry-run", guard_sustain=1), g, 60 * i, sig)
    assert sig.calls == []
    assert [(e["kind"], e["step"]) for e in out] == [("skip", "renice"), ("would", "suspend")]


def test_undo_keeps_and_reports_a_nice_it_could_not_restore():
    g = {}
    for i in range(2):
        step([proc()], cfg(**{**ACT, "guard_step_samples": 50}), g, 60 * i, FakeSig())
    key = next(iter(g["targets"]))
    assert g["targets"][key]["orig_nice"] == 0
    lines = guard.undo(g, FakeSig(set_nice_error=PermissionError(1, "Operation not permitted")))
    assert len(lines) == 1 and lines[0].startswith("could not restore nice 0")
    assert g["targets"][key]["orig_nice"] == 0     # kept: a root helper or a later undo can still restore it
    ok = guard.undo(g, FakeSig())
    assert ok == ["restored nice 0 on tracker-miner-fs-3 (pid 500)"] and g["targets"] == {}


def test_mode_off_cli_reports_a_failed_restore(sentinel_tmp, monkeypatch, capsys):
    s = sentinel_tmp
    st = _suspended_state()
    st["guard"]["targets"]["500:1000"].update(suspended_at=None, orig_nice=0)
    s._write_astate(st)
    monkeypatch.setattr(guard, "Signaller", lambda: FakeSig(set_nice_error=PermissionError(1, "EPERM")))
    s.run_guard(mode="off")
    assert "could not restore" in capsys.readouterr().out
    assert json.loads(s.ASTATE.read_text())["guard"]["targets"]["500:1000"]["orig_nice"] == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX nice")
def test_real_signaller_predicts_restorability_honestly():
    """On a real process of ours: when can_restore_nice says yes, the round trip works;
    when it says no, the kernel refuses the restore (macOS non-root: always no)."""
    import psutil
    p = subprocess.Popen(["sleep", "30"])
    try:
        sig = guard.Signaller()
        orig = psutil.Process(p.pid).nice()
        predicted = sig.can_restore_nice(p.pid, orig)
        assert sig.renice(p.pid, 5) == orig
        try:
            sig.set_nice(p.pid, orig)
            restored = psutil.Process(p.pid).nice() == orig
        except (psutil.AccessDenied, PermissionError):
            restored = False
        assert predicted == restored
        if sys.platform == "darwin" and os.geteuid() != 0:
            assert predicted is False
    finally:
        p.kill()
        p.wait()


def test_a_sampler_killed_right_after_the_pause_leaves_the_record_on_disk(tmp_path, monkeypatch):
    """The end-to-end case: the sampler pauses a runaway, then dies (systemd timeout, OOM
    kill) before its last write. The pause record must already be on disk."""
    import getpass
    import types
    from macmon_core import sentinel
    for name in ("METRICS", "ASTATE", "SEQ", "CONF", "ALERTS_LOG"):
        monkeypatch.setattr(sentinel, name, tmp_path / name.lower())
    monkeypatch.setattr(sentinel, "SYSTEM_CONF", tmp_path / "none.json")
    monkeypatch.setattr(sentinel, "MACMON_DIR", tmp_path)
    sentinel.CONF.write_text(json.dumps({"guard_mode": "act", "guard_sustain": 1, "guard_step_samples": 0}))
    key = "999999:1000"
    sentinel.ASTATE.write_text(json.dumps({"guard": {"targets": {key: {"pid": 999999, "ct": 1000.0, "name": "tracker-miner-fs-3",
                                                        "step": 1, "wait": 0, "would": "suspend"}},
                                      "streak": {key: 5}, "acts": []}}))
    row = dict(proc(pid=999999), user=getpass.getuser(), ppid=1, exe="", terminal=None, ctime=1000.0)
    ns, ps = types.SimpleNamespace, sentinel.psutil
    monkeypatch.setattr(ps, "process_iter", lambda *a, **k: [])
    monkeypatch.setattr(ps, "cpu_percent", lambda interval=None: 12.0)
    monkeypatch.setattr(ps, "virtual_memory", lambda: ns(percent=60.0))
    monkeypatch.setattr(ps, "swap_memory", lambda: ns(used=1e9))
    monkeypatch.setattr(ps, "disk_usage", lambda p: ns(free=100e9))
    monkeypatch.setattr(sentinel, "load_average", lambda: (1.0, 1.0, 1.0))
    monkeypatch.setattr(sentinel, "_ping_rtt", lambda: None)
    monkeypatch.setattr(sentinel, "_notify", lambda *a, **k: None)
    monkeypatch.setattr(sentinel.subprocess, "run", lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError(cmd[0])))
    monkeypatch.setattr(sentinel.aegis, "scan", lambda: [dict(row)])
    sig = FakeSig()
    monkeypatch.setattr(guard, "Signaller", lambda: sig)

    def killed(*a, **k):
        raise SystemExit("killed by systemd (TimeoutStartSec)")
    monkeypatch.setattr(guard, "summary", killed)
    with pytest.raises(SystemExit):
        sentinel.run_sample()
    assert ("suspend", 999999) in sig.calls
    on_disk = json.loads(sentinel.ASTATE.read_text())["guard"]["targets"][key]
    assert on_disk["suspended_at"]


@pytest.mark.parametrize("variant", ["missing", "raises"])
def test_the_os_failsafe_is_best_effort(variant):
    """An integrator's duck-typed Signaller may not have schedule_resume, and the OS call
    may blow up: the pause (already recorded) still happens, the guard does not break."""
    class Duck(FakeSig):
        pass
    if variant == "missing":
        Duck.schedule_resume = property(lambda self: (_ for _ in ()).throw(AttributeError("schedule_resume")))
    else:
        def boom(self, pid, after_s):
            raise RuntimeError("no user bus")
        Duck.schedule_resume = boom
    sig, g, out = Duck(), {}, []
    for i in range(6):
        out += step([proc()], cfg(**ACT), g, 60 * i, sig)
    assert ("suspend", 500) in sig.calls
    assert not any(e["kind"] == "error" for e in out)
