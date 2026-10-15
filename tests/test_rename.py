"""The AegisForge rename (formerly macmon): `aegis` is the command, `macmon` a
deprecated alias that behaves the same plus one stderr line on a terminal; the
scheduler prefers an `aegis` launcher only when it is provably ours; every repo
URL names SoCloseSociety/AegisForge. Hermetic: no network, no live subprocess.
"""
import io
import json
import os
import re
import runpy
import sys
import tomllib
from pathlib import Path

import pytest

import macmon
from macmon_core import sentinel

REPO = Path(__file__).resolve().parent.parent


class _Stream(io.StringIO):
    def __init__(self, tty: bool):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


# ── entry points ─────────────────────────────────────────────────────────

class TestEntryPoints:
    def test_both_commands_are_declared(self):
        with open(REPO / "pyproject.toml", "rb") as f:
            scripts = tomllib.load(f)["project"]["scripts"]
        assert scripts["aegis"] == "macmon:app"
        assert scripts["macmon"] == "macmon:macmon_alias"

    def test_the_alias_runs_the_same_cli_with_one_notice_on_a_terminal(self, monkeypatch):
        err = _Stream(tty=True)
        seen = {}
        monkeypatch.setattr(sys, "stderr", err)
        monkeypatch.setattr(macmon, "app", lambda **kw: seen.update(kw))
        monkeypatch.setenv(macmon.ALIAS_ENV, macmon.ALIAS)
        macmon.macmon_alias()
        assert seen == {"prog_name": "macmon"}
        assert err.getvalue() == macmon.DEPRECATION_NOTICE + "\n"
        assert "aegis" in macmon.DEPRECATION_NOTICE and "—" not in macmon.DEPRECATION_NOTICE
        # A child the CLI spawns is not an alias call: the marker is not inherited.
        assert macmon.ALIAS_ENV not in os.environ

    def test_the_alias_is_silent_when_scheduled(self, monkeypatch):
        """launchd / cron / schtasks run `macmon sentinel --sample` every 60s with
        stderr off a terminal: no line, or cron would mail it every minute."""
        err = _Stream(tty=False)
        monkeypatch.setattr(sys, "stderr", err)
        monkeypatch.setattr(macmon, "app", lambda **kw: None)
        macmon.macmon_alias()
        assert err.getvalue() == ""

    @staticmethod
    def _run_main(monkeypatch, argv, alias_env, tty=True):
        """Run macmon.py as `__main__` in-process (no subprocess): the same
        dispatch install.sh's wrappers reach. Returns (exit code, stdout, stderr)."""
        out, err = _Stream(tty=False), _Stream(tty=tty)
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        monkeypatch.setattr(sys, "argv", [str(REPO / "macmon.py"), *argv])
        if alias_env:
            monkeypatch.setenv(macmon.ALIAS_ENV, macmon.ALIAS)
        else:
            monkeypatch.delenv(macmon.ALIAS_ENV, raising=False)
        with pytest.raises(SystemExit) as exc:
            runpy.run_path(str(REPO / "macmon.py"), run_name="__main__")
        code = exc.value.code or 0
        return code, out.getvalue(), err.getvalue()

    def test_aegis_itself_never_prints_the_notice(self, monkeypatch):
        code, out, err = self._run_main(monkeypatch, ["--version"], alias_env=False)
        assert code == 0
        assert out.strip() == f"aegis {macmon.__version__}"
        assert macmon.DEPRECATION_NOTICE not in err

    def test_the_wrapper_alias_keeps_stdout_byte_identical(self, monkeypatch):
        """--json consumers of `macmon` see exactly what `aegis` prints; the
        notice goes to stderr only (install.sh's wrapper path)."""
        a = self._run_main(monkeypatch, ["--version"], alias_env=False)
        m = self._run_main(monkeypatch, ["--version"], alias_env=True)
        assert a[0] == m[0] == 0
        assert a[1] == m[1]
        assert m[2] == macmon.DEPRECATION_NOTICE + "\n"


# ── the scheduled launcher ───────────────────────────────────────────────

def _exe(path: Path, body: str) -> str:
    path.write_text(body)
    path.chmod(0o755)
    return str(path)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX exec bit")
class TestLauncherProbe:
    def test_a_verified_aegis_launcher_wins(self, tmp_path, monkeypatch):
        aegis = _exe(tmp_path / "aegis", "#!/bin/bash\nexec /x/python /x/macmon.py \"$@\"\n")
        legacy = _exe(tmp_path / "macmon", "#!/bin/bash\nexec /x/python /x/macmon.py \"$@\"\n")
        monkeypatch.setattr(sentinel.shutil, "which",
                            lambda name: {"aegis": aegis, "macmon": legacy}.get(name))
        assert sentinel.find_macmon() == aegis

    def test_the_pip_console_script_is_recognised(self, tmp_path, monkeypatch):
        aegis = _exe(tmp_path / "aegis", "#!/x/python\nimport sys\nfrom macmon import app\n"
                                          "if __name__ == '__main__':\n    sys.exit(app())\n")
        monkeypatch.setattr(sentinel.shutil, "which", lambda name: aegis if name == "aegis" else None)
        assert sentinel.find_macmon() == aegis

    def test_an_unrelated_aegis_is_never_scheduled(self, tmp_path, monkeypatch):
        other = _exe(tmp_path / "aegis", "#!/bin/sh\necho some other aegis tool\n")
        legacy = _exe(tmp_path / "macmon", "#!/bin/bash\nexec /x/python /x/macmon.py \"$@\"\n")
        monkeypatch.setattr(sentinel.shutil, "which",
                            lambda name: {"aegis": other, "macmon": legacy}.get(name))
        assert sentinel.find_macmon() == legacy
        monkeypatch.setattr(sentinel.shutil, "which", lambda name: other if name == "aegis" else None)
        monkeypatch.setattr(sentinel, "_AEGIS_CANDIDATES", ())
        monkeypatch.setattr(sentinel, "_MACMON_CANDIDATES", ())
        assert sentinel.find_macmon() is None

    def test_well_known_aegis_home_off_path(self, tmp_path, monkeypatch):
        aegis = _exe(tmp_path / "aegis", "#!/bin/bash\nexec /x/python /x/macmon.py \"$@\"\n")
        monkeypatch.setattr(sentinel.shutil, "which", lambda name: None)
        monkeypatch.setattr(sentinel, "_AEGIS_CANDIDATES", (str(tmp_path / "nope"), aegis))
        monkeypatch.setattr(sentinel, "_MACMON_CANDIDATES", ())
        assert sentinel.find_macmon() == aegis


# ── install.sh ───────────────────────────────────────────────────────────

class TestInstallScript:
    def test_installs_aegis_and_the_alias(self):
        sh = (REPO / "install.sh").read_text(encoding="utf-8")
        assert "install_wrapper aegis \"\"" in sh
        assert "install_wrapper macmon \"AEGISFORGE_INVOKED_AS=macmon \"" in sh
        assert macmon.ALIAS_ENV == "AEGISFORGE_INVOKED_AS"
        # State stays where existing installs keep it.
        assert 'MACMON_DIR="$HOME/.macmon"' in sh
        # Wrappers carry a marker sentinel._is_our_launcher recognises.
        assert '"$APP_DIR/macmon.py"' in sh


# ── repo URLs ────────────────────────────────────────────────────────────

_TEXT_SUFFIXES = {".py", ".md", ".toml", ".sh", ".yml", ".json", ".java", ".js", ".html", ".txt"}


_SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", "node_modules", "__pycache__",
              ".pytest_cache", ".claude", ".gradle", "tasks"}


def _tracked_text_files():
    """Source text files of the checkout (no git call: the suite stays hermetic)."""
    out = []
    for f in REPO.rglob("*"):
        rel = f.relative_to(REPO).parts
        if any(part in _SKIP_DIRS for part in rel[:-1]):
            continue
        if f.is_file() and f.suffix in _TEXT_SUFFIXES:
            out.append(f)
    return out


class TestRepoUrls:
    def test_no_live_reference_to_the_old_repo_name(self):
        """CHANGELOG history and this test are the only places the old name may stay."""
        old = re.compile(r"SoCloseSociety/macmon(?![_\w])")
        offenders = []
        for f in _tracked_text_files():
            if f.name in ("CHANGELOG.md", "test_rename.py") or not f.exists():
                continue
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if old.search(line) and "redirect" not in line:
                    offenders.append(f"{f.relative_to(REPO)}:{i}")
        assert offenders == []

    def test_android_update_points_at_the_new_repo_and_keeps_its_asset(self):
        manifest = json.loads((REPO / "apps/android/update/version.json").read_text())
        assert manifest["apkUrl"].startswith("https://github.com/SoCloseSociety/AegisForge/releases/download/")
        assert manifest["apkUrl"].endswith("/aegisforge-9.apk")
        java = (REPO / "apps/android/app/src/main/java/co/soclose/aegisforge/Updater.java").read_text()
        assert ("https://raw.githubusercontent.com/SoCloseSociety/AegisForge/main/"
                "apps/android/update/version.json") in java

    def test_readme_leads_with_the_no_install_one_liner(self):
        lines = (REPO / "README.md").read_text(encoding="utf-8").splitlines()
        h1 = next(i for i, l in enumerate(lines) if l.startswith("<h1"))
        assert lines[h1].startswith('<h1 align="center">AegisForge -- ')
        after = [l for l in lines[h1 + 1:] if l.strip()]
        assert after[:3] == ["```bash",
                             "uvx --from git+https://github.com/SoCloseSociety/AegisForge aegis gc --scan",
                             "```"]
        assert any("(formerly macmon)" in l for l in after[3:6])

    def test_readme_has_no_em_dash(self):
        assert "—" not in (REPO / "README.md").read_text(encoding="utf-8")


# ── autopilot daemon identity ────────────────────────────────────────────

class TestDaemonIdentity:
    @pytest.mark.parametrize("cmdline,ours", [
        (["/u/.venv/bin/python", "/u/.local/bin/aegis", "auto", "--start"], True),     # pip / uv aegis
        (["C:\\py\\python.exe", "C:\\py\\Scripts\\aegis.exe", "auto"], True),          # Windows launcher
        (["/u/.macmon/venv/bin/python", "/u/.macmon/app/macmon.py", "auto"], True),   # install.sh wrapper
        (["/u/.venv/bin/python", "/u/.local/bin/macmon", "auto"], True),              # legacy alias
        (["/usr/bin/python3", "/opt/aegis-tools/run.py"], False),                     # not ours
        (["/usr/sbin/sshd", "-D"], False),
    ])
    def test_the_daemon_is_recognised_by_any_of_our_launchers(self, monkeypatch, cmdline, ours):
        from macmon_core import autopilot

        class _P:
            def __init__(self, pid):
                pass

            def cmdline(self):
                return cmdline
        monkeypatch.setattr(autopilot.psutil, "Process", _P)
        assert autopilot._is_macmon_process(4242) is ours
