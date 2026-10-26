"""The R3 recording demo must keep working as the others change their code (run in its own process)."""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "r03_demo.py"


def test_the_r03_demo_runs_and_tells_the_story():
    run = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-1500:]
    for expected in ("ALREADY_VOTED", "Has Victor been marked off? False", "WRONG_DIVISION", "POLLS_NOT_OPEN",
                     "vera     IN_PERSON", "victor   ONLINE"):
        assert expected in run.stdout, f"missing in demo output: {expected}"
