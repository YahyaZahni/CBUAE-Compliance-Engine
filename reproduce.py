"""Rebuild every output of Steps 1 to 4 from the sources, then run all checks. One command, any OS:

    python reproduce.py            # everything (about 4 minutes on a laptop CPU)
    python reproduce.py --no-gnn   # skip Step 4 if PyTorch is not installed

Outputs: outputs/step1/, data/raw_sample/, data/processed/, data/step3/, data/step4/. No LLM is called; to add the
LLM experiments set LLM_PROVIDER / LLM_MODEL (see README) and run the `step3 coverage` and `step3 translate` commands.
"""
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from cbuae_conformity.config import opa_path  # noqa: E402

PY = [sys.executable, "-W", "ignore"]
STAGES = [
    ("Step 1  catalogue, OSCAL, sample policy", PY + ["catalogue/build_catalogue.py"]),
    ("Step 2  sample data, evidence base, answer key", PY + ["-m", "cbuae_conformity.pipeline", "sample"]),
    ("Step 3  rule inputs + reference rules", PY + ["-m", "cbuae_conformity.step3", "inputs"]),
    ("Step 3  coverage: keyword baseline", PY + ["-m", "cbuae_conformity.step3", "coverage", "--no-llm"]),
    ("Step 4  access graph, GNN and baselines", PY + ["-m", "cbuae_conformity.step4"]),
    ("Checks  pytest", PY + ["-m", "pytest", "-q", "tests"]),
    ("Checks  seeded Rego tests", [opa_path(), "test", "--v1-compatible", "rules/cbuae", "rules/tests"]),
]


def main():
    skip_gnn = "--no-gnn" in sys.argv
    for d in ("outputs", "data/raw_sample", "data/processed", "data/step3", "data/step4"):
        shutil.rmtree(ROOT / d, ignore_errors=True)
    for name, cmd in STAGES:
        if skip_gnn and name.startswith("Step 4"):
            continue
        print(f"\n=== {name}\n$ {' '.join(cmd[len(PY) - 2:] if cmd[0] == sys.executable else cmd)}", flush=True)
        t0 = time.time()
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            sys.exit(f"FAILED: {name}")
        print(f"--- done in {time.time() - t0:.0f}s", flush=True)
    print("\nAll stages completed.")


if __name__ == "__main__":
    main()
