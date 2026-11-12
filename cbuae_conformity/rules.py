"""Run Rego rule sets with Open Policy Agent over every period and score them against the answer key.

The same runner evaluates the reference rules (rules/cbuae, written by the researcher from the policy clauses) and
LLM-generated rules (Step 3), so the two can be compared on behaviour, not wording.
"""
import json
import subprocess
from pathlib import Path

import pandas as pd

from .config import ROOT, opa_path

OPA = None  # resolved lazily by config.opa_path()
# criterion -> (package, scope set, violation set)
LAYOUT = {
    "AC-01": ("ac01", "scope", "violations"), "AC-02": ("ac02", "scope", "violations"),
    "AC-03": ("ac03", "scope", "violations"), "AC-04": ("ac04", "scope", "violations"),
    "AC-05": ("ac05", "scope", "violations"), "AC-07": ("ac07", "scope", "violations"),
    "AC-08": ("ac08", "scope", "violations"), "NW-01": ("nw", "rule_scope", "nw01"),
    "NW-02": ("nw", "rule_scope", "nw02"), "NW-03": ("nw", "rule_scope", "nw03"),
    "NW-04": ("nw", "flow_scope", "nw04"), "NW-05": ("nw", "cia_flow_scope", "nw05"),
}


def opa_eval(rule_dir: Path, input_path: Path) -> dict:
    r = subprocess.run([opa_path(), "eval", "--v1-compatible", "--format", "json", "-d", str(rule_dir),
                        "-i", str(input_path), "data.cbuae"], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:2000])
    return json.loads(r.stdout)["result"][0]["expressions"][0]["value"]


def determinations(rule_dir: Path, input_paths, layout=LAYOUT) -> pd.DataFrame:
    rows = []
    for path in input_paths:
        period = json.loads(path.read_text(encoding="utf-8"))["period"]["id"]
        out = opa_eval(rule_dir, path)
        for crit, (pkg, scope_key, viol_key) in layout.items():
            res = out
            for part in pkg.split("."):          # nested packages, e.g. "gen.ac02" -> data.cbuae.gen.ac02
                res = res.get(part, {}) if isinstance(res, dict) else {}
            bad = {}
            for v in res.get(viol_key, []):
                bad.setdefault(v["entity"], []).append(v["detail"])
            for ent in set(res.get(scope_key, [])) | set(bad):
                rows.append({"criterion": crit, "entity": ent, "period": period,
                             "determination": "nonconforming" if ent in bad else "conforming",
                             "detail": ";".join(sorted(bad.get(ent, [])))[:300]})
    return pd.DataFrame(rows)


def score(det: pd.DataFrame, key: pd.DataFrame, split=None) -> pd.DataFrame:
    """Per-criterion confusion matrix. A truth case the checker did not assess counts as 'missed scope'."""
    k = key if split is None else key[key.split == split]
    m = k.merge(det, on=["criterion", "entity", "period"], how="outer", indicator=True)
    out = []
    for crit, g in m.groupby("criterion"):
        both = g[g._merge == "both"]
        tp = ((both.truth == "nonconforming") & (both.determination == "nonconforming")).sum()
        fp = ((both.truth == "conforming") & (both.determination == "nonconforming")).sum()
        fn = ((both.truth == "nonconforming") & (both.determination == "conforming")).sum()
        tn = ((both.truth == "conforming") & (both.determination == "conforming")).sum()
        missed = g[g._merge == "left_only"]
        fn += (missed.truth == "nonconforming").sum()
        extra = g[g._merge == "right_only"]
        fp += (extra.determination == "nonconforming").sum()
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / (tp + fn) if tp + fn else float("nan")
        out.append({"criterion": crit, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec,
                    "f1": 2 * prec * rec / (prec + rec) if prec + rec else float("nan"),
                    "cases_not_assessed": len(missed), "assessed_not_in_key": len(extra)})
    return pd.DataFrame(out)
