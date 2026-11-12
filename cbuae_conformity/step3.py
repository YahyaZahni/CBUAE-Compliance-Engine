"""Step 3 command line: LLM policy reader experiments (RQ1).

  python -m cbuae_conformity.step3 inputs       # per-period rule inputs + reference (OPA) rule results
  python -m cbuae_conformity.step3 coverage     # Art. 8.6 coverage on every policy variant: LLM vs keyword baseline
  python -m cbuae_conformity.step3 translate    # clause -> Rego for each technical criterion, validated
  python -m cbuae_conformity.step3 evaluate     # behaviour of validated/approved rules on the evidence
  python -m cbuae_conformity.step3 review       # start the reviewer UI (http://127.0.0.1:5000)

The LLM is configured with environment variables (see llm_client.py). Results go to data/step3/.
"""
import argparse
import json
import shutil
from pathlib import Path

import pandas as pd
from sklearn.metrics import cohen_kappa_score

from . import rules
from .config import ROOT
from .llm_client import LLM, LLMError
from .policy_reader import KeywordBaseline, check_coverage, flatten, load_catalogue, package_for, translate

EV = ROOT / "data" / "processed" / "evidence"
OUT = ROOT / "data" / "step3"
CAND = OUT / "rule_candidates"
APPROVED = ROOT / "rules" / "approved"
RULE_CRITERIA = ["AC-01", "AC-02", "AC-03", "AC-04", "AC-05", "AC-07", "AC-08", "NW-01", "NW-02", "NW-03", "NW-04", "NW-05"]


def load_variants():
    vdir = EV / "policy" / "variants"
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(vdir.glob("POLICY-V*.json"))}


def metrics(df, pred_col="pred", truth_col="truth"):
    """Positive class = nonconforming (topic not addressed)."""
    y = df[truth_col].eq("nonconforming")
    p = df[pred_col].eq("nonconforming")
    tp, fp, fn = int((y & p).sum()), int((~y & p).sum()), int((y & ~p).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    # "no_answer" (malformed model output) is never correct: it is a miss on a nonconforming topic and an error on a
    # conforming one, so accuracy compares the labels themselves.
    return {"n": len(df), "tp": tp, "fp": fp, "fn": fn, "tn": int((~y & df[pred_col].eq("conforming")).sum()),
            "no_answer": int(df[pred_col].eq("no_answer").sum()), "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else float("nan"),
            "accuracy": float((df[pred_col] == df[truth_col]).mean()),
            "kappa": float(cohen_kappa_score(df[truth_col], df[pred_col])) if y.nunique() > 1 else float("nan")}


def coverage(llm):
    reqs, crit = load_catalogue()
    variants = load_variants()
    key = pd.read_csv(EV / "truth" / "answer_key_policy.csv")
    names = sorted(variants)
    train = [n for n in names if n != "POLICY-V00"][: (len(names) - 1) // 2]
    test = [n for n in names if n not in train]
    kb = KeywordBaseline(reqs, crit).fit({n: variants[n] for n in train}, key)
    rows = []
    for n in names:
        for r in kb.check(variants[n]):
            rows.append({"method": "keyword_tfidf", "entity": n, "criterion": r["criterion"],
                         "pred": "conforming" if r["addressed"] else "nonconforming", "clause_ids": r["clause_ids"]})
        if llm is not None:
            try:
                for r in check_coverage(llm, variants[n], reqs, crit):
                    rows.append({"method": f"llm:{llm.model or llm.provider}", "entity": n, "criterion": r["criterion"],
                                 "pred": "no_answer" if not r["answered"] else "conforming" if r["addressed"] else "nonconforming",
                                 "clause_ids": r["clause_ids"],
                                 "invalid_citations": r["invalid_citations"], "ungrounded": r["model_said_addressed"] and not r["addressed"]})
            except LLMError as e:
                print("LLM skipped:", e)
                llm = None
    res = pd.DataFrame(rows).merge(key, on=["entity", "criterion"])
    res["split"] = res.entity.map(lambda n: "train" if n in train else "test")
    OUT.mkdir(parents=True, exist_ok=True)
    res.to_csv(OUT / "coverage_predictions.csv", index=False)
    summary = []
    for (m, sp), g in res.groupby(["method", "split"]):
        summary.append({"method": m, "split": sp, "edit": "all", **metrics(g)})
        for e, ge in g.groupby("edit"):
            summary.append({"method": m, "split": sp, "edit": e, "n": len(ge),
                            "accuracy": float((ge.pred == ge.truth).mean())})
    s = pd.DataFrame(summary)
    s.to_csv(OUT / "coverage_metrics.csv", index=False)
    print(f"keyword threshold (fit on {len(train)} training variants): {kb.threshold:.2f}")
    return s


def translate_all(llm, criteria):
    reqs, crit = load_catalogue()
    policy = json.loads((ROOT / "catalogue" / "sample_policy.json").read_text(encoding="utf-8"))
    clauses = {c["id"]: c["text"] for c in flatten(policy)}
    CAND.mkdir(parents=True, exist_ok=True)
    rows = []
    for cid in criteria:
        try:
            rep, rego, raw = translate(llm, cid, reqs, crit, clauses)
        except LLMError as e:
            print("LLM unavailable:", e)
            break
        stem = cid.lower().replace("-", "")
        (CAND / f"{stem}.json").write_text(json.dumps({"report": rep, "raw_response": raw}, indent=2), encoding="utf-8")
        if rego:
            (CAND / f"{stem}.rego").write_text(rego, encoding="utf-8")
        rows.append({"criterion": cid, "status": rep["status"], **{k: v for k, v in rep["checks"].items()}})
    df = pd.DataFrame(rows)
    if len(df):
        df.to_csv(OUT / "translation_validation.csv", index=False)
    return df


def evaluate(rule_source):
    """Run generated rules (candidates that passed the validator, or reviewer-approved ones) on every period and
    compare with the answer key and with the reference rules."""
    src = CAND if rule_source == "candidates" else APPROVED
    work = OUT / "eval_rules"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    shutil.copy(ROOT / "rules" / "cbuae" / "lib.rego", work / "lib.rego")
    layout = {}
    for cid in RULE_CRITERIA:
        stem = cid.lower().replace("-", "")
        rego, meta = src / f"{stem}.rego", CAND / f"{stem}.json"
        ok = rego.exists() and (rule_source == "approved" or
                                json.loads(meta.read_text(encoding="utf-8"))["report"]["status"] == "pending_review")
        if ok:
            shutil.copy(rego, work / f"{stem}.rego")
            layout[cid] = (package_for(cid).replace("cbuae.", ""), "scope", "violations")
    inputs = sorted((ROOT / "data" / "processed" / "rule_inputs").glob("period_*.json"))
    key = pd.read_csv(EV / "truth" / "answer_key_technical.csv")
    if not layout:
        print("no rules to evaluate")
        return None
    det = rules.determinations(work, inputs, layout)
    ref = pd.read_csv(ROOT / "data" / "processed" / "reference_rule_determinations.csv")
    sc = rules.score(det, key[key.criterion.isin(layout)])
    agree = det.merge(ref, on=["criterion", "entity", "period"], how="outer", suffixes=("_gen", "_ref")).fillna("not_assessed")
    sc["agreement_with_reference"] = sc.criterion.map(
        agree.groupby("criterion").apply(lambda g: float((g.determination_gen == g.determination_ref).mean())))
    sc.to_csv(OUT / f"translation_behaviour_{rule_source}.csv", index=False)
    return sc


def build_inputs():
    from .config import load_config
    from .rule_input import EvidenceView
    paths = EvidenceView(EV, load_config()).write_all(ROOT / "data" / "processed" / "rule_inputs")
    det = rules.determinations(ROOT / "rules" / "cbuae", paths)
    det.to_csv(ROOT / "data" / "processed" / "reference_rule_determinations.csv", index=False)
    key = pd.read_csv(EV / "truth" / "answer_key_technical.csv")
    sc = rules.score(det, key[key.criterion.isin(rules.LAYOUT)])   # AC-06 is judgement-based: no rule, see Step 4
    OUT.mkdir(parents=True, exist_ok=True)
    sc.to_csv(OUT / "reference_rules_vs_answer_key.csv", index=False)
    return sc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["inputs", "coverage", "translate", "evaluate", "review"])
    ap.add_argument("--criteria", default=",".join(RULE_CRITERIA))
    ap.add_argument("--rules", choices=["candidates", "approved"], default="candidates")
    ap.add_argument("--no-llm", action="store_true", help="coverage: keyword baseline only")
    a = ap.parse_args()
    pd.set_option("display.width", 200)
    if a.cmd == "inputs":
        print(build_inputs().to_string(index=False))
    elif a.cmd == "coverage":
        print(coverage(None if a.no_llm else LLM()).to_string(index=False))
    elif a.cmd == "translate":
        print(translate_all(LLM(), a.criteria.split(",")).to_string(index=False))
    elif a.cmd == "evaluate":
        r = evaluate(a.rules)
        if r is not None:
            print(r.to_string(index=False))
    else:
        from .review_app import app
        app.run(host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
