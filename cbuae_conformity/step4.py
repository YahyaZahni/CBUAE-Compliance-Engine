"""Step 4 command line: access conformity (RQ2).

  python -m cbuae_conformity.step4            # train/evaluate the GNN and baselines for AC-06, combine with rules

Protocol (time-based, Arp et al. 2022; Pendlebury et al. 2019):
  train periods       GNN fitted by self-supervised link prediction (no AC-06 labels)
  validation periods  one decision threshold per method chosen to maximise F1 against the answer key
  test periods        reported once: precision, recall, F1, edge-level PR-AUC, McNemar's test vs each baseline
GNN results are averaged over 5 seeds (mean and standard deviation). McNemar's exact test is run once per seed
against each baseline and all five results are reported, so the conclusion does not hang on one training run.

summary.json records the environment (operating system, library versions, thread count) and a fingerprint of the
graphs the model was given. GNN figures are reproducible within one environment, not across environments: quote
them together with the environment, and compare two runs only after checking that their fingerprints match.
"""
import json

import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.metrics import average_precision_score

from .access_graph import BASELINES, cases_from_scores, load_snapshots
from .config import ROOT, load_config

EV = ROOT / "data" / "processed" / "evidence"
OUT = ROOT / "data" / "step4"


def prf(det, key):
    """Scores a method on the answer-key cases of the periods it assessed. A key case the method did not assess
    counts as a miss if it is nonconforming (same convention as rules.score)."""
    k = key[key.period.isin(set(det.period))]
    m = k.merge(det, on=["criterion", "entity", "period"], how="left")
    y, p = m.truth.eq("nonconforming"), m.determination.eq("nonconforming")
    tp, fp, fn = int((y & p).sum()), int((~y & p).sum()), int((y & ~p).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0, "cases": len(k),
            "key_cases_not_assessed": int(m.determination.isna().sum()),
            "assessed_not_in_key": len(det) - int(m.determination.notna().sum())}


def best_threshold(snaps, scores, key, method):
    cands = np.unique(np.concatenate([s for s in scores if len(s)] + [np.array([1.01])]))
    best = (-1.0, 1.01)
    for th in cands:
        det = pd.DataFrame([c for s, sc in zip(snaps, scores) for c in cases_from_scores(s, sc, th, method)])
        best = max(best, (prf(det, key)["f1"], float(th)))
    return best[1]


def edge_truth(snaps, inj):
    bad = set(zip(inj.loc[inj.criterion == "AC-06", "entity"], inj.loc[inj.criterion == "AC-06", "entitlement"]))
    return np.concatenate([[(i, e) in bad for i, e in zip(s.candidates.identity, s.candidates.entitlement)] for s in snaps])


def mcnemar(a, b, key):
    """Exact McNemar test on paired test cases (a, b: determinations of two methods)."""
    m = a.merge(b, on=["criterion", "entity", "period"], suffixes=("_a", "_b")).merge(key, on=["criterion", "entity", "period"])
    ra = m.determination_a.eq(m.truth)
    rb = m.determination_b.eq(m.truth)
    n01, n10 = int((ra & ~rb).sum()), int((~ra & rb).sum())
    p = binomtest(n01, n01 + n10, 0.5).pvalue if n01 + n10 else 1.0
    return {"a_right_b_wrong": n01, "a_wrong_b_right": n10, "p_value": p}


def run(seeds=(0, 1, 2, 3, 4), epochs=60):
    from . import gnn  # torch is only needed here
    cfg = load_config()
    snaps = load_snapshots(ROOT / "data" / "processed" / "rule_inputs", cfg)
    split = pd.read_csv(EV / "periods.csv").set_index("period").split
    key_all = pd.read_csv(EV / "truth" / "answer_key_technical.csv")
    key = key_all[key_all.criterion == "AC-06"][["criterion", "entity", "period", "truth"]]
    inj = pd.read_csv(EV / "truth" / "injections.csv")
    by = {sp: [s for s in snaps if split[s.period] == sp] for sp in ("train", "validation", "test")}
    OUT.mkdir(parents=True, exist_ok=True)
    rows, dets, gnn_dets = [], {}, {}
    y_edge = edge_truth(by["test"], inj)

    def evaluate(name, score_fn, seed=None):
        val = [score_fn(s) for s in by["validation"]]
        th = best_threshold(by["validation"], val, key, name)
        test = [score_fn(s) for s in by["test"]]
        det = pd.DataFrame([c for s, sc in zip(by["test"], test) for c in cases_from_scores(s, sc, th, name)])
        r = {"method": name, "seed": seed, "threshold": th, **prf(det, key),
             "edge_pr_auc": average_precision_score(y_edge, np.concatenate(test)) if y_edge.any() else float("nan")}
        return r, det

    for name, fn in BASELINES.items():
        r, det = evaluate(name, fn)
        rows.append(r)
        dets[name] = det
    for seed in seeds:
        model = gnn.train(by["train"], cfg, epochs=epochs, seed=seed)
        r, det = evaluate("gnn_hetero_sage", lambda s: gnn.anomaly(model, s, seed=seed), seed)
        rows.append(r)
        gnn_dets[seed] = det
    dets["gnn_hetero_sage"] = gnn_dets[seeds[0]]   # determinations kept on file: first seed
    res = pd.DataFrame(rows)
    res.to_csv(OUT / "ac06_test_metrics_by_run.csv", index=False)
    summary = res.groupby("method")[["precision", "recall", "f1", "edge_pr_auc"]].agg(["mean", "std"]).round(3)
    summary.to_csv(OUT / "ac06_test_metrics_summary.csv")
    tests = [{"comparison": f"gnn_hetero_sage vs {b}", "seed": sd, **mcnemar(gnn_dets[sd], dets[b], key)}
             for b in BASELINES for sd in seeds]
    pd.DataFrame(tests).to_csv(OUT / "ac06_mcnemar.csv", index=False)
    pd.concat(dets.values()).to_csv(OUT / "ac06_test_determinations.csv", index=False)

    # combined access checker on the test periods: Rego rules for clear-cut criteria + GNN for AC-06
    ref = pd.read_csv(ROOT / "data" / "processed" / "reference_rule_determinations.csv")
    test_periods = set(split[split == "test"].index)
    ref = ref[ref.criterion.str.startswith("AC") & ref.period.isin(test_periods)]
    combined = pd.concat([ref.assign(method="rego_reference"),
                          dets["gnn_hetero_sage"].drop(columns=["score"])], ignore_index=True)
    combined.to_csv(OUT / "access_determinations_test.csv", index=False)
    key_test = key_all[key_all.criterion.str.startswith("AC") & key_all.period.isin(test_periods)]
    per_crit = pd.DataFrame([{"criterion": c, "checker": "GNN" if c == "AC-06" else "Rego rule",
                              **prf(combined[combined.criterion == c], key_test[key_test.criterion == c])}
                             for c in sorted(key_test.criterion.unique())])
    per_crit.to_csv(OUT / "access_checker_test_by_criterion.csv", index=False)
    g = res[res.method == "gnn_hetero_sage"]
    (OUT / "summary.json").write_text(json.dumps({
        "seeds": list(seeds), "epochs": epochs, "periods": {k: len(v) for k, v in by.items()},
        "test_edges": int(len(y_edge)), "test_inappropriate_edges": int(y_edge.sum()),
        "gnn_f1_by_seed": {int(sd): round(float(f), 4) for sd, f in zip(g.seed, g.f1)},
        "input_fingerprint": gnn.fingerprint(snaps), "environment": gnn.environment()}, indent=2), encoding="utf-8")
    return summary, pd.DataFrame(tests), per_crit


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    s, t, c = run()
    print(s.to_string(), "\n", t.to_string(index=False), "\n", c.to_string(index=False))
