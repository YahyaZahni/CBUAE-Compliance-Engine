import numpy as np
import pandas as pd
import pytest

from cbuae_conformity.access_graph import BASELINES, cases_from_scores, load_snapshots
from cbuae_conformity.config import ROOT, load_config

INPUTS = ROOT / "data" / "processed" / "rule_inputs"
pytestmark = pytest.mark.skipif(not INPUTS.exists(), reason="run `python -m cbuae_conformity.step3 inputs` first")


@pytest.fixture(scope="module")
def snaps():
    return load_snapshots(INPUTS, load_config())


def test_candidates_exclude_baseline_and_nonhuman(snaps):
    s = snaps[-1]
    kind = dict(zip(s.identities.identity, s.identities.kind))
    assert not s.candidates.in_baseline.any()
    assert set(s.candidates.identity.map(kind)) <= {"human"}


def test_baseline_scores_in_range(snaps):
    for fn in BASELINES.values():
        v = fn(snaps[-1])
        assert ((v >= 0) & (v <= 1)).all()


def test_case_scope_matches_answer_key(snaps):
    key = pd.read_csv(ROOT / "data" / "processed" / "evidence" / "truth" / "answer_key_technical.csv")
    s = snaps[-1]
    det = pd.DataFrame(cases_from_scores(s, np.zeros(len(s.candidates)), 0.5, "x"))
    k = key[(key.criterion == "AC-06") & (key.period == s.period)]
    assert set(det.entity) == set(k.entity)


def test_gnn_trains_and_scores(snaps):
    gnn = pytest.importorskip("cbuae_conformity.gnn")
    model = gnn.train(snaps[:3], load_config(), epochs=3, seed=0)
    a = gnn.anomaly(model, snaps[-1])
    assert len(a) == len(snaps[-1].candidates) and ((a >= 0) & (a <= 1)).all()


def test_gnn_same_seed_same_scores(snaps):
    """Regression test for reproducibility: one seed must give identical scores when training is repeated, and the
    seed must matter. If this fails, results in data/step4/ cannot be reproduced even on the same machine."""
    gnn = pytest.importorskip("cbuae_conformity.gnn")
    cfg = load_config()
    a, b, c = (gnn.anomaly(gnn.train(snaps[:3], cfg, epochs=3, seed=sd), snaps[-1], seed=0) for sd in (0, 0, 1))
    assert np.array_equal(a, b)
    assert not np.array_equal(a, c)
    assert gnn.fingerprint(snaps[:3]) == gnn.fingerprint(snaps[:3]) != gnn.fingerprint(snaps[:2])


def test_amazon_eval_on_kaggle_format(tmp_path):
    pytest.importorskip("torch_geometric")
    from cbuae_conformity import amazon_eval
    rng = np.random.default_rng(0)
    rows = []
    for _ in range(600):  # small file in the Kaggle column layout: approvals follow role family, denials do not
        fam = int(rng.integers(5))
        approved = rng.random() < 0.85
        res = fam * 10 + int(rng.integers(3)) if approved else int(rng.integers(50))
        rows.append({"ACTION": int(approved), "RESOURCE": res, "MGR_ID": fam * 100 + int(rng.integers(4)),
                     "ROLE_ROLLUP_1": 1, "ROLE_ROLLUP_2": fam, "ROLE_DEPTNAME": fam, "ROLE_TITLE": int(rng.integers(3)),
                     "ROLE_FAMILY_DESC": fam, "ROLE_FAMILY": fam, "ROLE_CODE": fam * 10 + int(rng.integers(2))})
    p = tmp_path / "train.csv"
    pd.DataFrame(rows).to_csv(p, index=False)
    out = amazon_eval.run(p, folds=3, epochs=5).set_index("method")
    assert {"gnn", "peer_ROLE_CODE"} <= set(out.index)
    assert out.roc_auc.between(0, 1).all()
