"""Real-data test of the least-privilege method (RQ2) on the Amazon Employee Access data.

Why: in the built-in sample, 'appropriate' access is defined by the generator (same business function), so a
function-frequency heuristic mirrors the generator and the comparison is not informative. The Amazon data holds
real access decisions made by people: each row is a request by an employee (role attributes, manager) for a
resource, approved (ACTION=1) or denied (ACTION=0).

Method, identical in spirit to Step 4: the GNN learns from APPROVED access only (self-supervised link prediction);
denied requests are never used for training and serve as the positives ('access not justified by role') at test
time. Labels are used only for scoring.

Data: Kaggle "Amazon.com - Employee Access Challenge" train.csv (also on OpenML as dataset 4135), columns
ACTION, RESOURCE, MGR_ID, ROLE_ROLLUP_1, ROLE_ROLLUP_2, ROLE_DEPTNAME, ROLE_TITLE, ROLE_FAMILY_DESC, ROLE_FAMILY,
ROLE_CODE. Rows carry no timestamp, so the protocol is stratified 5-fold over requests; held-out requests are
removed from the graph before scoring.

  python -m cbuae_conformity.amazon_eval data/raw/amazon/train.csv
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from torch import nn
from torch_geometric.data import HeteroData
from torch_geometric.nn import HeteroConv, SAGEConv

ATTRS = ["MGR_ID", "ROLE_ROLLUP_1", "ROLE_ROLLUP_2", "ROLE_DEPTNAME", "ROLE_TITLE", "ROLE_FAMILY_DESC", "ROLE_FAMILY", "ROLE_CODE"]


def load(path):
    df = pd.read_csv(path)
    missing = {"ACTION", "RESOURCE", *ATTRS} - set(df.columns)
    if missing:
        raise ValueError(f"missing columns {missing}")
    df["profile"] = df[ATTRS].astype(str).agg("|".join, axis=1)   # an employee profile = role attributes + manager
    return df


class Index:
    def __init__(self, values):
        self.map = {v: i + 1 for i, v in enumerate(sorted(set(values)))}  # 0 = unseen

    def __call__(self, values):
        return torch.tensor([self.map.get(v, 0) for v in values], dtype=torch.long)

    def __len__(self):
        return len(self.map) + 1


def build_graph(df_edges, profiles, res_index, prof_index, attr_index):
    """profiles: DataFrame of unique profiles with their attributes; df_edges: approved requests used as messages."""
    g = HeteroData()
    g["profile"].node_id = torch.arange(len(prof_index))
    g["resource"].node_id = torch.arange(len(res_index))
    p = prof_index(profiles.profile)
    for a in ATTRS:
        g[a].node_id = torch.arange(len(attr_index[a]))
        g["profile", f"has_{a}", a].edge_index = torch.stack([p, attr_index[a](profiles[a])])
    g["profile", "approved", "resource"].edge_index = torch.stack([prof_index(df_edges.profile), res_index(df_edges.RESOURCE)])
    for (s, r, d) in list(g.edge_types):
        g[d, f"rev_{r}", s].edge_index = g[s, r, d].edge_index.flip(0)
    return g


class Model(nn.Module):
    def __init__(self, sizes, metadata, dim=32):
        super().__init__()
        self.emb = nn.ModuleDict({t: nn.Embedding(n, dim) for t, n in sizes.items()})
        self.convs = nn.ModuleList([HeteroConv({et: SAGEConv((-1, -1), dim) for et in metadata[1]}, aggr="mean") for _ in range(2)])
        self.dec = nn.Sequential(nn.Linear(3 * dim, dim), nn.ReLU(), nn.Linear(dim, 1))

    def forward(self, g, p, r):
        x = {t: self.emb[t](g[t].node_id) for t in self.emb}
        for conv in self.convs:
            out = conv(x, g.edge_index_dict)
            x = {k: torch.relu(out[k]) + x[k] if k in out else x[k] for k in x}
        hp, hr = x["profile"][p], x["resource"][r]
        return self.dec(torch.cat([hp, hr, hp * hr], 1)).squeeze(1)


def gnn_fold(train, test, seed=0, epochs=80, hide_frac=0.3):
    torch.set_num_threads(1)                                   # same reproducibility settings as gnn.deterministic()
    torch.use_deterministic_algorithms(True, warn_only=True)
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    allp = pd.concat([train, test]).drop_duplicates("profile")
    prof_index, res_index = Index(allp.profile), Index(train.RESOURCE)        # unseen test resources -> index 0
    attr_index = {a: Index(allp[a].astype(str)) for a in ATTRS}
    profiles = allp[["profile"] + ATTRS].astype(str)
    approved = train[train.ACTION == 1]
    sizes = {"profile": len(prof_index), "resource": len(res_index), **{a: len(attr_index[a]) for a in ATTRS}}
    g0 = build_graph(approved, profiles, res_index, prof_index, attr_index)
    model = Model(sizes, g0.metadata())
    with torch.no_grad():
        model(g0, torch.tensor([0]), torch.tensor([0]))
    opt = torch.optim.Adam(model.parameters(), lr=0.01)
    lossf = nn.BCEWithLogitsLoss()
    res_ids = np.array(sorted(res_index.map.values()))
    for _ in range(epochs):
        hide = rng.random(len(approved)) < hide_frac
        g = build_graph(approved[~hide], profiles, res_index, prof_index, attr_index)
        pos = approved[hide]
        p = prof_index(pos.profile)
        neg_r = torch.tensor(rng.choice(res_ids, len(pos)))
        logits = model(g, torch.cat([p, p]), torch.cat([res_index(pos.RESOURCE), neg_r]))
        y = torch.cat([torch.ones(len(pos)), torch.zeros(len(pos))])
        loss = lossf(logits, y)
        opt.zero_grad()
        loss.backward()
        opt.step()
    model.eval()
    with torch.no_grad():
        g = build_graph(approved, profiles, res_index, prof_index, attr_index)   # test requests are not in the graph
        s = torch.sigmoid(model(g, prof_index(test.profile), res_index(test.RESOURCE))).numpy()
    return 1 - s


def peer_fold(train, test, level):
    """1 - share of approved requests for this resource among training requests with the same attribute value."""
    a = train[train.ACTION == 1]
    tot = a.groupby(level).size()
    hit = a.groupby([level, "RESOURCE"]).size()
    return np.array([1 - hit.get((v, r), 0) / tot.get(v, 1) if tot.get(v, 0) else 1.0 for v, r in zip(test[level], test.RESOURCE)])


def run(path, folds=5, seed=0, epochs=80):
    df = load(path)
    y = (df.ACTION == 0).to_numpy()   # positive = denied = not justified
    scores = {m: np.zeros(len(df)) for m in ["gnn", "peer_ROLE_CODE", "peer_ROLE_FAMILY", "peer_MGR_ID"]}
    for tr, te in StratifiedKFold(folds, shuffle=True, random_state=seed).split(df, y):
        train, test = df.iloc[tr], df.iloc[te]
        scores["gnn"][te] = gnn_fold(train, test, seed=seed, epochs=epochs)
        for lvl in ("ROLE_CODE", "ROLE_FAMILY", "MGR_ID"):
            scores[f"peer_{lvl}"][te] = peer_fold(train, test, lvl)
    out = pd.DataFrame([{"method": m, "roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s),
                         "positive_rate": y.mean()} for m, s in scores.items()])
    return out


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    print(run(Path(sys.argv[1])).to_string(index=False))
