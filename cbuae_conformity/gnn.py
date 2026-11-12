"""Heterogeneous GNN for least privilege (AC-06), trained without AC-06 labels.

Graph: identity -has_role-> role -in_function-> function; identity -holds-> entitlement -on-> asset;
identity -used-> asset (within the review window); reverse edges added for message passing.
Node inputs: learnable embeddings for roles, functions, entitlements and assets (a fixed vocabulary from the
institution configuration); identities get only their kind, so an identity is represented by what it is connected
to, and the model applies to identities it has not seen (inductive).

Training is self-supervised link prediction on the training periods: hide part of the `holds` edges and learn to
recognise them against random identity-entitlement pairs. A held entitlement the model finds implausible for that
identity's role, function and usage receives a high anomaly score (1 - p). Labels from the answer key are used only
to choose the decision threshold on the validation periods, never for training.
Scoring is leakage-free: each candidate edge is scored by a model pass in which that edge is hidden (K folds).

Reproducibility: a seed fixes the initial weights, the hidden edges and the negative samples. Training also runs on
one CPU thread with PyTorch's deterministic algorithms (see deterministic()), so the same seed on the same machine
and library versions gives the same scores; tests/test_step4.py checks this. Across operating systems or library
versions the last digits of the arithmetic differ, and over 780 optimiser steps that is enough to move this model's
results, so GNN figures are comparable only within one environment (step4 records it in summary.json).
"""
import hashlib
import platform

import numpy as np
import torch
from torch import nn
from torch_geometric.data import HeteroData
from torch_geometric.nn import HeteroConv, SAGEConv

from .access_graph import Snapshot
from .config import Config

KINDS = ["human", "service_account", "ai_agent"]


def deterministic():
    """One CPU thread and deterministic kernels: the order in which floating-point sums are taken no longer depends
    on how many cores the machine has. The graphs are small (a few hundred nodes), so nothing is lost in speed."""
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True, warn_only=True)


def environment():
    """Where a result was produced. GNN numbers from two different environments are not expected to match."""
    import pandas
    import torch_geometric
    return {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
            "torch": torch.__version__, "torch_geometric": torch_geometric.__version__, "numpy": np.__version__,
            "pandas": pandas.__version__, "torch_threads": torch.get_num_threads(),
            "deterministic_algorithms": torch.are_deterministic_algorithms_enabled()}


def fingerprint(snaps) -> str:
    """Hash of exactly what the model is given, row order included (the hidden-edge mask depends on row order).
    Two runs with the same fingerprint trained on the same graphs; any difference then comes from the environment."""
    h = hashlib.sha256()
    for s in snaps:
        h.update(f"period={s.period}\n".encode())
        for name, cols in (("identities", ["identity", "kind", "role", "function"]), ("holds", ["identity", "entitlement"]),
                           ("used", ["identity", "asset_id"]), ("candidates", ["identity", "entitlement"])):
            h.update(name.encode())
            h.update(getattr(s, name)[cols].to_csv(index=False, lineterminator="\n").encode())
    return h.hexdigest()


class Vocab:
    def __init__(self, cfg: Config):
        self.role = {r: i for i, r in enumerate(sorted(cfg.roles) + [""])}
        self.function = {f: i for i, f in enumerate(sorted(set(cfg.role_function.values())) + ["none"])}
        self.ent = {e: i for i, e in enumerate(cfg.entitlements.entitlement)}
        self.asset = {a: i for i, a in enumerate(cfg.assets.asset_id)}
        self.role_function = dict(cfg.role_function)   # role -> business function
        self.ent_asset = dict(cfg.ent_asset)           # entitlement -> asset
        self.inv_ent = {i: e for e, i in self.ent.items()}


def to_graph(s: Snapshot, voc: Vocab, hide=None):
    """HeteroData for one snapshot. `hide`: boolean mask over s.holds rows whose edges are left out."""
    idx = {i: n for n, i in enumerate(s.identities.identity)}
    g = HeteroData()
    g["identity"].x = torch.tensor([[float(k == kind) for kind in KINDS] for k in s.identities.kind])
    g["role"].node_id = torch.arange(len(voc.role))
    g["function"].node_id = torch.arange(len(voc.function))
    g["entitlement"].node_id = torch.arange(len(voc.ent))
    g["asset"].node_id = torch.arange(len(voc.asset))

    def edges(src, dst):
        return torch.tensor([src, dst], dtype=torch.long) if len(src) else torch.zeros((2, 0), dtype=torch.long)

    g["identity", "has_role", "role"].edge_index = edges([idx[i] for i in s.identities.identity],
                                                         [voc.role.get(r, voc.role[""]) for r in s.identities.role])
    g["role", "in_function", "function"].edge_index = edges(
        list(voc.role.values())[:-1], [voc.function.get(f, voc.function["none"]) for f in
                                       [voc.role_function.get(r, "none") for r in list(voc.role)[:-1]]])
    h = s.holds if hide is None else s.holds[~hide]
    g["identity", "holds", "entitlement"].edge_index = edges([idx[i] for i in h.identity], [voc.ent[e] for e in h.entitlement])
    g["entitlement", "on", "asset"].edge_index = edges(list(voc.ent.values()), [voc.asset[voc.ent_asset[e]] for e in voc.ent])
    u = s.used[s.used.identity.isin(idx) & s.used.asset_id.isin(voc.asset)]
    g["identity", "used", "asset"].edge_index = edges([idx[i] for i in u.identity], [voc.asset[a] for a in u.asset_id])
    for (a, r, b) in list(g.edge_types):
        g[b, f"rev_{r}", a].edge_index = g[a, r, b].edge_index.flip(0)
    return g, idx


class Model(nn.Module):
    def __init__(self, voc: Vocab, metadata, dim=32, layers=2):
        super().__init__()
        self.emb = nn.ModuleDict({"role": nn.Embedding(len(voc.role), dim), "function": nn.Embedding(len(voc.function), dim),
                                  "entitlement": nn.Embedding(len(voc.ent), dim), "asset": nn.Embedding(len(voc.asset), dim)})
        self.id_in = nn.Linear(len(KINDS), dim)
        self.convs = nn.ModuleList([HeteroConv({et: SAGEConv((-1, -1), dim) for et in metadata[1]}, aggr="mean")
                                    for _ in range(layers)])
        self.dec = nn.Sequential(nn.Linear(3 * dim + 1, dim), nn.ReLU(), nn.Linear(dim, 1))

    def encode(self, g):
        x = {"identity": self.id_in(g["identity"].x)}
        for t in ("role", "function", "entitlement", "asset"):
            x[t] = self.emb[t](g[t].node_id)
        for conv in self.convs:
            out = conv(x, g.edge_index_dict)
            x = {k: torch.relu(out[k]) + x[k] if k in out else x[k] for k in x}  # residual keeps isolated nodes
        return x

    def score(self, x, ids, ents, used):
        hi, he = x["identity"][ids], x["entitlement"][ents]
        return self.dec(torch.cat([hi, he, hi * he, used.unsqueeze(1)], 1)).squeeze(1)


def _used_flag(s, idx, ids_list, ents_list, voc):
    """1.0 if the identity used the entitlement's asset within the review window (decoder input)."""
    used = set(zip(s.used.identity, s.used.asset_id))
    inv_id = {v: k for k, v in idx.items()}
    return torch.tensor([float((inv_id[i], voc.ent_asset[voc.inv_ent[e]]) in used) for i, e in zip(ids_list, ents_list)])


def train(snaps, cfg: Config, epochs=60, seed=0, dim=64, lr=0.01, hide_frac=0.3, negatives="uniform"):
    """Defaults chosen on the validation weeks (dim 64, uniform negatives, 60 epochs); see README."""
    deterministic()
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    voc = Vocab(cfg)
    g0, _ = to_graph(snaps[0], voc)
    model = Model(voc, g0.metadata(), dim)
    with torch.no_grad():
        model.encode(g0)  # initialise lazy layers
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    lossf = nn.BCEWithLogitsLoss()
    for _ in range(epochs):
        for s in snaps:
            hide = rng.random(len(s.holds)) < hide_frac
            g, idx = to_graph(s, voc, hide)
            pos = s.holds[hide]
            pi = [idx[i] for i in pos.identity]
            pe = [voc.ent[e] for e in pos.entitlement]
            held = set(zip(s.holds.identity, s.holds.entitlement))
            ids = list(idx)
            # negatives: "popularity" draws entitlements in proportion to how often they are held, so the model must
            # use role/function context rather than learn which entitlements are common; "uniform" draws at random
            pop = s.holds.entitlement.value_counts()
            ent_pool, ent_p = (pop.index.to_numpy(), (pop / pop.sum()).to_numpy()) if negatives == "popularity" else \
                (np.array(list(voc.ent)), None)
            ni, ne = [], []
            while len(ni) < len(pi):
                i = ids[rng.integers(len(ids))]
                e = rng.choice(ent_pool, p=ent_p)
                if (i, e) not in held:
                    ni.append(idx[i])
                    ne.append(voc.ent[e])
            x = model.encode(g)
            ai, ae = pi + ni, pe + ne
            logits = model.score(x, torch.tensor(ai), torch.tensor(ae), _used_flag(s, idx, ai, ae, voc))
            y = torch.tensor([1.0] * len(pi) + [0.0] * len(ni))
            loss = lossf(logits, y)
            opt.zero_grad()
            loss.backward()
            opt.step()
    model.voc = voc
    return model


@torch.no_grad()
def anomaly(model, s: Snapshot, k=5, seed=0):
    """Anomaly score (1 - p(edge)) for each candidate edge, with that edge hidden from the graph (K folds)."""
    model.eval()
    voc = model.voc
    out = np.zeros(len(s.candidates))
    if not len(s.candidates):
        return out
    key = list(zip(s.holds.identity, s.holds.entitlement))
    cand_rows = [key.index(t) for t in zip(s.candidates.identity, s.candidates.entitlement)]
    folds = np.random.default_rng(seed).integers(0, k, len(cand_rows))
    for f in range(k):
        sel = [n for n, ff in enumerate(folds) if ff == f]
        if not sel:
            continue
        hide = np.zeros(len(s.holds), bool)
        hide[[cand_rows[n] for n in sel]] = True
        g, idx = to_graph(s, voc, hide)
        x = model.encode(g)
        ids = [idx[s.candidates.identity[n]] for n in sel]
        ents = [voc.ent[s.candidates.entitlement[n]] for n in sel]
        p = torch.sigmoid(model.score(x, torch.tensor(ids), torch.tensor(ents), _used_flag(s, idx, ids, ents, voc)))
        out[sel] = 1 - p.numpy()
    model.train()
    return out
