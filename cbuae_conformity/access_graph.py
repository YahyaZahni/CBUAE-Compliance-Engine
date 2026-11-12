"""Step 4: the access graph for the judgement-based least-privilege criterion (AC-06), and non-GNN baselines.

One snapshot per period, built ONLY from the rule inputs (processed evidence): identities with their role and
business function, entitlements held at the end of the period, the asset of each entitlement, and assets actually
used within the review window. Clear-cut access criteria (AC-01..AC-05, AC-07, AC-08) are handled by the Rego
rules; this graph is used where a rule cannot decide: is an APPROVED entitlement justified by the holder's role?

Candidate edges (what is scored): entitlements held by enabled humans that are outside their role baseline. A
baseline entitlement is justified by definition (POL-AC-01), so the rule part filters it out; the model judges the
rest.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from .config import Config


@dataclass
class Snapshot:
    period: int
    identities: pd.DataFrame          # identity, kind, role, function
    holds: pd.DataFrame               # identity, entitlement, asset_id, in_baseline, used_recently
    used: pd.DataFrame                # identity, asset_id (used within review window)
    candidates: pd.DataFrame = field(default=None)   # holds rows to score (non-baseline, human)


def load_snapshots(input_dir: Path, cfg: Config):
    snaps = []
    for p in sorted(input_dir.glob("period_*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        end, window = d["period"]["end"], d["params"]["review_window_ms"]
        base = {r: set(v) for r, v in d["params"]["role_baselines"].items()}
        ent_asset = {e: v["asset_id"] for e, v in d["params"]["entitlements"].items()}
        ids = pd.DataFrame([i for i in d["identities"] if i["created_at"] <= end and (i["disabled_at"] is None or i["disabled_at"] > end)])
        ids = ids[["identity", "kind", "role"]].copy()
        ids["role"] = ids.role.fillna("")
        ids["function"] = ids.role.map(lambda r: cfg.role_function.get(r, "none"))
        enabled = set(ids.identity)
        held = pd.DataFrame([e for e in d["entitlements"] if e["granted_at"] <= end < e["revoked_at"] and e["identity"] in enabled])
        held = held[["identity", "entitlement"]].drop_duplicates()
        held["asset_id"] = held.entitlement.map(ent_asset)
        role = dict(zip(ids.identity, ids.role))
        held["in_baseline"] = [e in base.get(role.get(i, ""), set()) for i, e in zip(held.identity, held.entitlement)]
        lu = pd.DataFrame(d["last_use"]) if d["last_use"] else pd.DataFrame(columns=["identity", "asset_id", "t"])
        used = lu[lu.t >= end - window][["identity", "asset_id"]].drop_duplicates()
        held = held.merge(used.assign(used_recently=True), on=["identity", "asset_id"], how="left")
        held["used_recently"] = held.used_recently.fillna(False).astype(bool)
        kind = dict(zip(ids.identity, ids.kind))
        cand = held[~held.in_baseline & held.identity.map(kind).eq("human")].reset_index(drop=True)
        snaps.append(Snapshot(d["period"]["id"], ids.reset_index(drop=True), held.reset_index(drop=True), used, cand))
    return snaps


# ------------------------------------------------------------------ baselines (anomaly score: higher = less justified)
def peer_score(s: Snapshot, level: str) -> np.ndarray:
    """1 - share of OTHER enabled identities in the same role (or business function) holding the entitlement."""
    grp = dict(zip(s.identities.identity, s.identities[level]))
    size = s.identities.groupby(level).size()
    holders = s.holds.assign(g=s.holds.identity.map(grp)).groupby(["g", "entitlement"]).size()
    out = []
    for i, e in zip(s.candidates.identity, s.candidates.entitlement):
        g = grp[i]
        others = size.get(g, 1) - 1
        share = (holders.get((g, e), 0) - 1) / others if others > 0 else 0.0
        out.append(1.0 - share)
    return np.array(out)


BASELINES = {"role_peer_frequency": lambda s: peer_score(s, "role"),
             "function_peer_frequency": lambda s: peer_score(s, "function")}


def cases_from_scores(s: Snapshot, scores: np.ndarray, threshold: float, method: str):
    """Identity-level determinations (AC-06 case unit). Scope = enabled humans holding entitlements."""
    humans = set(s.identities.loc[s.identities.kind == "human", "identity"]) & set(s.holds.identity)
    flagged = {}
    for (i, e), v in zip(s.candidates[["identity", "entitlement"]].itertuples(index=False), scores):
        if v >= threshold:
            flagged.setdefault(i, []).append(f"{e}:{v:.2f}")
    best = {}
    for i, v in zip(s.candidates.identity, scores):
        best[i] = max(best.get(i, 0.0), float(v))
    return [{"criterion": "AC-06", "entity": i, "period": s.period, "method": method,
             "determination": "nonconforming" if i in flagged else "conforming",
             "score": best.get(i, 0.0), "detail": ";".join(flagged.get(i, []))} for i in sorted(humans)]
