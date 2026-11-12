"""Document-level answer key: versions of the sample policy for the Art. 8.6 coverage check (RQ1).

A topic counts as ADDRESSED when at least one clause states a concrete obligation (who must do what, or a
threshold) for that topic. Each variant applies one to three edits:
  removed      the topic's section is deleted                                   -> nonconforming
  hollow       the section keeps its heading but only mentions the topic,
               with no concrete obligation                                       -> nonconforming
  relocated    the section is deleted and an equivalent obligation, reworded
               without the topic's usual keywords, is placed in another section -> conforming
Removed topics are easy for keyword matching; hollow and relocated ones are the hard cases that test whether a
reader understands the obligation rather than the vocabulary. Variant 0 is the full policy.
"""
import copy
import json

import numpy as np
import pandas as pd

from .config import ROOT

TOPIC = {"DOC-8.6.1": "S1", "DOC-8.6.2": "S2", "DOC-8.6.3-AC": "S3.1", "DOC-8.6.3-IM": "S3.2", "DOC-8.6.3-CIA": "S3.3",
         "DOC-8.6.3-NS": "S3.4", "DOC-8.6.3-VND": "S3.5", "DOC-8.6.3-PHY": "S3.6", "DOC-8.6.3-VUL": "S3.7",
         "DOC-8.6.3-CLS": "S3.8", "DOC-8.6.4": "S4", "DOC-8.6.5": "S5", "DOC-8.6.6": "S6", "DOC-8.6.7": "S7",
         "DOC-8.6.8": "S8", "DOC-8.6.9": "S9"}

# Reworded obligations that avoid the topic's usual keywords (relocated variants).
REWORDED = {
    "DOC-8.6.1": "The Board signs off this document every year, and the CISO briefs the Board Risk Committee on technology exposure each quarter.",
    "DOC-8.6.2": "Each system has a named business lead who answers for its technology exposure; departures from this document need the CISO's written consent and lapse after 90 days.",
    "DOC-8.6.3-AC": "People receive only the system rights their job needs; anything beyond the standard set for their job needs a signed request, and rights are re-checked every 90 days.",
    "DOC-8.6.3-IM": "Every person, service account and AI agent gets its own log-in; log-ins of staff who leave are switched off within one working day, and every non-human log-in has a named staff member answerable for it.",
    "DOC-8.6.3-CIA": "Systems holding the institution's most important data are listed with their owner, location and sensitivity, are reachable only over approved encrypted protocols, and only by people granted rights to them.",
    "DOC-8.6.3-NS": "Traffic between the USER, SERVER, DATABASE, DMZ, MANAGEMENT and INTERNET areas is blocked unless the zone matrix allows it; Telnet, FTP and SMBv1 are never allowed.",
    "DOC-8.6.3-VND": "Outside firms that connect to our systems are assessed before they start and every year, and follow the same rules as staff.",
    "DOC-8.6.3-PHY": "Rooms housing servers and network equipment admit authorised staff only, are monitored, and are protected against fire, flood and power loss.",
    "DOC-8.6.3-VUL": "Systems are scanned for known weaknesses every month and internet-facing systems are attacked by testers every year; critical weaknesses are fixed within 15 days.",
    "DOC-8.6.3-CLS": "Every document and dataset is labelled Public, Internal, Confidential or Restricted, and data in the most important systems is labelled Confidential or Restricted.",
    "DOC-8.6.4": "The effectiveness of technology safeguards is measured continuously against the limits in this document and the risk appetite, and limit breaches go to the Steering Committee.",
    "DOC-8.6.5": "Owners of each dataset set how long it is kept, how its quality is assured and how it is destroyed; personal information follows UAE law.",
    "DOC-8.6.6": "Modifications to live systems are risk-rated, signed off and given a back-out plan, and supplier fixes are installed within 30 days, or 7 days for critical weaknesses on the most important systems.",
    "DOC-8.6.7": "Plans to respond to security events, keep the business running and restore systems after a disaster are kept current and rehearsed every year.",
    "DOC-8.6.8": "Every technology initiative assesses security risk when it starts and needs security sign-off before going live.",
    "DOC-8.6.9": "Software built or bought for the institution must meet secure coding requirements, including peer review and security testing before release.",
}
# Mentions without a concrete obligation (hollow variants).
HOLLOW = {
    "DOC-8.6.1": "Governance and oversight of ICT and cybersecurity are important to the institution.",
    "DOC-8.6.2": "The institution values risk ownership, accountability and compliance.",
    "DOC-8.6.3-AC": "Access controls are an important part of the institution's security.",
    "DOC-8.6.3-IM": "The institution recognises the importance of identity management.",
    "DOC-8.6.3-CIA": "Critical Information Assets deserve appropriate protection.",
    "DOC-8.6.3-NS": "Network security is a priority for the institution.",
    "DOC-8.6.3-VND": "Vendor management security will be considered where appropriate.",
    "DOC-8.6.3-PHY": "The institution is aware of physical and environmental security risks.",
    "DOC-8.6.3-VUL": "Vulnerability testing may be performed from time to time.",
    "DOC-8.6.3-CLS": "Information classification is encouraged.",
    "DOC-8.6.4": "ICT controls may be evaluated and monitored as needed.",
    "DOC-8.6.5": "Data management is acknowledged as an important area.",
    "DOC-8.6.6": "The institution aims for good ICT operations, change and patch management.",
    "DOC-8.6.7": "The institution intends to be prepared for incidents and disasters.",
    "DOC-8.6.8": "ICT projects should be managed well.",
    "DOC-8.6.9": "Systems development and acquisition should be secure.",
}


def _sections(p):
    for s in p["sections"]:
        yield s
        yield from s.get("subsections", [])


def clauses(policy):
    """Clause repository: every clause with a stable id, its section and its text."""
    return [{"clause_id": c["id"], "section": f'{s["id"]} {s["title"]}', "text": c["text"]}
            for s in _sections(policy) for c in s.get("clauses", [])]


def edit(policy, crit, kind, host_section):
    p = copy.deepcopy(policy)
    sid = TOPIC[crit]
    if kind in ("removed", "relocated"):
        p["sections"] = [s for s in p["sections"] if s["id"] != sid]
        for s in p["sections"]:
            if "subsections" in s:
                s["subsections"] = [x for x in s["subsections"] if x["id"] != sid]
    if kind == "hollow":
        for s in _sections(p):
            if s["id"] == sid:
                s["clauses"] = [{"id": f"POL-HOL-{crit.split('-', 1)[1]}", "text": HOLLOW[crit]}]
    if kind == "relocated":
        for s in _sections(p):
            if s["id"] == host_section and "clauses" in s:
                s["clauses"].append({"id": f"POL-REL-{crit.split('-', 1)[1]}", "text": REWORDED[crit]})
    return p


def build(out_dir, n_variants, seed):
    policy = json.loads((ROOT / "catalogue" / "sample_policy.json").read_text(encoding="utf-8"))
    crit = [c["id"] for c in json.loads((ROOT / "catalogue" / "criteria.json").read_text(encoding="utf-8"))["criteria"] if c["level"] == "document"]
    assert set(crit) == set(TOPIC) == set(REWORDED) == set(HOLLOW), "topic tables out of sync with criteria.json"
    rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    key = []
    for v in range(n_variants + 1):
        pv, edits = policy, {}
        if v:
            chosen = list(rng.choice(sorted(TOPIC), int(rng.integers(1, 4)), replace=False))
            for c in chosen:
                kind = ["removed", "hollow", "relocated"][int(rng.integers(3))]
                # relocated text goes into a section that no edit in this variant touches
                hosts = [s["id"] for s in _sections(pv) if "clauses" in s and s["id"] not in {TOPIC[x] for x in chosen}]
                host = hosts[int(rng.integers(len(hosts)))]
                pv = edit(pv, c, kind, host)
                edits[c] = (kind, host)
        pv = copy.deepcopy(pv)
        pv["variant"] = f"POLICY-V{v:02d}"
        (out_dir / f"POLICY-V{v:02d}.json").write_text(json.dumps(pv, indent=2), encoding="utf-8")
        for c in crit:
            kind = edits.get(c, ("none", ""))[0]
            key.append({"criterion": c, "entity": f"POLICY-V{v:02d}",
                        "truth": "nonconforming" if kind in ("removed", "hollow") else "conforming",
                        "edit": kind, "relocated_to": edits.get(c, ("", ""))[1] if kind == "relocated" else ""})
    return pd.DataFrame(key)
