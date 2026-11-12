"""Step 3: the LLM reads the institution's policy.

Task A, coverage check (Art. 8.6): for each required topic, does the policy contain a clause with a concrete
obligation? The answer must cite clause ids; citations are verified against the policy, and an 'addressed' answer
without a valid citation is downgraded (grounding check).

Task B, rule translation: turn the policy clause(s) behind a technical criterion into an executable Rego rule
against the input contract. A deterministic validator gates every rule before human review: JSON shape, package
name, forbidden built-ins, compilation, input fields, and the seeded test cases.

A TF-IDF keyword baseline (no LLM) answers Task A as a comparison point for RQ1.
"""
import json
import re
import subprocess
import tempfile
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from .config import ROOT, opa_path
from .llm_client import parse_json
from .seeded_cases import CASES, subject

CAT = ROOT / "catalogue"
RULES = ROOT / "rules"
OPA = None  # resolved lazily by config.opa_path()


def load_catalogue():
    reqs = {r["id"]: r for r in json.loads((CAT / "cbuae_requirements.json").read_text(encoding="utf-8"))["requirements"]}
    crit = {c["id"]: c for c in json.loads((CAT / "criteria.json").read_text(encoding="utf-8"))["criteria"]}
    return reqs, crit


def flatten(policy):
    rows = []
    for s in policy["sections"]:
        for c in s.get("clauses", []):
            rows.append({"id": c["id"], "section": f'{s["id"]} {s["title"]}', "text": c["text"]})
        for sub in s.get("subsections", []):
            for c in sub["clauses"]:
                rows.append({"id": c["id"], "section": f'{sub["id"]} {sub["title"]}', "text": c["text"]})
    return rows


def topic_query(c, reqs):
    """What the regulation asks for under this DOC criterion (measure name for 8.6.3 sub-criteria)."""
    base = reqs[c["cbuae"][0]]["text"]
    if c["id"].startswith("DOC-8.6.3-"):
        return c["title"].replace("Policy addresses ", "")
    return base


# ------------------------------------------------------------------ Task A: coverage
COVERAGE_SYSTEM = """You are a compliance analyst assessing whether a financial institution's ICT and cybersecurity
policy addresses the topics required by Article 8.6 of the CBUAE Operational Risk Management Regulation.
A topic is ADDRESSED only if at least one clause states a concrete obligation for it: who must do what, by when,
or a measurable threshold. A clause that only mentions the topic, states an intention, or uses words such as
"important", "encouraged", "may" or "will consider" without a concrete obligation does NOT address it. The
obligation may appear under any heading and in any wording; judge the meaning, not the vocabulary.
Answer with JSON only."""


def coverage_prompt(policy, topics, reqs):
    clauses = "\n".join(f'[{c["id"]}] ({c["section"]}) {c["text"]}' for c in flatten(policy))
    tl = "\n".join(f'- {c["id"]}: {topic_query(c, reqs)}' for c in topics)
    return f"""Required topics (criterion id: what the regulation requires):
{tl}

Policy clauses ([clause id] (section) text):
{clauses}

Return JSON exactly in this form, one entry per topic, in the same order:
{{"results": [{{"criterion": "<id>", "addressed": true|false, "clause_ids": ["<clause id>", ...],
  "reason": "<one sentence>"}}]}}
Cite every clause that states the obligation. If not addressed, clause_ids is []."""


def check_coverage(llm, policy, reqs, crit):
    """One call per policy. A malformed answer never stops the run: topics the model did not answer in the required
    form are returned with answered=False and are scored as wrong, not silently dropped or guessed."""
    topics = [c for c in crit.values() if c["level"] == "document"]
    raw = llm.complete(COVERAGE_SYSTEM, coverage_prompt(policy, topics, reqs))
    try:
        results = parse_json(raw).get("results", [])
    except (ValueError, AttributeError):
        results = []
    valid_ids = {c["id"] for c in flatten(policy)}
    got = {r.get("criterion"): r for r in results if isinstance(r, dict)} if isinstance(results, list) else {}
    out = []
    for c in topics:
        r = got.get(c["id"], {})
        ids = r.get("clause_ids", [])
        cited = [x for x in (ids if isinstance(ids, list) else []) if isinstance(x, str)]
        bad = [x for x in cited if x not in valid_ids]
        answered = isinstance(r.get("addressed"), bool)
        addressed = r.get("addressed") is True and bool(set(cited) & valid_ids)  # grounding: needs a real citation
        out.append({"criterion": c["id"], "answered": answered, "addressed": addressed,
                    "model_said_addressed": r.get("addressed") is True,
                    "clause_ids": ";".join(x for x in cited if x in valid_ids), "invalid_citations": ";".join(bad),
                    "reason": str(r.get("reason", ""))})
    return out


class KeywordBaseline:
    """TF-IDF similarity between each topic and each clause; addressed if the best match exceeds a threshold
    tuned on training variants. No understanding of obligations: the point of comparison for the LLM."""

    def __init__(self, reqs, crit):
        self.reqs, self.topics = reqs, [c for c in crit.values() if c["level"] == "document"]
        self.threshold = 0.2

    def scores(self, policy):
        clauses = flatten(policy)
        docs = [f'{c["section"]} {c["text"]}' for c in clauses]
        queries = [topic_query(t, self.reqs) for t in self.topics]
        vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2)).fit(docs + queries)
        sim = (vec.transform(queries) @ vec.transform(docs).T).toarray()
        return {t["id"]: (float(sim[i].max()), clauses[int(sim[i].argmax())]["id"]) for i, t in enumerate(self.topics)}

    def fit(self, policies, key):
        """Pick the threshold that maximises F1 on the given (training) variants."""
        s = [(self.scores(p)[c][0], t) for name, p in policies.items()
             for c, t in key[key.entity == name][["criterion", "truth"]].itertuples(index=False)]
        best = (-1, 0.2)
        for th in np.linspace(0.02, 0.8, 79):
            tp = sum(1 for v, t in s if v < th and t == "nonconforming")
            fp = sum(1 for v, t in s if v < th and t == "conforming")
            fn = sum(1 for v, t in s if v >= th and t == "nonconforming")
            f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0
            best = max(best, (f1, th))
        self.threshold = best[1]
        return self

    def check(self, policy):
        return [{"criterion": c, "addressed": v >= self.threshold, "score": round(v, 3), "clause_ids": cid}
                for c, (v, cid) in self.scores(policy).items()]


# ------------------------------------------------------------------ Task B: rule translation
TRANSLATE_SYSTEM = """You translate clauses of a financial institution's ICT and cybersecurity policy into executable
Open Policy Agent rules (Rego v1) that test evidence for conformity. Follow the input contract exactly: use only the
fields it lists, plus the helpers in data.cbuae.lib. Do not use http.send, net.*, opa.runtime or any external data.
The rule must define the set `scope` (entity ids assessed this period) and the set `violations` (objects
{"entity": <id>, "detail": <string>}). Answer with JSON only."""

PACKAGE_EXAMPLE = {"AC-01": "ac01.rego"}


def package_for(cid):
    return "cbuae.gen." + cid.lower().replace("-", "")


def translate_prompt(cid, crit, reqs, policy_clauses):
    c = crit[cid]
    contract = (RULES / "INPUT_CONTRACT.md").read_text(encoding="utf-8")
    lib = (RULES / "cbuae" / "lib.rego").read_text(encoding="utf-8")
    example_id = "AC-04" if cid == "AC-01" else "AC-01"
    example = (RULES / "cbuae" / f'{example_id.lower().replace("-", "")}.rego').read_text(encoding="utf-8")
    cl = "\n".join(f"[{p}] {policy_clauses[p]}" for p in c["policy_clauses"])
    cb = "\n".join(f"[Art. {a}] {reqs[a]['text']}" for a in c["cbuae"])
    return f"""Criterion {cid}: {c['title']}
CBUAE requirement(s):
{cb}
Institution policy clause(s):
{cl}
Pass condition: {c['pass_condition']}
Entity assessed: {c['entity']}

INPUT CONTRACT
{contract}

HELPER LIBRARY (data.cbuae.lib, already available)
{lib}

EXAMPLE of a finished rule for another criterion ({example_id}); note the style, not the logic:
{example}

Write the rule for {cid} in package {package_for(cid)}.
Return JSON: {{"package": "{package_for(cid)}", "rego": "<complete Rego v1 module>", "assumptions": ["<any interpretation you made>"]}}"""


FORBIDDEN = re.compile(r"\b(http\.send|net\.\w+|opa\.runtime|io\.jwt|time\.now_ns)\b")


def _fields(rego):
    """input.<path> references with dynamic keys normalised, e.g. input.params.services[x].encrypted."""
    return set(re.findall(r"input\.([A-Za-z_][\w.]*)", rego))


ALLOWED_TOP = {"period", "params", "identities", "entitlements", "last_use", "authentications", "firewall_rules", "flows"}
ALLOWED_PARAMS = {"leaver_grace_days", "review_window_ms", "directory_assets", "sod_pairs", "role_baselines",
                  "zone_matrix", "services", "port_service", "assets", "entitlements"}
ALLOWED_PERIOD = {"id", "start", "end", "data_start"}


def validate_rule(cid, response_text):
    """Deterministic gate before human review. Returns (report, rego_or_None)."""
    rep = {"criterion": cid, "checks": {}}
    try:
        data = parse_json(response_text)
        rego = data["rego"]
        rep["assumptions"] = data.get("assumptions", [])
        rep["checks"]["json"] = True
    except Exception as e:  # noqa: BLE001
        rep["checks"]["json"] = False
        rep["error"] = f"unparseable response: {e}"
        return rep, None
    pkg = package_for(cid)
    rep["checks"]["package"] = bool(re.search(rf"^package\s+{re.escape(pkg)}\s*$", rego, re.M))
    rep["checks"]["no_forbidden_builtins"] = not FORBIDDEN.search(rego)
    bad = []
    for f in _fields(rego):
        parts = f.split(".")
        if parts[0] not in ALLOWED_TOP or (parts[0] == "params" and len(parts) > 1 and parts[1] not in ALLOWED_PARAMS) \
                or (parts[0] == "period" and len(parts) > 1 and parts[1] not in ALLOWED_PERIOD):
            bad.append(f)
    rep["checks"]["fields_in_contract"] = not bad
    rep["unknown_fields"] = sorted(bad)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "lib.rego").write_text((RULES / "cbuae" / "lib.rego").read_text(encoding="utf-8"), encoding="utf-8")
        (td / "rule.rego").write_text(rego, encoding="utf-8")
        r = subprocess.run([opa_path(), "check", "--v1-compatible", str(td)], capture_output=True, text=True, encoding="utf-8")
        rep["checks"]["compiles"] = r.returncode == 0
        if r.returncode != 0:
            rep["compile_error"] = r.stderr[:1500]
        else:
            results = []
            for crit, name, inp, expected in CASES:
                if crit != cid:
                    continue
                (td / "input.json").write_text(json.dumps(inp), encoding="utf-8")
                q = "data." + pkg
                o = subprocess.run([opa_path(), "eval", "--v1-compatible", "--format", "json", "-d", str(td / "lib.rego"),
                                    "-d", str(td / "rule.rego"), "-i", str(td / "input.json"), q], capture_output=True, text=True, encoding="utf-8")
                who = subject(crit, inp)
                try:
                    val = json.loads(o.stdout)["result"][0]["expressions"][0]["value"]
                    flagged = sorted({v["entity"] for v in val.get("violations", [])})
                    scope = sorted(set(val.get("scope", [])))
                except Exception:  # noqa: BLE001
                    flagged = scope = None
                want = [who] if expected else []
                results.append({"case": name, "expected": expected, "got": None if flagged is None else len(flagged),
                                "pass": flagged == want, "scope": scope, "scope_pass": scope == [who]})
            rep["seeded_cases"] = results
            rep["checks"]["seeded_cases"] = bool(results) and all(x["pass"] for x in results)
            # a rule must also say whom it assessed: exactly the entity the case is about, no more and no fewer
            rep["checks"]["seeded_scope"] = bool(results) and all(x["scope_pass"] for x in results)
    rep["status"] = "pending_review" if all(rep["checks"].values()) else "rejected_by_validator"
    return rep, rego


def translate(llm, cid, reqs, crit, policy_clauses):
    text = llm.complete(TRANSLATE_SYSTEM, translate_prompt(cid, crit, reqs, policy_clauses))
    rep, rego = validate_rule(cid, text)
    return rep, rego, text
