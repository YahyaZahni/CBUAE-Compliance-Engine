"""Reviewer UI for LLM-generated rules (Step 3: a person approves every rule before it is used).

Shows, for each candidate: the CBUAE text, the policy clause, the pass condition, the model's stated assumptions,
the validator results (including seeded test cases), behaviour on the evidence if evaluated, and the Rego code.
Approve copies the rule to rules/approved/; every decision is appended to data/step3/review_log.jsonl with the
reviewer, time, comment and the SHA-256 of the exact rule text approved (audit trail).
Run: python -m cbuae_conformity.step3 review
"""
import hashlib
import json
import shutil
import time

import pandas as pd
from flask import Flask, abort, redirect, render_template_string, request, url_for

from .config import ROOT
from .policy_reader import flatten, load_catalogue

OUT = ROOT / "data" / "step3"
CAND = OUT / "rule_candidates"
APPROVED = ROOT / "rules" / "approved"
LOG = OUT / "review_log.jsonl"
app = Flask(__name__)

STYLE = """<style>
body{font-family:system-ui,Arial,sans-serif;margin:32px auto;max-width:1100px;color:#1d2433;background:#f7f5f0}
h1{font-size:26px} h2{font-size:20px;margin-top:28px} table{border-collapse:collapse;width:100%;background:#fff}
td,th{border:1px solid #d9dce1;padding:6px 10px;text-align:left;vertical-align:top;font-size:14px}
th{background:#14213d;color:#fff} pre{background:#fff;border:1px solid #d9dce1;padding:12px;overflow:auto;font-size:13px}
.ok{color:#1b6b3a;font-weight:600} .bad{color:#b5480e;font-weight:600} .box{background:#fff;border:1px solid #d9dce1;padding:12px 16px}
button{padding:8px 18px;margin-right:8px;font-size:15px} input,textarea{width:100%;padding:6px;font-size:14px}
a{color:#14213d}</style>"""

INDEX = STYLE + """<h1>Rule review: LLM-generated rules</h1>
<p>Approve only rules whose logic matches the policy clause and the pass condition. Validator checks are a minimum, not proof.</p>
<table><tr><th>Criterion</th><th>Validator</th><th>Review decision</th></tr>
{% for r in rows %}<tr><td><a href="{{ url_for('detail', cid=r.cid) }}">{{ r.cid }}</a> {{ r.title }}</td>
<td class="{{ 'ok' if r.status=='pending_review' else 'bad' }}">{{ r.status }}</td><td>{{ r.decision }}</td></tr>{% endfor %}
</table>"""

DETAIL = STYLE + """<p><a href="{{ url_for('index') }}">&larr; all rules</a></p>
<h1>{{ cid }}: {{ c.title }}</h1>
<div class="box"><b>CBUAE</b>{% for a in c.cbuae %}<br>Art. {{ a }}: {{ reqs[a].text }}{% endfor %}
<br><br><b>Policy clause(s)</b>{% for p in c.policy_clauses %}<br>[{{ p }}] {{ clauses.get(p, '') }}{% endfor %}
<br><br><b>Pass condition</b><br>{{ c.pass_condition }}</div>
<h2>Validator</h2><table><tr><th>Check</th><th>Result</th></tr>
{% for k, v in rep.checks.items() %}<tr><td>{{ k }}</td><td class="{{ 'ok' if v else 'bad' }}">{{ 'pass' if v else 'FAIL' }}</td></tr>{% endfor %}</table>
{% if rep.compile_error %}<pre>{{ rep.compile_error }}</pre>{% endif %}
{% if rep.unknown_fields %}<p class="bad">Fields outside the input contract: {{ rep.unknown_fields|join(', ') }}</p>{% endif %}
{% if rep.seeded_cases %}<h2>Seeded test cases</h2><table><tr><th>Case</th><th>Expected violations</th><th>Got</th><th>Entities the rule assessed</th></tr>
{% for s in rep.seeded_cases %}<tr><td>{{ s.case }}</td><td>{{ s.expected }}</td><td class="{{ 'ok' if s.pass else 'bad' }}">{{ s.got }}</td>
<td class="{{ 'ok' if s.scope_pass else 'bad' }}">{{ (s.scope or [])|join(', ') }}</td></tr>{% endfor %}</table>{% endif %}
{% if behaviour %}<h2>Behaviour on the evidence (all periods)</h2><table><tr>{% for k in behaviour %}<th>{{ k }}</th>{% endfor %}</tr>
<tr>{% for v in behaviour.values() %}<td>{{ v }}</td>{% endfor %}</tr></table>{% endif %}
<h2>Model's assumptions</h2><ul>{% for a in rep.get('assumptions', []) %}<li>{{ a }}</li>{% else %}<li>none stated</li>{% endfor %}</ul>
<h2>Rule</h2><pre>{{ rego }}</pre>
<h2>Decision</h2>
{% if rep.status == 'pending_review' %}
<form method="post" action="{{ url_for('decide', cid=cid) }}">
<p>Reviewer <input name="reviewer" required></p><p>Comment <textarea name="comment" rows="3"></textarea></p>
<button name="decision" value="approved">Approve</button><button name="decision" value="rejected">Reject</button></form>
{% else %}<p class="bad">The validator rejected this rule; it cannot be approved. Regenerate it or fix it and re-run the validator.</p>{% endif %}
<h2>History</h2><ul>{% for h in history %}<li>{{ h.at }}: {{ h.decision }} by {{ h.reviewer }}: {{ h.comment }}</li>{% else %}<li>none</li>{% endfor %}</ul>"""


def _log():
    return [json.loads(x) for x in LOG.read_text(encoding="utf-8").splitlines()] if LOG.exists() else []


@app.route("/")
def index():
    _, crit = load_catalogue()
    last = {h["criterion"]: h["decision"] for h in _log()}
    rows = []
    for p in sorted(CAND.glob("*.json")):
        rep = json.loads(p.read_text(encoding="utf-8"))["report"]
        cid = rep["criterion"]
        rows.append({"cid": cid, "title": crit[cid]["title"], "status": rep["status"], "decision": last.get(cid, "not reviewed")})
    return render_template_string(INDEX, rows=rows)


@app.route("/rule/<cid>")
def detail(cid):
    reqs, crit = load_catalogue()
    if cid not in crit:
        abort(404)
    stem = cid.lower().replace("-", "")
    meta = CAND / f"{stem}.json"
    if not meta.exists():
        abort(404)
    rep = json.loads(meta.read_text(encoding="utf-8"))["report"]
    rego_path = CAND / f"{stem}.rego"
    policy = json.loads((ROOT / "catalogue" / "sample_policy.json").read_text(encoding="utf-8"))
    beh = None
    bpath = OUT / "translation_behaviour_candidates.csv"
    if bpath.exists():
        b = pd.read_csv(bpath)
        b = b[b.criterion == cid]
        if len(b):
            beh = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in b.iloc[0].to_dict().items()}
    return render_template_string(DETAIL, cid=cid, c=crit[cid], reqs=reqs, rep=rep, behaviour=beh,
                                  clauses={c["id"]: c["text"] for c in flatten(policy)},
                                  rego=rego_path.read_text(encoding="utf-8") if rego_path.exists() else "(no rule)",
                                  history=[h for h in _log() if h["criterion"] == cid])


@app.route("/rule/<cid>/decide", methods=["POST"])
def decide(cid):
    _, crit = load_catalogue()
    if cid not in crit:          # only catalogue ids reach the file system
        abort(404)
    stem = cid.lower().replace("-", "")
    meta = CAND / f"{stem}.json"
    if not meta.exists() or not (CAND / f"{stem}.rego").exists():
        abort(404)
    rep = json.loads(meta.read_text(encoding="utf-8"))["report"]
    decision, reviewer = request.form.get("decision"), request.form.get("reviewer", "").strip()
    if rep["status"] != "pending_review" or decision not in ("approved", "rejected") or not reviewer:
        abort(400)
    rego = (CAND / f"{stem}.rego").read_text(encoding="utf-8")
    entry = {"criterion": cid, "decision": decision, "reviewer": reviewer,
             "comment": request.form.get("comment", "").strip(), "rule_sha256": hashlib.sha256(rego.encode()).hexdigest(),
             "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    APPROVED.mkdir(parents=True, exist_ok=True)
    if decision == "approved":
        shutil.copy(CAND / f"{stem}.rego", APPROVED / f"{stem}.rego")
    elif (APPROVED / f"{stem}.rego").exists():
        (APPROVED / f"{stem}.rego").unlink()
    return redirect(url_for("detail", cid=cid))
