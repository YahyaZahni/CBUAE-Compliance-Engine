# CBUAE conformity engine: Steps 1 to 4

Prototype for the MSc thesis *LLM- and GNN-Based Continuous Conformity Assessment of UAE Financial Institutions
Against CBUAE Requirements* (Yahya Zahni, University of Wollongong in Dubai). It checks whether a Licensed Financial
Institution conforms to the access-control and network-security requirements of the CBUAE Operational Risk
Management Regulation (Circular C 1/2026, Articles 7 and 8), using public information only.

This README describes what each step does, how to run it, what the results are, what the review of 10 November 2026
found and fixed, and what the work cannot yet claim. The first section is a one-page progress summary.

## Progress summary (as of 12 November 2026)

**In one sentence:** the end-to-end pipeline for Steps 1 to 4 is built, tested and reproducible with one command on a
synthetic sample; the experiments that answer the research questions (LLM runs for RQ1, real public data for RQ2)
have not been run yet.

| Step | What it does | Status |
|---|---|---|
| 1. Decide what to check | In-scope CBUAE sub-articles (verbatim), a fictional institution policy, 29 assessment criteria | complete |
| 2. Gather evidence, create the answer key | Dataset loaders, entity resolution, OCSF events, planted nonconformities, answer key, time split | complete; verified on the built-in sample only |
| 3. LLM reads the policy | Coverage check, clause-to-rule translation, validator, reviewer UI, reference rules, keyword baseline | built and tested; **no LLM results yet** |
| 4. Who has access to what | Rules for clear-cut access criteria, graph neural network for least privilege, baselines, McNemar | runs end to end; **the GNN does not beat the baselines on the sample** |
| 5. Traffic classifier (NW-05) | Detect cleartext traffic disguised on an encrypted service's port | not started |
| 6. Insufficient evidence | Decide when evidence is too thin to give a determination | not started |
| 7. Time to identify (RQ4) | Compare continuous assessment with periodic audit | not started |

**Code so far.** About 3,800 lines of Python in 22 modules (`cbuae_conformity/`, `catalogue/`), 9 hand-written Open
Policy Agent (Rego) rule files, 32 Python tests and 30 seeded Rego tests, all passing. `python reproduce.py` rebuilds
every output from scratch in about 3 minutes.

**Headline results (synthetic sample, for pipeline validation only, not thesis findings):**

| What was measured | Result |
|---|---|
| Reference rules vs. answer key, 11 clear-cut criteria, 26 weeks | 19,241 cases, 0 false positives, 0 misses |
| Reference rule NW-05 (encryption in transit) | Precision 1.00, recall 0.50; the misses are the disguised-cleartext cases left for Step 5 |
| Keyword baseline, policy coverage (RQ1 baseline), test versions | F1 0.43, Cohen's kappa 0.39; 0 of 9 hollow topics detected |
| Seven clear-cut access criteria on the test weeks | Precision and recall 1.00 |
| Least privilege (AC-06), F1 on test weeks | Function-peer baseline 0.87, role-peer baseline 0.67, **GNN 0.52 ± 0.06** (5 seeds) |

**What the results mean.** The rule engine and evidence pipeline work as designed. The keyword baseline is weak on
policy topics that are mentioned but hollow, which is where the LLM is expected to help (RQ1). The GNN currently loses
to a simple baseline. On the sample this is partly by construction, because the generator defines "justified access"
the same way the function-peer baseline measures it. The GNN is also unstable across seeds, which must be fixed
before the real-data run.

**Next steps, in order:**
1. Run Step 3 with a named LLM (coverage and rule translation) and report it against the keyword baseline (RQ1).
2. Prepare and load the real public datasets (CERT r6.2, LANL, UQ NetFlow v3), see Step 2 below.
3. Stabilise the GNN (more negatives, ranking-based threshold, early stopping) and evaluate it on real data and on
   the Amazon Employee Access data (RQ2).
4. Get a second annotator for the 41 policy versions and report agreement.
5. Steps 5 to 7.

## Repository and branches

| Branch | Purpose |
|---|---|
| `dev` | Active development; all work so far is here |
| `staging` | Code that has been run end to end and checked, ready for review |
| `main` | Reviewed, thesis-ready versions |

Not committed (see `.gitignore`):
- `data/`: every dataset, generated evidence, answer key, LLM call log and experiment output. All of it is rebuilt
  by `python reproduce.py`, and the result figures are copied into this README.
- `docs/`: the unpublished thesis chapters.
- `bin/`: the Open Policy Agent binary, which you download for your OS (see below).

## Run it

Setup, once (Python 3.13 from python.org; on Windows tick "Add python.exe to PATH" in the installer).

Get the code:

```bash
git clone -b dev https://github.com/YahyaZahni/CBUAE-Compliance-Engine.git cbuae-conformity
cd cbuae-conformity
```

Windows, in PowerShell inside the `cbuae-conformity` folder:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned, then retry
python -m pip install --upgrade pip
pip install -r requirements.txt
mkdir bin
curl.exe -L -o bin\opa.exe https://github.com/open-policy-agent/opa/releases/download/v1.4.2/opa_windows_amd64.exe
python reproduce.py
```

macOS or Linux, in a terminal inside the folder:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
# Linux without an NVIDIA GPU only, to avoid a 3 GB CUDA download:
#   pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
mkdir -p bin
curl -L -o bin/opa https://github.com/open-policy-agent/opa/releases/download/v1.4.2/opa_darwin_arm64_static
#   Intel Mac: opa_darwin_amd64     Linux: opa_linux_amd64_static
chmod +x bin/opa
python reproduce.py
```

`python reproduce.py` rebuilds every output of Steps 1-4 and runs all checks (about 3 minutes); it ends with
"All stages completed." Add `--no-gnn` to skip Step 4 if PyTorch will not install. Activate the environment again
(`.venv\Scripts\Activate.ps1` or `source .venv/bin/activate`) in every new terminal before running anything.

`reproduce.py` runs these commands in order; each can also be run alone.

```bash
python catalogue/build_catalogue.py                 # Step 1 -> outputs/step1/
python -m cbuae_conformity.pipeline sample          # Step 2 -> data/raw_sample/, data/processed/evidence/
python -m cbuae_conformity.step3 inputs             # Step 3 -> data/processed/rule_inputs/, reference rules scored
python -m cbuae_conformity.step3 coverage --no-llm  # Step 3 -> keyword baseline for the coverage check
python -m cbuae_conformity.step4                    # Step 4 -> data/step4/
python -m pytest -q tests                           # 32 tests
bin/opa test --v1-compatible rules/cbuae rules/tests   # 30 seeded Rego tests
```

Generated outputs under `data/` are not in the repository. Run `python reproduce.py` once to create them. The
figures quoted below are copied from those files. The Step 1 deliverables in `outputs/step1/` are committed.

## Step 1: what is checked

The scope is Art. 8.6 (the policy must address nine topics), Art. 8.6.3 (access controls, identity management,
protection of Critical Information Assets, network security, plus four measures checked at document level only),
Art. 7.4.2 (segregation of duties), the first half of Art. 7.4.5 (safeguards for access to and use of assets) and
Art. 8.3 (confidentiality in transit). The regulation text in `catalogue/cbuae_requirements.json` was re-verified
word for word against the CBUAE Rulebook on 10 November 2026.

Assessment works at two levels: the CBUAE sub-article says what must exist, and the institution's own policy clause
says how. Each of the 29 criteria in `catalogue/criteria.json` links a sub-article to a policy clause, a pass
condition, the evidence, an assessment method (NIST SP 800-53A EXAMINE or TEST) and a checker. One case is one
criterion, one entity, one week.

| ID | Criterion | CBUAE | Checker |
|---|---|---|---|
| AC-01 | Segregation of duties | 7.4.2, 8.6.3 | rule |
| AC-02 | Leavers disabled within one business day, no use afterwards | 8.6.3, 7.4.5 | rule |
| AC-03 | Service accounts and AI agents have an owner who is an active employee | 8.6.3 | rule |
| AC-04 | Entitlements outside the role baseline are approved before the grant | 8.6.3, 7.4.5 | rule |
| AC-05 | Entitlements unused for 90 days are removed | 8.6.3, 7.4.5 | rule |
| AC-06 | Access is justified by the holder's role (least privilege) | 7.4.5, 8.6.3 | rule + GNN |
| AC-07 | Privileged access to Critical Information Assets approved by owner and CISO first | 8.6.3, 7.4.5 | rule |
| AC-08 | Critical Information Assets accessed only by entitled identities | 7.4.5, 8.6.3 | rule |
| NW-01 | No firewall rule permits a prohibited service | 8.6.3 | rule |
| NW-02 | No ANY rule into the DATABASE or MANAGEMENT zone | 8.6.3 | rule |
| NW-03 | Firewall rules follow the zone matrix | 8.6.3 | rule |
| NW-04 | Observed traffic follows the zone matrix | 8.6.3 | rule |
| NW-05 | Connections to Critical Information Assets are encrypted | 8.6.3, 8.3 | rule + ML (Step 5) |
| DOC-8.6.x (16) | The policy addresses each Art. 8.6 topic and each 8.6.3 measure | 8.6 | LLM |

Outputs in `outputs/step1/`: `CBUAE_Criteria_Catalogue.xlsx` (criteria, regulation text, policy clauses, annexes,
out-of-scope list), `oscal/cbuae_orm_catalog.json` (NIST OSCAL 1.1.3, validated against NIST's schema) and
`Sample_LFI_ICT_Cybersecurity_Policy.docx` (the fictional "Example Finance LFI" policy, 28 clauses).

## Step 2: evidence and answer key

The pipeline reads three public datasets in their published formats (CERT Insider Threat r6.2 for staff and
workstation logons, LANL for server authentications, UQ NetFlow v3 for traffic), resolves their identities and hosts
into one institution, and writes everything as OCSF 1.6.0 events. No public dataset contains entitlements, approvals,
owners of non-human identities or firewall rules, so that state is simulated, conforming by construction, in plain
CSV files that a real export could replace. Nonconformities are then planted, 12 per technical criterion, and an
answer key is computed for every case.

| Path under `data/processed/evidence/` | Content |
|---|---|
| `ocsf/*.jsonl.gz` | Authentication (3002), User Access Management (3005), Account Change (3001), Network Activity (4001). Every event is validated against the OCSF schema; flows carry no application label |
| `state/*.csv` | Weekly snapshots of entitlements, identities and firewall rules; firewall change log, approvals, HR, identity registry |
| `policy/` | Policy clause repository and 41 policy versions for the coverage check |
| `truth/` | Answer keys, the list of planted nonconformities, and the hidden application label per flow. **Checkers never read this folder** |
| `periods.csv`, `summary.json` | 26 weekly periods split by time into train (13), validation (5), test (8); run summary |

Sample run: 160 people, 12 service accounts, 4 AI agents, 26 weeks; 43,991 authentication, 583 entitlement, 233
account and 39,027 network events; 23,254 technical cases, of which 1,615 are nonconforming (1,329 from the 156
planted nonconformities, 286 side effects of them, 0 unexplained).

To use the real datasets, place them as below and run `python -m cbuae_conformity.pipeline run --raw data/raw`.

```
data/raw/cert/LDAP/YYYY-MM.csv, data/raw/cert/logon.csv   CERT r6.2      https://doi.org/10.1184/R1/12841247.v1
data/raw/lanl/auth.txt                                    LANL (Kent, 2015)  https://csr.lanl.gov/data/cyber1/
data/raw/netflow/*.csv                                    UQ NetFlow v3  https://staff.itee.uq.edu.au/marius/NIDS_datasets/
```

Leave `data/raw/crosswalk/` and `data/raw/iam/` out: the pipeline creates both on the first run (the join between
the datasets and the simulated institution state) and reuses them afterwards, so delete them to recompose.

The raw downloads cannot be dropped in unchanged. Three things have to be prepared first, and none of them is
automated yet:

1. **Size.** The loaders read each file whole into memory. LANL `auth.txt` holds about 1.6 billion events (roughly
   70 GB unpacked) and must be cut down to a subset of a few million rows: user accounts only (names starting with
   `U`, not computer accounts ending in `$`) and a sample of users. One NetFlow v3 file is enough; NF-UNSW-NB15-v3
   is the smallest and its internal address ranges are already recognised.
2. **Roles.** CERT's LDAP roles (Salesman, ProductionLineWorker and so on) are not the institution's roles in
   `config/role_entitlements.csv`. Planting nonconformities looks each person's role up in that file and stops on an
   unknown one, so the `role` column of the LDAP files has to be mapped onto the institution's 18 roles first. The
   mapping is an assumption of the study and should be saved and reported like the crosswalk.
3. **Time window.** Weekly periods run from the first to the last authentication. CERT covers about 17 months, LANL
   58 days, a NetFlow capture a few days; LANL and NetFlow are moved to start on the first CERT Monday. Unless CERT
   is cut to the same weeks, every week after the eighth has no server activity, and entitlements then read as
   unused (AC-05). Eight or nine weeks give a split of about 4 / 2 / 3 weeks.

After the run, check `data/processed/evidence/summary.json`: `injection_shortfall` and `injections_not_surfacing`
should be empty, and `nonconforming_by_source` shows how many nonconforming cases are `natural`, meaning produced by
the composition and not planted.

## Step 3: the LLM reads the policy (RQ1)

**Coverage check.** For each of the 16 topics the model says whether the policy contains a clause with a concrete
obligation and cites clause ids. Citations are verified; an "addressed" answer with no real citation is downgraded.
The test material is 41 policy versions in which topics are removed, hollow (mentioned with no obligation) or
relocated (reworded without the usual keywords and moved under another heading, so still addressed).

**Rule translation.** For each technical criterion the model receives the CBUAE text, the policy clause, the pass
condition and the input contract (`rules/INPUT_CONTRACT.md`) and returns an Open Policy Agent rule. A deterministic
validator gates it: JSON shape, package name, no forbidden built-ins, only contract fields, compiles, flags the right
entities on 30 hand-written seeded cases, and assesses exactly the entity each case is about. Rules that pass go to
the reviewer UI, where a person approves or rejects each one; decisions are logged with reviewer, time, comment and
the SHA-256 of the rule.

**Reference rules** in `rules/cbuae/` are hand-written from the same clauses. They are the yardstick for generated
rules and the rule-only baseline for the final comparison.

```bash
export LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=... LLM_MODEL=<model>         # or, for a local model:
export LLM_PROVIDER=openai OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=ollama LLM_MODEL=qwen2.5:14b-instruct
python -m cbuae_conformity.step3 coverage            # LLM against the keyword baseline
python -m cbuae_conformity.step3 translate           # candidates + validator report -> data/step3/rule_candidates/
python -m cbuae_conformity.step3 evaluate            # behaviour of validated rules on the evidence
python -m cbuae_conformity.step3 review              # approve or reject at http://127.0.0.1:5000
python -m cbuae_conformity.step3 evaluate --rules approved
```

On Windows PowerShell, set the variables with `$env:` instead of `export`:

```powershell
$env:LLM_PROVIDER="anthropic"; $env:ANTHROPIC_API_KEY="..."; $env:LLM_MODEL="<model>"
```

**With a Claude subscription instead of an API key.** A Pro or Max subscription does not include API access, but
Claude Code runs on it, and `LLM_PROVIDER=claude_cli` sends each prompt through Claude Code's print mode
(`claude -p`). Install Claude Code (the VS Code extension is enough; its copy of the program is found
automatically, otherwise set `CLAUDE_BIN`), sign in once with `claude auth login`, then:

```powershell
$env:LLM_PROVIDER="claude_cli"; $env:LLM_MODEL="claude-sonnet-5-5"      # a full model id, not an alias
python -m cbuae_conformity.step3 coverage
python -m cbuae_conformity.step3 translate
```

The whole of Step 3 is 41 coverage calls and 12 translation calls. If a usage limit interrupts a run, run the same
command again later: answered calls are read from the log and only the missing ones are sent. Three differences
from the API must be reported with results obtained this way: the temperature cannot be set to 0 (the model's
default is used, so a fresh run can answer differently; the log is what makes a result repeatable), Claude Code adds
about a thousand tokens of its own context to every request, and the model may reason before answering. The log
records the provider and the model id the service answered with. An `ANTHROPIC_API_KEY` in the environment is
ignored by this provider.

Every call is saved in `data/llm_runs/`; `LLM_PROVIDER=replay` re-scores from that log without calling a model.
Keep that folder with the thesis material: it is the record of what the model was asked and what it answered.

Results on the sample, no LLM involved:

| Checker | Result |
|---|---|
| Reference rules, 11 clear-cut criteria, all 26 weeks | Agree with the answer key on every one of the 19,241 cases (0 false positives, 0 misses) |
| Reference rule for NW-05 | Precision 1.00, recall 0.50: finds cleartext on cleartext ports, misses the 6 asset-weeks whose only cleartext traffic runs on an encrypted service's port. That gap is the job of the traffic classifier in Step 5 |
| Keyword baseline, coverage, 21 test versions | F1 0.43, kappa 0.39; correct on 0 of 9 hollow topics, 7 of 18 relocated, 10 of 16 removed |

## Step 4: access conformity (RQ2)

Seven access criteria are clear-cut and are checked by rules. Least privilege (AC-06) needs judgement, because an
entitlement can be properly approved and still not be justified by the holder's role. The rule part sets aside
entitlements inside the role baseline; a heterogeneous GraphSAGE model scores the rest. The graph links identities to
roles, business functions, entitlements, assets and recent use. The model is trained by self-supervised link
prediction on the training weeks with no AC-06 labels; labels are used only to choose a threshold on the validation
weeks, and the test weeks are scored once. Two simple baselines score the same entitlements: how many peers in the
same role hold it, and how many peers in the same business function hold it.

Results on the sample test weeks (537 scored entitlement-weeks, 84 planted as unjustified):

| Method | Precision | Recall | F1 | Edge PR-AUC |
|---|---|---|---|---|
| Business-function peer frequency | 0.97 | 0.79 | 0.87 | 0.92 |
| Role peer frequency | 0.54 | 0.88 | 0.67 | 0.50 |
| Heterogeneous GNN, 5 seeds (mean ± sd) | 0.42 ± 0.10 | 0.74 ± 0.12 | 0.52 ± 0.06 | 0.42 ± 0.08 |

The GNN is worse than both baselines and unstable: F1 ranges from 0.43 to 0.59 across seeds. McNemar's exact test
favours the function-peer baseline for all five seeds (p < 0.001) and the role-peer baseline for four of five (the
fifth is a tie). The other seven access criteria score precision and recall 1.00 on the test weeks.

**The GNN row depends on where it was run.** The figures above are the ones in `data/step4/`, produced on Windows 11
with PyTorch 2.15.0 (CPU), NumPy 2.5.4 and pandas 3.1.1. The same code, seeds and sample on the Linux build machine
gave precision 0.43 ± 0.16, recall 0.84 ± 0.13, F1 0.54 ± 0.11 and PR-AUC 0.45 ± 0.03, with F1 from 0.36 to 0.66 and
one seed whose threshold flagged everything. Both baselines were identical in the two runs to every printed digit,
so the evidence and the scoring agree; only the trained model differs. No unseeded step was found in the code: the
seed fixes the weights, the hidden edges and the negative samples. What differs between two environments is the last
digit of the floating-point arithmetic (operating system build of PyTorch, library versions, number of threads), and
780 optimiser steps on a model this unstable turn that into different results. The conclusion is the same in both
runs; the individual numbers are not. Since then:

- training runs on one thread with PyTorch's deterministic algorithms, and a test (`test_gnn_same_seed_same_scores`)
  checks that one seed gives identical scores when training is repeated;
- `data/step4/summary.json` records the environment, the F1 of each seed and a fingerprint of the graphs the model
  was given, so two runs can be told apart as "different input" or "different environment";
- the table above predates the one-thread setting and will move again on the next run. Copy the GNN row from
  `ac06_test_metrics_summary.csv` after each run, and quote it with the environment.

Identical numbers on another machine are not promised. `requirements.txt` gives minimum versions, so a new install
can pick up newer libraries; pin the versions listed in `summary.json` before the runs that go into the thesis.

Two things follow. First, the sample cannot answer RQ2: in it, "justified" is defined by the generator as "belongs to
the same business function", which is exactly what the function-peer baseline measures, so that baseline is close to
an upper bound by construction. Second, the instability is a real weakness of the model as built and should be dealt
with before the real-data run (candidates: more negatives per positive, threshold chosen on ranking rather than F1,
early stopping on validation link-prediction loss). For real access decisions, `amazon_eval.py` applies the same
method to the Amazon Employee Access data, where people approved or denied each request:

```bash
python -m cbuae_conformity.amazon_eval data/raw/amazon/train.csv    # Kaggle "Amazon.com - Employee Access Challenge"
```

## Review of 10 November 2026

All four steps were re-read and re-run from clean. The findings below were fixed, and most fixes have a regression test.

**Step 1.** Definition 1.16 of the regulation was truncated and is now complete. The pass conditions of NW-01 to
NW-03 said "at the end of the period" while the code assessed every rule in force at any time in the period; the
catalogue now says what the code does. NW-05 now states that cleartext on an encrypted service's port is in scope.

**Step 2, answer-key leakage.** The evidence gave planted records away in several ways: a log name containing
"planted", identifier prefixes and number ranges used only for planted records, account and host names in a different
format, synthetic byte and packet counts on planted flows, and fixed time gaps. All records now get content-hash
identifiers in one format, planted logons are written in the server log's own naming, and planted flows copy the
statistics, source port and sub-minute timing of a real flow. Two timing shortcuts were also removed: ordinary
approved grants used to happen only in the first 60 days and the firewall rule base never changed, so "changed
recently" identified planted records. Ordinary grants and routine rule re-issues now occur throughout the window.

**Step 2, correctness.** 434 entitlement events contained the JSON value `NaN` where an approval id was empty (a
pandas 3 behaviour); output is now strict JSON and the write fails on any missing value. The pipeline depended on a
file written by the Step 1 script and now writes it itself. The pool of administrators for AC-07 could run out, so
fewer than 12 nonconformities were planted on some samples; AC-07 is now planted first.

**Step 3.** Rule inputs contained hindsight: future terminations and approvals not yet requested were visible in
earlier weeks. Each week's input is now a point-in-time view, with undecided approvals marked `pending`. A malformed
model answer used to crash a whole coverage run; it is now recorded as `no_answer` and scored as wrong. The validator
checked which entities a rule flagged but not which it claimed to have assessed; it now checks both, and two seeded
cases cover pending approvals. The reviewer endpoint accepts only catalogue ids and the two known decisions. A missing
source asset on a logon broke rule-input writing on the public-dataset path and is now written as `null`.

**Step 4.** Part of the model's vocabulary lived in module-level variables and is now in the vocabulary object.
McNemar's test was run on the first seed only and is now reported for every seed. Scoring silently ignored answer-key
cases a method did not assess; they now count as misses and are reported.

**General.** Added `requirements.txt`, `reproduce.py`, 10 Python tests and 2 Rego tests (now 31 and 30). The earlier README said the
answer key and the reference rules were "two independent implementations"; they were written by the same author from
the same specification and share one date helper, so their agreement shows consistency, not independent confirmation.

**Later on 10 November 2026.** The project was rebuilt on a second machine (Windows) and the GNN figures came out
different from the ones first written here, with everything else identical. Step 4 above now reports the figures on
file, explains the difference, and the code fixes the thread count, records the environment and tests that a seed
repeats. A provider that runs Step 3 on a Claude subscription was added (`LLM_PROVIDER=claude_cli`), and the
preparation the real datasets need is now listed under Step 2. Python tests: 32.

## What this work cannot yet claim

1. **No model performance is established.** The sample is synthetic and exists to test the pipeline. Steps 3 and 4
   must be reported on real runs: an LLM with a named model and version for Step 3, real public data for Step 4.
2. **The real datasets have not been processed.** Their hosts were not reachable from the build environment, and
   the raw files need the preparation listed under Step 2 (size, roles, time window) before they will load. The
   public-dataset path was exercised on a copy of the sample relabelled to look like unlinked downloads (no
   crosswalk, no state, different addresses and timestamps): it ran, and the reference rules matched its answer key
   on every clear-cut case. Expect format surprises on the real files.
3. **The composed institution is an assumption.** CERT, LANL and NetFlow share no identifiers, so they are joined by
   documented heuristics, saved to `raw/crosswalk/`. On the relabelled copy this produced 144 nonconforming cases
   that were not planted (107 unused entitlements, 37 traffic cases). Report such cases separately.
4. **For clear-cut criteria the answer key is definitional.** A rule that sees the same evidence agrees with it by
   design. The research value lies in the judgement-based criteria (AC-06, disguised cleartext in NW-05), in the LLM
   tasks, and in time-to-identify against periodic audit (RQ4, Step 7).
5. **`insufficient_evidence` is defined but never produced.** Every checker returns conforming or nonconforming;
   deciding when evidence is too thin belongs to Step 6.
6. **The policy answer key has one annotator.** Hollow and relocated topics were written for this study; a second
   annotator should label the 41 versions and agreement should be reported before RQ1 results are used.
7. **Planted flows reuse a real flow's statistics**, so each has an exact twin in the data. On real data small flows
   repeat naturally, but a duplicate large flow is a faint tell; a traffic model in Step 5 should not use exact
   duplicate detection as a feature.
8. **Smaller assumptions.** Termination dates have month granularity (CERT LDAP). Usage is known per asset, not per
   entitlement, so AC-05 cannot separate two entitlements on one asset. Routine directory logons from outside the
   MANAGEMENT zone do not count as use of the directory. The working week is Monday to Friday. nDPI protocol ids
   were checked against `vendor/ndpi_protocol_ids.h` and should be confirmed for each dataset's nDPI version.

## Layout

```
catalogue/           Step 1 sources (regulation text, criteria, sample policy) and build script
config/              thresholds and the institution model: assets, entitlements, roles, SoD, services, zones
cbuae_conformity/    Step 2: formats, entities, simulate_state, sample_data, inject, truth, ocsf, pipeline, policy_variants
                     Step 3: rule_input, rules, seeded_cases, llm_client, policy_reader, review_app, step3
                     Step 4: access_graph, gnn, step4, amazon_eval
rules/cbuae/         reference Rego rules; rules/tests/ seeded Rego tests; rules/INPUT_CONTRACT.md
tests/               pytest suite
outputs/step1/       generated Step 1 deliverables
data/raw_sample/     generated sample in the public datasets' file formats
data/processed/      generated evidence, answer keys, rule inputs, reference rule determinations
data/step3, step4/   generated experiment results
vendor/              compiled OCSF 1.6.0 schema, OSCAL 1.1.3 catalog schema, nDPI protocol ids
reproduce.py, requirements.txt
```

`data/` is generated and not committed. Also not in the repository: the thesis chapters (`docs/`), the Open Policy
Agent binary (download it for your OS, see above) and the OCSF schema repository, which is needed only to recompile
`vendor/ocsf_1.6.0_compiled.json`.
