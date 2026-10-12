# CertiProto

Code, logs and result files for *CertiProto: Certifiably Insertion-Robust and
Self-Explaining Malware Detection via Monotone Prototype Graph Learning*.

CertiProto turns a Windows PE file into a heterogeneous graph of its components
(imported libraries and functions, header fields, flags, signatures, size
counts, sections, data directories, exports). Monotone message passing with
non-negative weights and max aggregation, followed by a non-negative prototype
multiple-instance head, makes the malice score provably non-decreasing under any
insertion of components. Content-hash partition voting turns that into a
deterministic certificate against unlimited insertion **plus** a bounded number
of edits, with a radius computed in a single pass.

Two variants are reported:

| Variant | Trained on | Guarantee |
|---|---|---|
| `certiproto-i` | full programs | insertion (Theorem 1) |
| `certiproto-ie` | full programs + random groups | insertion + `r` edits (Theorem 2) |

## Safety note

No malware binary is downloaded, executed or modified anywhere in this
repository. Every experiment runs on the **static metadata released by the
dataset authors** (header fields, import tables, section tables, EMBER-format
feature records). The adversarial attacks operate on the parsed component graph,
never on a file on disk. Anyone extending this work to real binaries should do so
in an isolated environment.

## Layout

```
src/        data preparation, model, training, attacks, explanations, figures
paper/      manuscript generator (docx in the IJIES/CAMFusion layout)
scripts/    queue helpers used to run jobs sequentially on a small machine
results/    every number used in the paper, as JSON
figs/       figures as SVG (vector) plus low-resolution previews
logs/       raw stdout of every training, attack and analysis run
```

`results/results.json` is the single source of truth: the manuscript text,
tables and figures all read their numbers from it, so no value in the paper is
typed by hand.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export CERTIPROTO_ROOT=$(pwd)   # optional; defaults to the repository directory
```

Everything runs on CPU. The reported runs used two cores; a full reproduction
takes roughly 12–16 core-hours, dominated by the BMD graph models and the
greedy attacks.

## Datasets

The three datasets are public but are **not** redistributed here. Download them
first and point `src/load_bmd.py` and `src/prep_others.py` at the files:

| Dataset | Source | What is used |
|---|---|---|
| Brazilian Malware Dataset (BMD) | `github.com/fabriciojoc/brazilian-malware-dataset` | header fields, imports, packer/compiler labels |
| ClaMP | `github.com/urwithajit9/ClaMP` | `ClaMP_Integrated-5184.csv` (69 header features) |
| MOTIF | `github.com/boozallen/MOTIF` | `motif_dataset.jsonl` and `X_train.dat` (EMBER vectors) |

Then build the component graphs:

```bash
python src/load_bmd.py      # parse BMD csv -> prep/bmd_recs.pkl
python src/prep_bmd.py      # dedupe, align functions to libraries, build records
python src/prep_others.py   # ClaMP and MOTIF records
```

`prep_bmd.py` resolves 93.4% of imported functions to the library that exports
them, using the exact library–function pairs in the MOTIF import tables plus the
single-library import tables of BMD; unresolved functions attach to the root.

## Reproducing the experiments

Order matters: thresholds and quorums are selected on validation data before any
test number is read.

```bash
# 1. train (detection)
python src/train.py bmd   certiproto-i,certiproto-ie,rgat,gnncert,nngcn,twin 0,1,2
python src/flat.py  bmd   lgbm,lgbm-mono,mlp 0,1,2,3,4
python src/train.py clamp certiproto-i,certiproto-ie,rgat,gnncert,nngcn,twin 0,1,2,3,4
python src/flat.py  clamp lgbm,lgbm-mono,mlp 0,1,2,3,4

# 2. train (family attribution, 5-fold CV)
python src/train.py motif certiproto-i,rgat,twin 0,1,2,3,4
python src/flat.py  motif lgbm-ember,mlp-ember 0,1,2,3,4

# 3. calibrate decision thresholds and the voting quorum on validation data
python src/calib.py bmd,clamp
python src/select_kappa.py

# 4. adversarial attacks (main results use the strong budget)
ATK_OUT=results/bmd/attacks_hi   ATK_KINS=40 ATK_MIXINS=20 ATK_REDIT=8 \
  python src/run_attacks.py bmd   twin,rgat,gnncert,lgbm,lgbm-mono,nngcn,certiproto-i,certiproto-ie 200
ATK_OUT=results/clamp/attacks_hi2 ATK_KINS=40 ATK_MIXINS=20 ATK_REDIT=8 \
  python src/run_attacks.py clamp twin,rgat,gnncert,lgbm,lgbm-mono,nngcn,certiproto-i,certiproto-ie 150

# 5. explanations, qualitative witnesses, MOTIF insertion test
python src/explain.py bmd   certiproto-i,rgat,twin,nngcn
python src/explain.py clamp certiproto-i,rgat,twin,nngcn
python src/motif_robust.py certiproto-i,rgat,twin
python src/qualitative.py

# 6. collect every number, then draw the figures
python src/make_results.py
python src/make_figs.py && python src/fig_arch.py && python src/flatten_png.py
```

### Paired evaluation and insertion split (added in revision 1)

```bash
# one fixed sample set: the malware every detector finds, for a paired McNemar test
python src/common_pick.py bmd 100
ATK_PICK=results/bmd/common_pick.pkl ATK_OUT=results/bmd/attacks_paired \
  ATK_KINS=40 ATK_MIXINS=20 ATK_REDIT=8 python src/run_attacks.py bmd lgbm,lgbm-mono,rgat,gnncert,nngcn,twin,certiproto-i,certiproto-ie

# separate the two kinds of insertion: growth of a count vs arrival of a new node
ATK_INS=grow  ATK_OUT=results/bmd/attacks_grow  ATK_KINS=40 ATK_NOMIX=1 python src/run_attacks.py bmd nngcn,certiproto-i,lgbm-mono,rgat,twin 100
ATK_INS=nodes ATK_OUT=results/bmd/attacks_nodes ATK_KINS=40 ATK_NOMIX=1 python src/run_attacks.py bmd nngcn,certiproto-i,lgbm-mono,rgat,twin 100

# cost of the sign constraints alone (identical architecture, constraints removed)
python src/train.py clamp certiproto-i-relax 0,1,2,3,4
python src/train.py bmd   certiproto-i-relax 0,1,2
```

`ATK_INS` selects which insertion operations the attacker may use (`all`, `grow`,
`nodes`); `ATK_PICK` pins the attacked sample list so outcomes are paired across
models. The `-relax` variant sets `CP_RELAX`, which turns the non-negativity
reparameterisations into identities while leaving initialisation, normalisation,
aggregation and the head unchanged.

### Attack budgets

`run_attacks.py` reads its budget from the environment, so the same code
produces both reported attackers:

| Variable | Meaning | Weak run | Strong run (reported) |
|---|---|---|---|
| `ATK_KINS` | insertions, insertion-only attack | 25 | 40 |
| `ATK_MIXINS` | insertions, mixed attack | 15 | 20 |
| `ATK_REDIT` | edits, mixed attack | 4 | 8 |

The insertion-only evasion rate of every monotone model is 0.0% at **both**
budgets, and Theorem 1 says no larger budget can change that.

### Ablation

```bash
for v in certiproto-i-cosine certiproto-i-meanagg certiproto-i-protoonly \
         certiproto-i-H1 certiproto-i-nomil certiproto-i-nongram \
         certiproto-i-K16 certiproto-i-K64; do
  python src/train.py clamp $v 0,1,2
done
ATK_OUT=results/clamp/attacks_abl python src/run_attacks.py clamp certiproto-i,certiproto-i-cosine,... 100
```

Variant names are parsed in `src/train.py:make_model`: `-cosine` swaps coverage
for cosine similarity, `-meanagg` swaps max for mean aggregation (both break
monotonicity), `-protoonly` removes the axis-aligned prototypes, `-H1` uses a
single hashed relation channel, `-nomil` drops the MIL contrastive term,
`-nongram` drops character n-grams, and `-K16` / `-K64` change the number of
prototypes.

## Where each result comes from

| In the paper | Produced by | Reads |
|---|---|---|
| Table 2 (datasets) | `src/prep_*.py` | `results/dataset_stats.json` |
| Table 3 (clean detection) | `src/train.py`, `src/flat.py` | `clean_bmd`, `clean_clamp` |
| Table 4 (certificates, evasion) | `src/run_attacks.py` | `cert_*`, `attack_hi_*` |
| Table 5 (faithfulness) | `src/explain.py` | `explain_bmd`, `explain_clamp` |
| Table 6 (MOTIF) | `src/train.py`, `src/motif_robust.py` | `motif` |
| Table 7 (ablation) | ablation loop above | `ablation` |
| Table 8 (significance) | `src/make_results.py` | `sig_*` + Fisher tests |
| Figures 2–5 | `src/figs.py` | `results/results.json` |
| Figure 1 (architecture) | `src/fig_arch.py` | — |

Figures are written as SVG and as 600 dpi PNG on a white background.

## Rebuilding the manuscript

```bash
export CERTIPROTO_TEMPLATE=/path/to/unzipped/journal_template   # the publisher's .docx, unzipped
./scripts/build_paper.sh out/CertiProto_paper.docx
```

The journal's template (styles, header, footer, page setup) is **not**
redistributed here; unzip the publisher's own `.docx` and point
`CERTIPROTO_TEMPLATE` at the resulting folder.

This assembles the .docx in the journal's two-column layout, converting every
equation to native Office Math (OMML) through `pandoc`, embedding each figure as
SVG with a 600 dpi PNG fallback, and numbering the references in citation order
from `paper/refs.py`. The text is generated from `results/results.json`, so
re-running the experiments and rebuilding keeps the prose, tables and figures
consistent with each other.

## Logs

`logs/` holds the raw stdout of every run, including the probe runs for design
choices that were tested and **not** adopted (longer training schedules, 64
prototypes on BMD, a piecewise-linear monotone count encoder) — they are kept so
the selection decisions can be checked. Validation metrics decided each of them;
none improved held-out performance enough to adopt.

## Known limitations

- The guarantee covers the parsed component graph. Packing rewrites nearly every
  component, and attacks on the parser itself are not modelled.
- The attacks operate in graph space, not on PE files; they do not verify that a
  modified sample still executes.
- BMD publishes no first-seen date for goodware, so the PE compile timestamp is
  used as a proxy in the time-aware split.
- On MOTIF the certificate protects per-family evidence, not the top-1 family:
  components merged from another family can raise that family's score.

## License

MIT — see `LICENSE`. The datasets keep their own licences and are not included.
