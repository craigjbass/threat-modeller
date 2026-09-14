# Release notes

What changed in the application, newest first. A change that moves a score
states the numbers it moved, measured on one model before the change and after
it.

## Unreleased

### Risk over time

`threatmodeller history` states what the model scored at each commit that
touched a threat model file, newest first. The report writes `## Risk over
time` with a graph, `## What changed` since the previous sampled commit, and
one sentence in the executive summary stating the direction.

The history is git: nothing is stored, nothing is checked out, and neither the
working tree nor the index is touched. The sample is bounded by `--commits`,
which defaults to 50; `--commits 0` turns the sections off.

### A project states the rules it enforces

`threatmodel/policy.hcl` states the rules `threatmodeller check` enforces for
the whole project: `max_open_at_level`, `accepted_requires_owner`,
`accepted_requires_review_by`, `implemented_requires_evidence_above`,
`restricted_data_stays_out_of_public_zones`, `assumptions_require_owner` and
`system_requires_owner`. A breach prints one line naming the rule and exits 1.

A project with no policy file checks exactly as it did. The `.arch` file's
`system` block takes one more attribute, `owner`, which one of the rules reads.

### A control states what proves it is in place

A `control` and a `compensating` block take `evidence`, `reference` and
`verified_on`. The five tiers are `asserted`, `documented`, `configured`,
`tested` and `audited`. A tier moves no score: a model saved today opens
unchanged and scores exactly what it scored before.

A project that states `requires_evidence_above` in its `.arch` file fails
`threatmodeller check` for an implemented control above that risk level with no
tier. A project that states nothing fails nothing.

### An accepted risk states who carries it

A `.governance` file beside each system's `.arch` and `.controls` files states
who carries each accepted risk, when they took it and when they read it again,
and who does each recommendation and each action.

WARNING: a project that accepts a risk today and holds no `.governance` file
fails `threatmodeller check` the first time it runs after this change. The fix
is two steps:

1. Run `threatmodeller compile`, which writes the file and a stanza for every
   accepted control.
2. Fill in `owner` and `review_by` in each stanza, and commit the file.

No score moves. An accepted risk still counts at its full score, which is what
accepting a risk always did.

### Two pathway mitigations answering one threat now compound

Before this change, two mitigations answering one threat gave the **stronger**
of the two: each one was worked out from the original score and the lowest
answer won. Now each mitigation acts on the risk the one before it left, so the
score is `max(1, floor(score × (1 − p1/100) × (1 − p2/100) × …))`.
`docs/LANGUAGE.md` states the rule with a worked number.

### A zone threat reads the mitigations inside that zone

Before this change, a zone threat was never pathway-mitigated: a zone sits
nowhere in the connection graph, so nothing was upstream of it. Now a zone
threat reads the mitigations the components **inside that zone** provide, so a
firewall in the zone answers the threats about moving inside it.

### A mitigation's default mode and percentage come from the catalogue

The catalogue and a `.lib` file now state `mode` and `reduces_risk_by` for each
mitigation, and the user's own settings win over both. The application's own
default — mode `reduce` at 50 per cent — is used only for what the catalogue
leaves out. The vendored library states neither today, so the application's
default still stands for every vendored mitigation.

### What the three changes did to a score

Measured on one model: CloudFront → API Gateway → EC2, with a network firewall
in a private zone, the master pathway toggle **on**, and every mitigation at
its default of `reduce` 50 per cent. The model raises 41 threats.

| Threat | Source | Before | After |
|---|---|---|---|
| `dos-attack` | the EC2 instance, answered by DDoS Protection and Rate Limiting | 4 → 2 | 4 → 1 |
| `lateral-movement` | the private zone, answered by Network Firewall | 5 → 5 | 5 → 2 |
| the other 39 threats | — | unchanged | unchanged |

The total of every score fell from 246 to 239.

With the master pathway toggle **off** nothing changes at all, and all three
bundled samples keep the toggle off, so every sample scores exactly what it
scored before.
