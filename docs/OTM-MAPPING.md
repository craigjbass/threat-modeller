# The model's export formats

`threatmodeller export` writes the assessed model in one of three shapes:
`--format otm` writes an Open Threat Model file, `--format threatcl` writes a
threatcl HCL file, and `--format json` writes this application's own data
shape, stated in `docs/threatmodel-export.schema.json`. This page states what
each format carries and what each one drops.

## `--format otm`

OTM is what other threat-modelling tools read. It states a project, trust
zones, components, dataflows, threats and mitigations. It carries no score of
its own, so the assessment's numbers ride in `risk` and in `attributes`. The
version written is stated in the file as `otmVersion`.

### What becomes what

| This model | The OTM file | Note |
| --- | --- | --- |
| the system's name | `project.name` | `project.id` is the name as an identifier: lower case, a dash for anything else |
| the system's owner | `project.owner` | absent when the system states none |
| the system's description | `project.description` | |
| — | one hard-coded `representations` entry, of type `diagram` | OTM asks for a representation before a component may state where it sits. The entry names the model, not the model's own diagram blocks: see "What the OTM file drops" |
| a zone | one `trustZones` entry | the id is the zone's name as an identifier |
| a zone's kind and network | `trustZones[].description` | written as `<zone>, <network>` |
| a zone's risk reduction | `trustZones[].risk.trustRating` | zero when the zone states none |
| a component | one `components` entry | the id is the component's own id |
| a component's category | `components[].type` | `generic-component` when the catalogue no longer holds the technology |
| a component's zone | `components[].parent.trustZone` | absent for a component outside every zone |
| a component's technology, classification, privilege and status | `components[].tags` | four tags, in that order. The status tag is `Live` or `Proposed` |
| a flow | one `dataflows` entry | the id is `<source>-><target>`, which is the id this model keys a flow on |
| a flow's description | `dataflows[].description` | absent when the flow states none |
| a flow's kind | `dataflows[].tags` | one tag |
| a threat on one element | one `threats` entry | see "Threats" below |
| a control on a threat | one `mitigations` entry | see "Mitigations" below |

### Threats

OTM keys a threat once and lists what it sits on. This model raises one threat
on many elements and scores each pair on its own, so each pair is one OTM
threat and no score is lost. The id is `<threat id>@<source id>`, where the
source id is `component:<id>`, `connection:<id>` or `zone:<id>`.

| This model | The OTM file |
| --- | --- |
| the threat's name and description | `name`, `description` |
| the STRIDE categories | `categories` |
| the likelihood tier | `risk.likelihood` |
| what the threat harms | `risk.impact`, as a list in one string |
| the residual score | `risk.score` |
| the score after the zone reduction and before every control | `risk.inherentScore` |
| the risk level | `risk.level` |
| the severity | `attributes.severity` |
| whether anybody answered it | `attributes.isOpen` |
| what raised it | `attributes.raisedBy`, `attributes.element` |
| the assets on that element | `attributes.assetsAtRisk` |
| the MITRE ATT&CK techniques | `attributes.mitreTechniqueIds` |

`cwes` is written empty: this model states MITRE ATT&CK techniques, not CWE
identifiers. Whether a library changed the threat's severity, or an attack
tree raised it, has no attribute: see "What the OTM file drops".

### Mitigations

One control on one threat is one `mitigations` entry. The id is the threat id
and the control's description as an identifier. A compensating control is not
a control this model states on the catalogue's own list, so it writes no
`mitigations` entry: see "What the OTM file drops".

| This model | The OTM file |
| --- | --- |
| the control's description | `name` |
| what proves the control is in place | `description` |
| whether it is implemented | `riskReduction`, 100 when implemented and 0 when not |
| the answer a person wrote | `attributes.status` |
| the threat it answers | `attributes.threat`, the OTM threat id |

OTM states a risk reduction as a number, and this model states a status. A
control this model calls implemented reduces the whole risk in OTM's terms,
and one nobody has answered reduces none. The reading tool sees the status
itself in `attributes.status`.

### What the OTM file drops

The recommendations, the leverage table, the accepted risks, the assumptions,
the scope (the use cases, the users and the exclusions), the data inventory,
the third parties, the known vulnerabilities, the policy, the threat actors,
the attack trees and the history have no place in the OTM schema.

Within what OTM does carry, this export also drops: the model's own diagram
blocks (`representations` names the model once, not each diagram); a
compensating control (only a catalogue control becomes a `mitigations`
entry); whether a control's evidence answers a threat's likelihood or
severity by a library change or an attack tree; a component's free-form
tags, its version and the third party that provides it; a zone's boundary
(privilege or network); and the `mitigates` edges between components, both
adopted and assumed. `--format json` writes most of these; see
`docs/threatmodel-export.schema.json`.

## `--format threatcl`

threatcl is a third-party format with its own shape, so this export honours
that shape rather than inventing one. The blocks and the words are the ones
the threatcl specification states, at the release named `specVersion` in the
file's header comment and in the exporter's own `specVersion` constant.

### What becomes what

| This model | The threatcl file |
| --- | --- |
| the system's name | the `threatmodel` block's label |
| the system's authors, or its owner when it states no author | `author` |
| the system's description, or a generated sentence when it states none | `description` |
| the system's first link | `link` |
| the system's repositories | `repository` |
| each row of the data inventory | one `information_asset` block, with its description and a three-way classification |
| each use case | one `usecase` block |
| each exclusion, and each assumption prefixed `Assumed:` | one `exclusion` block each |
| each third party | one `third_party_dependency` block, with its kind as three booleans, whether it is a paying customer, and its uptime dependency |
| each threat on one element | one `threat` block, labelled `<threat name> on <element name>`; see "Threats" below |
| the zones, the components they hold, the components outside every zone, and the flows between them | one `data_flow_diagram_v2` block |
| a diagram whose kind is `mermaid` | one `mermaid` block, with the diagram's text unchanged |

### Threats

| This model | The threatcl file |
| --- | --- |
| the threat's description | `description` |
| what the threat harms | `impacts` |
| the STRIDE categories, in threatcl's own words | `stride` |
| the assets at risk | `information_asset_refs` |
| the likelihood tier, banded to threatcl's `low`, `medium` or `high` | `risk.likelihood` |
| the severity, mapped to threatcl's five words | `risk.impact` |
| the risk level, mapped to threatcl's five words | `risk.severity` |
| the likelihood's rationale, or, when the threat states none, a sentence stating the residual and the score before controls | `risk.rationale` |
| each control the catalogue offers | one `control` block, with its evidence as `implementation_notes` and a risk reduction of 100 when implemented and 0 otherwise |
| each compensating control | one `control` block, implemented, with its own risk reduction percentage |

WARNING: `risk.rationale` states the residual score and the score before
controls only while the threat has no likelihood rationale of its own. A
threat that states a likelihood rationale loses both numbers from the file:
the rationale text takes the one line threatcl gives this attribute.

### What the threatcl file drops

The recommendations, the leverage table, the accepted risks, the policy, the
known vulnerabilities, the threat actors, the attack trees, the attack paths,
the protection dependencies, the users, the history and a diagram whose kind
is not `mermaid` have no place in the file this export writes. A component's
own tags, its version, its zone's boundary, and the `mitigates` edges between
components (both adopted and assumed) are not carried either. `--format json`
writes most of these; see `docs/threatmodel-export.schema.json`.

## `--format json`

This format is this application's own shape, for a risk register, a
dashboard or a spreadsheet that reads the numbers without parsing Markdown.
`docs/threatmodel-export.schema.json` states every key it writes; this table
states only what a reader compares against the other two formats.

### What it carries

The system's document control, the summary, the zones, the components, the
flows, the data inventory, the third parties, the known vulnerabilities, the
assumptions, the use cases, the exclusions, the threats (with their controls,
their compensating controls, what answered them upstream and what reduced
them), the recommendations, the leverage table and the accepted risks.

### What it drops

The users, the threat actors, the policy, the attack trees, the attack
paths, the protection dependencies, the rollup tables, the model's own
diagram blocks, the history and what changed since the last sampled commit,
the findings cut and the executive summary's and the methodology's own
prose have no place in this shape. A person who needs those reads the
Markdown report.
