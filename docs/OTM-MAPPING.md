# The Open Threat Model export

`threatmodeller export --format otm` writes an Open Threat Model file, which
other threat-modelling tools read. This page states what each part of this
model becomes in that schema. The version written is stated in the file as
`otmVersion`.

OTM states a project, trust zones, components, dataflows, threats and
mitigations. It carries no score of its own, so the assessment's numbers ride
in `risk` and in `attributes`.

## What becomes what

| This model | The OTM file | Note |
| --- | --- | --- |
| the system's name | `project.name` | `project.id` is the name as an identifier: lower case, a dash for anything else |
| the system's owner | `project.owner` | absent when the system states none |
| the system's description | `project.description` | |
| the diagram the canvas draws | one entry in `representations`, of type `diagram` | OTM asks for a representation before a component may state where it sits. This model states no coordinates in a report, so the entry names the diagram and nothing more |
| a zone | one `trustZones` entry | the id is the zone's name as an identifier |
| a zone's kind and network | `trustZones[].description` | written as `<zone>, <network>` |
| a zone's risk reduction | `trustZones[].risk.trustRating` | zero when the zone states none |
| a component | one `components` entry | the id is the component's own id |
| a component's category | `components[].type` | `generic-component` when the catalogue no longer holds the technology |
| a component's zone | `components[].parent.trustZone` | absent for a component outside every zone |
| a component's technology, classification, privilege and status | `components[].tags` | four tags, in that order. The status tag is `Live` or `Proposed` |
| a flow | one `dataflows` entry | the id is `<source>-><target>`, which is the id this model keys a flow on |
| a flow's kind | `dataflows[].tags` | one tag |
| a threat on one element | one `threats` entry | see below |
| a control on a threat | one `mitigations` entry | see below |

## Threats

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
| the score before every control | `risk.inherentScore` |
| the risk level | `risk.level` |
| the severity | `attributes.severity` |
| whether anybody answered it | `attributes.isOpen` |
| what raised it | `attributes.raisedBy`, `attributes.element` |
| the assets on that element | `attributes.assetsAtRisk` |
| the MITRE ATT&CK techniques | `attributes.mitreTechniqueIds` |

`cwes` is written empty: this model states MITRE ATT&CK techniques, not CWE
identifiers.

## Mitigations

One control on one threat is one `mitigations` entry. The id is the threat id
and the control's description as an identifier.

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

## What the OTM file does not carry

The recommendations, the leverage table, the accepted risks, the assumptions,
the scope, the data inventory, the third parties, the attack trees and the
history have no place in the OTM schema. `--format json` writes all of them;
see `docs/threatmodel-export.schema.json`.
