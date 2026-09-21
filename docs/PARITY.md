# The window writes every attribute the languages read

The rule, stated 16 September 2026: the window has one-to-one parity with the
code model. Every attribute the languages in `docs/LANGUAGE.md` read is written
from the window, and every value the window writes is one the languages read.

## Where the list is

The list is a test, not a document. A list in a document is written by hand
once and goes stale; a list in a test is checked on every run.

| File | What it holds |
| --- | --- |
| `ThreatModelKit/Sources/ArchitectureDSL/LanguageVocabulary.swift` | every block of every language and the attribute names its parser reads |
| `threatmodellerTests/WindowModelParityList.swift` | one row per attribute: the control that writes it, or the reason |
| `threatmodellerTests/WindowModelParityTests.swift` | the walk that pairs the two |

Every parser builds its unknown-attribute message from `LanguageVocabulary`, so
the declaration is the parser's vocabulary, not a copy of it.

## What a row states

| Verdict | Meaning |
| --- | --- |
| `writes(<identifier>)` | a control a person can change writes the attribute; the word is the control's accessibility identifier, or its fixed prefix when a view builds the identifier from an element id |
| `stated(<reason>)` | the window writes no value here and the reason is not a fault: the word names a nested block, a gesture writes it, or the window shows it and no control changes it |
| `gap(<issue number>)` | the attribute is not in the window; the issue states what to build |

## What the test refuses

- An attribute with no row. A new attribute in any language fails the walk
  until the window gains the control that writes it, or the list states the
  reason.
- A row for a word no parser reads.
- A row whose identifier no window view declares.

## The gaps open today

Every gap below is an open issue. A gap is one block's set of attributes the
window neither shows nor writes; two blocks that are the same missing feature
take one issue.

| Language | Block | Attributes | Issue |
| --- | --- | --- | --- |
| `.arch` | `system` | `requires_evidence_above` | [#160](https://github.com/craigjbass/threat-modeller/issues/160) |
| `.arch` | `diagram` | `kind` | [#161](https://github.com/craigjbass/threat-modeller/issues/161) |
| `.arch` | `asset` (in system) | `description` | [#162](https://github.com/craigjbass/threat-modeller/issues/162) |
| `.arch`, `.lib` | `threat_actor` | `aliases` | [#163](https://github.com/craigjbass/threat-modeller/issues/163) |
| `.arch` | `zone` | `description`, `source` | [#164](https://github.com/craigjbass/threat-modeller/issues/164) |
| `.arch` | `component` | `source` | [#165](https://github.com/craigjbass/threat-modeller/issues/165) |
| `.controls` | `control` | `note` | [#167](https://github.com/craigjbass/threat-modeller/issues/167) |
| `.controls` | `compensating` | `sources` | [#168](https://github.com/craigjbass/threat-modeller/issues/168) |
| `.attacktree` | `attack_trees for` | `catalogue` | [#169](https://github.com/craigjbass/threat-modeller/issues/169) |
| `.attacktree` | `step` | `note` | [#170](https://github.com/craigjbass/threat-modeller/issues/170) |
| `.lib` | `classification` | `colour` | [#171](https://github.com/craigjbass/threat-modeller/issues/171) |
| `.lib` | `threat` | `connection`, `zone`, `applies_to`, `boundary`, `runs_as`, `pathway` | [#172](https://github.com/craigjbass/threat-modeller/issues/172) |
| `.lib` | `mitigation` | `description` | [#173](https://github.com/craigjbass/threat-modeller/issues/173) |

The `.governance` language is complete: every value attribute has a control.

A policy file and a library file are read in the window and written in a text
editor. Their rows state `read only in the window` with the place the window
draws the value.

## An attribute that names another block

One attribute names a block somewhere else in the file, so removing that block
changes the attribute. The row states the one rule the window, the use case and
the language all follow.

| Language | Attribute | Rule |
| --- | --- | --- |
| `.arch` | `uses "<client>"` on a `user` block | The label names a component the file declares. `RemoveComponents` takes the client off every user that holds it, with the components reached through it. The user panel opens one `user-use-reaches-<client>` row per client the user holds, so a client with no reach still shows its row. |
| `.controls` | `mitigated_by` on a `control` block | The value names a `mitigates` edge the `.arch` file declares, written `<protector>-><protected>`. `ApplyControlAnswers` drops a mapping whose edge the architecture no longer declares, or whose edge answers another threat or another element, keeps the control's status, and warns; the next compile writes no `mitigated_by`. The threat card opens one `control-mitigated-by-<key>` picker per control, offering only the edges that answer this threat on this element, and it reads `Nobody` while nothing is mapped. |
| `.arch` | `recommendation.blocked_by` on a `mitigates` edge | The parser refuses an action whose `blocked_by` names an assumption the file does not declare. `RemoveAssumption` clears `blocked_by` on every edge that names the removed assumption, keeps the action, and reports how many actions it unblocked. The assumptions panel shows that count in `unblocked-actions-note`. The mitigates sheet opens the "Held up by" picker on `nothing` when the model no longer declares the blocker. |

## What to do when a language changes

1. Add the attribute to the block's entry in `LanguageVocabulary`.
2. Add the control that writes it, in the panel or the sheet that owns the
   block, with a flow test that reads the file back.
3. Add the row to `WindowModelParityList` naming that control's identifier.

A language change with no control is not done.
