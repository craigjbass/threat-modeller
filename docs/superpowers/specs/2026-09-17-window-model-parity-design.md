# The window has one-to-one parity with the code model

**Status:** decided, 17 September 2026. Issue #152.

## The problem

The user's rule for the window, stated 16 September 2026: every attribute the
languages in `docs/LANGUAGE.md` read is written from the window, and every
value the window writes is one the languages read.

Nothing checked the rule. Issue #127 added `tags` to `component`, `zone` and
`flow` in the parser and the writer, and a Tags field to `ComponentPanel`
alone. A zone and a flow could be tagged in a text editor and never in the
window, and no test failed.

The rule cannot be checked while each parser spells its vocabulary twice. A
parser reads an attribute in a `switch` over `case` words, and names the same
words a second time as prose inside the unknown-attribute message. The two
copies drift: `LibraryParser` read `control` on a `technology` block and left
`control` out of the message.

## The decision

### One declaration of the vocabulary

`ThreatModelKit/Sources/ArchitectureDSL/LanguageVocabulary.swift` declares
every block of every language and the attribute names its parser reads.

`LanguageBlockId` is a `CaseIterable` enum, one case per block. Its `block`
property is an exhaustive `switch` that returns a `LanguageBlock`, so the
compiler refuses a new case with no entry. `LanguageVocabulary.blocks` is the
walk a test takes.

`LanguageBlock` builds the unknown-attribute message from its own word list.
Every parser's `default:` branch calls it, so the message and the declaration
cannot disagree.

| Type | Shape |
| --- | --- |
| `LanguageBlock` | `language`, `name`, `phrase`, `attributes`, `listsWithCommasAlone` |
| `LanguageBlockId` | one case per block, `CaseIterable` |
| `LanguageVocabulary` | `blocks`, `attributeKeys` |

A block is keyed by `<language>.<block name>`. One keyword that names two
blocks carries a qualifier: `asset (in system)` and `asset (in component)`.

### The parity list

`threatmodellerTests/WindowModelParityTests.swift` holds the list. Each row
pairs one attribute with one of three verdicts:

| Verdict | Meaning |
| --- | --- |
| `writes(<identifier>)` | a control a person can change writes this attribute; the word is its accessibility identifier |
| `stated(<reason>)` | the window writes no value here and the reason is not a fault: the word names a nested block, or a gesture writes it, or the window shows it and nothing changes it |
| `gap(<issue number>)` | no control writes it; the issue states what to build |

The test walks `LanguageVocabulary.blocks`. It fails when an attribute has no
row, and it fails when a row names an attribute no block holds. A new
attribute in any language therefore fails the test until the window gains the
control that writes it, or the list states the reason.

The test reads the identifiers back from the window's own views, so a row that
names an identifier no view declares fails too.

`docs/PARITY.md` states the rule for a reader and links the open gap issues.
The list itself lives in `threatmodellerTests/WindowModelParityList.swift`, because a list in a document is written by
hand once and a list in a test is checked on every run.

### One issue per gap

A gap is one block's set of unwritten attributes, not one attribute. The
issue goes in the milestone the block belongs to, carries a `model:` label,
and its number is the row's verdict, so the list links the issue and the issue
names the attributes.
