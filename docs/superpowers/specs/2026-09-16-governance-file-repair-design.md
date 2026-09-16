# Repairing a governance file the parser refuses

Issue #144. A person removed a third party in the assumptions panel, saved,
and the project stopped opening.

## What was wrong

`SourceGovernedThreat.key` built a threat key from the word the file states.
The file states `flow`; every other reader of a threat key states
`connection`, which section 5.10 of the language guide names as the one key
and `SourceThreatAnswer.resolverKind` as the one place that maps the two
words.

So on every save:

1. `CompileGovernance` looked for the existing block of a flow's threat under
   the key `<id>@connection:<flow>` and found none, because the block was
   keyed `<id>@flow:<flow>`.
2. It wrote a fresh block with every field empty.
3. It then read the existing block as a threat the architecture no longer
   raises, and wrote it again, marked `stale`.

The file then held two blocks with one key. `GovernanceParser` records
`<key> is governed twice` as an error, so `GovernanceRead.source` is nil,
`OpenSystem` returns `.refused`, and the window draws nothing. The owner, the
dates and the rationale a person wrote sat in the `stale` block and were not
read.

The reproduction is `GovernanceDuplicateBlockTests`. Before the fix it
recorded `connection-mitm@flow:api->db is governed twice` at line 1, column 1,
and `OpenSystem` refused `s.governance`.

## The fix

`SourceGovernedThreat.key` and `GovernanceStanza.changing` map the source
kind through `SourceThreatAnswer.resolverKind`. A block and an answer on one
flow now hold one key, so the compile finds the block, keeps it whole, and
writes one block.

The same map repairs three other readers that were wrong for a flow:
`CheckGovernance`, `ApplyGovernance` through `PolicyRules`, and
`CheckPolicy.acceptedRisks` all key a governance block against a controls
answer.

## The repair, and why it is a repair and not a looser parser

A file already written in the refused shape sits in a person's repository.
Two ways back were open:

1. The parser reads two blocks with one key and merges them.
2. The parser keeps refusing, and a repair rewrites the file.

This design takes 2.

Two blocks with one key state two decisions about one threat. Section 8.6 of
the language guide states the refusal, and section 5.10 states the matching
refusal for the controls file. A parser that merged them would pick one of two
owners on its own, print nothing, and the person would never know which
decision the application kept. The refusal is correct and stays.

The repair is `GovernanceSourceGateway.repair`, wired into
`threatmodeller format`:

- `format` writes each system's `.governance` file in the canonical shape, the
  way it already writes `.arch` and `.lib` files.
- A file the parser refuses goes to the repair. The repair merges the blocks
  that share a key, and the actions that share a label.
- The merge keeps every attribute a person wrote. Each attribute takes the
  first value the file states, in file order. A block or a stanza stays
  `stale` only when every block or stanza with that key is stale, because one
  block that is not stale says the architecture still raises the threat.
- The repair states `repaired` only when the file it wrote parses with no
  fault. Any other fault it hands back as `cannotRepair`, `format` prints the
  parser's own lines, and the file is left alone.
- `format` prints one line per merged key, so a person reads what changed.

The window shows the parser's message with the line already:
`ProjectSession` puts the diagnostics and the file name on screen, and
`DiagnosticsSheet` prints each as `<file>:<line>:<column>: <message>`. A
person reads the message, runs `threatmodeller format`, and opens the project
again.

## What holds it

- `GovernanceDuplicateBlockTests`: the reproduction, and the system opens
  again.
- `GovernanceWriterTests`: every stanza shape the writer can produce parses
  back, over every combination of stale and not stale at each level, and a
  rewrite of what was read writes the same bytes.
- `GovernanceRepairTests`: the merge keeps every attribute, keeps a block
  stale only when every block is, merges actions, needs no repair on a file
  that parses, and repairs nothing when the fault is something else.
- `GovernanceFormatTests`: `format` repairs the file, and the system opens
  after it.
- `GovernanceSurvivesAnEditFlowTests`: the four assumptions editors, in the
  window.
- `scripts/cli-smoke.sh`: a governed system loses a third party and still
  parses and checks; `format` repairs a file in the refused shape.
