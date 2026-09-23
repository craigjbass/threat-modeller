# Split a system by zone

**Status:** decided, 23 September 2026.

## The problem

`threatmodeller split <system>` moves three files into `arch/`, `controls/`
and `attacktree/` and writes no new content. One `.arch` file still holds
every zone, so two teams edit one file and every change meets every other
change.

The reader already joins several files: the merge holds one namespace across
the files of a system, resolves a flow end against every file, and reports a
duplicate identifier with both file names. What is missing is the command
that writes the files, the answers beside them, and an editor that reads a
part file as a part.

Today the language server reads every `.arch` file with the whole-file
parser, so a part file with no `system` block reports
`this file starts with system, not "<first word>"` at line 1, and every flow
in it reports `which this file does not declare`.

## The decision

### What the split writes

`SplitSystem` reads the system and writes files. It no longer moves bytes.

1. It reads every architecture file of the system as a part and merges them.
   A merge error stops the split, and the split writes nothing.
2. It gives each block a file:

| Block | File |
| --- | --- |
| the `system` block and every header field | `arch/<system>.arch` |
| `technology`, `user`, `threat_actor`, `assumption`, `clearance` | `arch/<system>.arch` |
| a component outside every zone | `arch/<system>.arch` |
| a `zone` block and the components it holds | `arch/<zone id>.arch` |
| a `flow` | the file of its source node |
| a `mitigates` edge | the file of its source node |

3. A zone whose identifier equals the system's stem stays in the header
   file, so two files never take one name.
4. It writes the header file with `ArchitectureWriter.write` and each zone
   file with `ArchitectureWriter.writePart`.
5. It deletes the files the content came from, and it deletes the report.
   The next report is written inside the subproject.

A flow whose source sits in a zone is written in that zone's file, and the
flow names a component another file declares. A flow whose source is a user,
or a component outside every zone, is written in the header file, because
that is the file its source sits in. A `mitigates` edge follows the same
rule. A component that a zone holds nests inside the `zone` block, so no
component needs the `zone` attribute after a split.

A system with no zone writes one architecture file, which is what the move
wrote before.

A system already in the directory form is read and written the same way, so
a second run of `split` sorts a subproject a person wrote by hand. A
subproject that is already in this shape writes the same bytes twice.

WARNING: the split writes the text through the writer rather than moving it.
A file that was not in the writer's order changes shape in the commit that
splits it.

### The header fields the writer drops today

`ArchitectureSourceSplit.parts` builds each part with an `ArchitectureSource`
initialiser that names neither `useCases`, `exclusions`, `systemAssets`,
`thirdParties`, `diagrams`, `description`, `authors`, `links`,
`repositories`, `created`, `reviewed`, `version` nor `attributes`. A save of
a split system drops every block of those kinds from the header file.

The split uses that writer, so the writer carries every header field into
the header's part. The window's save reads the same fix.

### The answers

Each architecture file takes the controls file that mirrors its stem, which
`ProjectSystem.controlsPath(mirroring:)` already states. The split routes
every answer by the origin of the element the answer names, the rule
`routedControls` states for `compile`:

| The answer names | The file |
| --- | --- |
| a component, a zone or a flow | the controls file that mirrors that block's architecture file |
| the system itself | `controls/<system>.controls` |

So `arch/edge.arch` gets `controls/edge.controls`. A later `compile` reads
the same origins and writes the same files, so the split and the compile do
not disagree.

A controls file answers for any element of the system. The reader applies
every file in `controlsPaths` to the whole model, and this design does not
narrow that.

### The trees

Each tree takes its own file: `attacktree/<tree id>.attacktree`. The reader
already reads every file in `attackTreePaths`, so a system of many tree
files reads whole.

`WriteAttackTree` reads one file named by `system.attackTreePath`, changes
one tree and writes the other trees back. It now finds the file by the
tree's identifier, and it lists the trees of every tree file. The command
line's `treeText(of:)` reads every tree file for the same reason.

### The editor

`LanguageServer.diagnostics(of:)` reads the system, not the one text:

1. It finds the system the open file belongs to, from the project layout.
2. It reads every architecture file of that system. It takes the editor's
   buffer for a file the editor holds open, and the file on disk for the
   rest.
3. It parses each file with `readPart` and merges them with
   `MergedArchitecture.merge`.
4. It publishes the diagnostics whose file is the open document. A merge
   fault that names two files is published in both files.
5. A file that belongs to no system is read with `read`, the way it is read
   today.

A merge fault carries line 1 and column 1, because the merge reads
identifiers and holds no token. A fault about an identifier inside a block
therefore marks the top of the file. Moving such a fault onto the line that
names the identifier needs the parser to record each reference's token, and
this design does not do that.

`architecturePaths()` and `libraryPaths()` read `documents.keys.first`, so
with two documents open they answer for the wrong one. Both take the uri the
request names.

### The faults

| Fault | Message |
| --- | --- |
| the split reads a system the merge refuses | `the system "<name>" cannot be split: <the first fault>` |
| two zones write one file name | `the zone "<id>" and the zone "<other>" both write the file "<name>.arch"` |
| the split cannot write a file | the `cannotWrite(reason:)` the response already holds |

`SplitSystemResponse` keeps `split`, `noSuchSystem` and `cannotWrite`, and it
gains `refused(reason:)` for the first two faults in the table. It loses
`alreadySplit`, because a split system is now read and written again.

The window's `splitSystem()` drops its `alreadySplit` message and shows the
`refused` reason as it shows the `cannotWrite` reason
(`ProjectSession.swift:1583-1599`).

The command line holds its own copy of the move
(`CommandLineApplication.swift:491-540`). It calls `SplitSystem` instead, so
one rule writes the files. `split` answers `ExitCode.fileFault` for
`noSuchSystem`, `refused` and `cannotWrite`.

### What does not change

- The language adds no attribute, so `docs/PARITY.md` gains no row and the
  window gains no control.
- The merge keeps one namespace for each kind of block across the files of a
  system. A zone, a component and a flow may still share one identifier, in
  one file or in three.
- A controls file still answers for any element of the system.
- The window's menu item `Split into Directory` calls the same use case, so
  the window gets the new behaviour with no change of its own.

## The checks

Every check drives a use case or the command line.

- A flat system with two zones splits into a header file and two zone files.
  Reading the subproject gives the model the flat file gave.
- A flow whose source sits in a zone is written in that zone's file. A flow
  that crosses zones is written in its source's file.
- A component outside every zone is written in the header file.
- A header that states `use_case`, `asset`, `third_party`, `diagram`,
  `author`, `link`, `repository`, `created`, `reviewed`, `version` and an
  attribute holds every one of them after the split.
- An answer for a zone's component is written in that zone's controls file.
  An answer about the system stays in the header's controls file.
- Each tree is written in `attacktree/<tree id>.attacktree`. `attack` lists
  every tree, and writing one tree changes one file.
- A second run of `split` on a split system changes no bytes.
- A system the merge refuses is not split, and the files on disk do not
  change.
- Two zones that write one file name stop the split with the message above.
- `threatmodeller split <system>` on a flat system writes the same files the
  use case writes, and it answers a non-zero exit code for a system the merge
  refuses.
- The language server publishes no fault for a part file that names a
  component another part declares.
- The language server publishes a fault for a name no part of the system
  declares.
- The language server answers for the document the request names when two
  documents are open.
