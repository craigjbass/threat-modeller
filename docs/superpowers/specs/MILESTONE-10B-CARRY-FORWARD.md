# Carry-forward into Milestone 10B

What Milestone 10A closed, and what it left.

## Closed in Milestone 10A

- The architecture language: a lexer, a parser that reports every fault with a
  line and a column, and a writer with a canonical shape. Two properties hold
  it: parse, write, parse gives the same value tree, and writing a canonical
  file reproduces it character for character.
- `LayOutModel`: a diagram placed from declaration order alone, with the
  coordinates stated in tests.
- `ImportArchitecture` and `ExportArchitecture`, each one change on the gateway.
- The project convention, one `ProjectConvention` read by a fake and a real
  gateway under one shared contract.
- `OpenProject`, `OpenSystem`, `SaveSystem`, and the project window with its
  systems picker, its notice strip and its diagnostics sheet.
- The `threatmodeller-cli` executable with `format`, and the Ubuntu job that
  builds, tests and runs it.
- The `--catalogue` override, so a Linux binary can be told where its data is.

## New in Milestone 10A

1. **The executable's product is named `threatmodeller-cli`.** A product named
   `threatmodeller` lands beside `threatmodeller.app` in one build directory,
   and the interface test runner then reads the wrong file:
   *"The bundle identifier for threatmodeller couldn't be read."*
   `scripts/build-linux.sh` installs the binary as `threatmodeller`.

2. **The project window is one window for the whole application.** A second
   window on one directory would fight the first over its files. A user cannot
   have two projects open at once.

3. **Nothing watches the project directory.** Spec §8.2 says a file that changes
   on disk reloads. It does not yet: a user who runs `git checkout` must choose
   the system again.

4. **There is no app-scoped bookmark yet.** The entitlement is in place and the
   open panel works, but *Open Recent Project* is unwritten, so a relaunch
   forgets which project was open.

5. **`OpenProject` reads the directory twice.** `OpenSystem` and `SaveSystem`
   each call `discover` again rather than taking the layout they were given.

6. **The project window's save is ⌥⌘S, not ⌘S.** ⌘S belongs to the document
   window's own save, and the two scenes share one menu.

7. **A warning is raised for a technology nothing holds, with line 1, column 1.**
   The import knows which component is at fault but not where it was declared,
   because the source tree does not carry positions. Carry a position on
   `SourceComponent` if a user asks to be taken to the line.

8. **The parser reports a duplicate identifier at line 1, column 1** for the
   same reason.

9. **`format` rewrites a file it read even when only whitespace differs.** That
   is the point of the verb, but it means a formatting run shows in `git diff`
   as a whole-file change the first time it is used on an existing project.

10. **Nothing checks that a technology block's threat ids exist.** The parser
    accepts them and `TechnologyLookup` drops what the catalogue does not hold,
    silently.

## Standing, from the earlier lists

The zone-drag undo defect of Milestone 6B; the sensitivity gap is now closed;
items 3, 4, 6 to 17 and 19 to 28 of the Milestone 10 carry-forward stand as
written in `MILESTONE-10-CARRY-FORWARD.md`.
