# Risk over time — design

Date: 2026-09-15
Status: approved for planning

## 1. Why

A report states the posture of one day. The question a team asks after a sprint
is "did risk go down?", and no report answers it.

`2026-09-13-report-professional-structure-design.md` lines 29 to 30 put this
out of scope: "The tool stores no prior report, so a change log needs a second
input and a diff engine." The second input exists. The project is in git, every
commit holds the `.arch`, `.controls`, `.attacktree` and `.governance` files of
that day, and the compile is deterministic. The score at every commit is
recoverable by reading the files at that commit.

## 2. The four decisions

### 2.1 Which commits are sampled

**Every commit that touched a threat model file, newest first, bounded to a
count.** The bound defaults to 50 and `--commits <n>` changes it.

A commit that touched no threat model file cannot change a score, so sampling
it costs a compile and shows a flat line. Tags are not sampled on their own: a
tag names a commit, and a project that tags every release still has those
commits in the list. The bound is what keeps a five-year repository from
compiling five thousand times, and the row list states when it truncated, so a
silent truncation never reads as the whole history.

### 2.2 How git is read

**A child `git` process behind a gateway**, with a fake for tests. No libgit2:
the package builds statically on Linux and ships as one binary, and a C
dependency would end that.

```swift
public protocol GitHistoryGateway: Sendable {
    /// The commits that touched any of `paths`, newest first.
    func commits(root: String, touching paths: [String], limit: Int) throws -> [SourceCommit]
    /// One file as it stood at one commit, or nil when the commit holds no
    /// such file.
    func file(root: String, at hash: String, path: String) throws -> String?
    /// Whether the directory is inside a git repository at all.
    func isRepository(root: String) -> Bool
}
```

The gateway reads with `git log` and `git show <hash>:<path>`. It never checks
out, never stashes, and touches neither the working tree nor the index. A test
proves the working tree is unchanged after a read.

### 2.3 Which numbers describe one commit

| Number | Why |
| --- | --- |
| `totalScore` | the sum of every residual score: the one number a direction is read from |
| `byLevel` | how many threats sit at each risk level |
| `worstScore` | the worst single threat, which a total can hide |
| `acceptedRisks` | how many risks the organisation carries |
| `openAttackTrees` | how many written routes are still open |
| `catalogueTag` | the catalogue the files named, because a score that moved on a catalogue change is not a posture change |

### 2.4 A commit whose files do not parse

The row is kept and states `did not parse` in place of its numbers. The graph
draws a gap there rather than a zero: a zero reads as "no risk", which is the
opposite of what a file that does not parse means.

## 3. What the verb prints

```
threatmodeller history [<root>] [--commits <n>] [--format <plain|github|json>]
```

One row per sampled commit, newest first:

```
2026-09-14  a1b2c3d  Craig  total 184  worst 12  critical 2  high 5  accepted 1  trees 1  v1.0.1
2026-09-07  9f8e7d6  Craig  did not parse
```

Two runs on one repository print the same rows: the sample is the git history,
the compile is deterministic, and nothing reads the wall clock.

## 4. The graph

An inline SVG, written beside the report as `<stem>-risk-over-time.svg` and
referenced from it, the way the threat pictures already are. The package writes
SVG itself, so every build draws it, including the static Linux one. No stored
image file is read.

The line is the total score against the commit date, oldest on the left. A
commit that did not parse breaks the line rather than dropping it to zero.

The application draws the same rows with the same numbers, in a sheet a person
opens from the menu. The history is read at the user's request and never at
open time, because reading it compiles the model once per sampled commit.

## 5. The report

`## Risk over time` holds the graph and the rows. `## What changed` states the
difference between the previous sampled commit and the working tree:

- threats the working tree raises that the commit did not, and the other way;
- controls whose status changed, by control and by threat;
- accepted risks added, and accepted risks whose review date moved;
- the score delta per element, worst first;
- the catalogue tag, when the two commits named different ones.

A project with one commit writes neither section: there is nothing to compare.

The executive summary states the direction in one sentence: `Risk is down 12
since the previous assessment.`, `up 12`, or `unchanged since the previous
assessment.`

## 6. What this design refuses

- **No stored history.** Nothing writes a file of past scores. The history is
  git, and a second store would drift from it.
- **No commit-by-commit blame.** The report states what changed between two
  points, not who changed it. `git` answers that better.
- **No history at open time.** A person asks for it.

## 7. Where the code goes

| File | Change |
| --- | --- |
| `architecture/gateway/GitHistoryGateway.swift` | new |
| `architecture/domain/SourceCommit.swift` | new |
| `assessment/domain/RiskHistoryRow.swift` | new: the numbers of one commit |
| `architecture/usecase/ReadRiskHistory.swift` | new: samples, compiles and scores |
| `architecture/usecase/CompareRiskToCommit.swift` | new: what changed |
| `FileGateways/GitHistory.swift` | new: the child `git` process |
| `TestSupport/FakeGitHistory.swift` | new |
| `TestSupport/GitHistoryContract.swift` | new |
| `DiagramRendering/RiskOverTimeChart.swift` | new: the SVG |
| `reporting/domain/Report.swift` | the rows and the change list |
| `reporting/usecase/MarkdownRiskOverTime.swift` | new |
| `reporting/usecase/MarkdownWhatChanged.swift` | new |
| `CommandLineApplication/CommandLineApplication.swift` | the `history` verb |
| `threatmodeller/history/HistorySheet.swift` | the sheet |
| `docs/TESTING.md` | the measured cost |
| `README.md` | the verb and the two sections |

## 8. Testing

| Test | Says |
| --- | --- |
| `GitHistoryContract` | both gateways answer the same for a repository, a file at a commit, and a path the commit does not hold |
| `GitHistoryTests` | the real gateway leaves the working tree and the index unchanged |
| `ReadRiskHistoryTests` | the numbers of each row, the bound, the truncation note, and a commit that does not parse |
| `CompareRiskToCommitTests` | each of the five things `## What changed` states |
| `MarkdownRiskOverTimeTests` | the section, and no section for a project with one commit |
| `RiskOverTimeChartTests` | the line, and a gap where a commit did not parse |
| `CommandLineApplicationTests` | the verb prints the rows, and twice the same |

Every test uses the fake gateway and `FixedClock`. No test runs `git`, except
the one that proves the real gateway leaves the working tree alone, and that
one builds its own repository in a temporary directory.
