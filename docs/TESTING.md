# Running the tests

```
cd ThreatModelKit && swift test          # the package: fast, no application
xcodebuild test -project threatmodeller.xcodeproj \
  -scheme threatmodeller -destination 'platform=macOS'
scripts/cli-smoke.sh                     # the executable, over real files
```

The third command runs the executable over projects it writes in a temporary
directory, and reads what the executable wrote and what it exited with. The
Linux job runs that same file, so a smoke test cannot say one thing here and
another in the job. `THREATMODELLER` names how to run the executable, which is
how the job runs the script against the static binary.

The second command runs the application tests. There are no interface journeys:
they needed macOS Automation Mode, which this machine will not enable without
authentication, so a test nobody could run was worse than no test. What they
covered is now split between `threatmodellerTests/ViewRenderTests.swift`, which
draws each view with `ImageRenderer` and reads the pixels back, and the session
tests, which state what each control does.

## What covers the icon

`threatmodellerTests/IconDrawingTests.swift` runs `scripts/make-icon.swift`
into a temporary directory and states, for each of the ten sizes, the pixel
size, that the drawing holds more than one colour, and the checksum of the
bytes. A change to the drawing fails the test and the message names the size
and its new checksum; a change made on purpose is that checksum written into
the table at the top of the file.

The test runs `swift`, which reads AppKit, so it runs in the macOS job with
the rest of the application tests. The Linux job runs the package tests and
never this one.

## What covers the canvas gestures

Six gestures move the model: node drag, marquee selection, connection drawing,
zone move, zone resize and undo. `threatmodellerTests/CanvasGestureTests.swift`
covers all six. Each test calls what the gesture's `onChanged` and `onEnded`
call, with the numbers SwiftUI reports, so the code under test is the code the
gesture runs. `threatmodellerTests/ZoneSelectionTests.swift` covers the same
gestures over a group of zones. `threatmodellerTests/TreeCanvasGestureTests.swift`
covers the tree canvas the same way: pan, zoom, marquee, drag, join, drop,
undo and Zoom to Fit, and `threatmodellerTests/canvas/ViewportGesturesTests.swift`
states the rules both canvases share.

**Why nothing presses the mouse.** A synthetic `NSEvent` does not reach a
SwiftUI gesture. Measured: a `CanvasView` in an `NSWindow`, laid out, with
`leftMouseDown` and `leftMouseUp` sent to the window at the middle of a node's
drawn rectangle, left `canvas.selectedComponentIds` empty. `NSHostingView` also
publishes no accessibility children in process, so no test can find a node by
its identifier and read its frame that way. Driving the pointer needs macOS
Automation Mode, which the next section states this machine will not enable.

Carry-forward item 27 asked whether a node far from the origin selects where it
draws. `aNodeFarFromTheOriginIsFoundWhereItDraws` walks the chain a tap walks —
view point, `CanvasTransform.modelPoint`, `CanvasHitTest.component` — for a node
at (4200, 3100) with the canvas panned and zoomed, and
`aClickPastTheDrawnEdgeOfAFarNodeFindsNothing` states the edge.

## If interface journeys are ever wanted again

They need Automation Mode, and this machine asks for authentication every time
it is enabled:

```
$ automationmodetool
Automation Mode is disabled.
This device requires user authentication to enable Automation Mode.
```

A runner asks for it, a panel appears, and the run fails after 60 seconds when
nobody answers the panel. Answer the panel while the run starts, or allow it
once and for all:

```
automationmodetool enable-automationmode-without-authentication
```

That command needs an administrator, and it lets any process on this machine
drive the interface without a further prompt. Turn it back off with
`automationmodetool disable-automationmode-without-authentication`.

`swift test`, the application tests and the render tests need none of this.

## After adding a file to `ThreatModelKit`, clean first

**Symptom.** `cd ThreatModelKit && swift test` passes, and
`xcodebuild test` then fails with `Cannot find type '<the new type>' in scope`
while it emits the module for `TestSupport`.

**Cause.** The Xcode build reuses its own copy of the package modules. A source
file added to the package does not reach it.

**Recovery.**

```
xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
```

Run the clean once, after adding the file, before the application tests.

## When `xcodebuild test` hangs with no output at all

**Cause.** `testmanagerd` holds one test session per user. Killing a test
process while a run is in flight — the runner, the host application, or
`xcodebuild` itself — leaves that session open. Every later run then waits for a
session it can never get: the run produces no output, and the host application
sits in `-[XCTestDriver _prepareTestConfigurationAndIDESession]` waiting.

**Recovery.** Restart the daemon. `launchctl kickstart` is refused while System
Integrity Protection is on, so kill it and let `launchd` start it again:

```
pkill -f 'Developer/usr/bin/xcodebuild'
pkill -x threatmodeller
kill -9 $(pgrep -x testmanagerd)
```

The next `xcodebuild test` starts a clean session.

**Prevention.** Do not `pkill` a test runner or a host application to stop a
run. Stop `xcodebuild` and let it tear its own session down. If a run must be
killed, restart `testmanagerd` straight afterwards, before starting another.

**It recurs on its own.** On 2026-09-08 a run hung this way with nothing killed
before it, and the run before it and the run after it both passed. The recovery
above clears it every time, and takes about ten seconds. Treat a run that has
printed nothing for two minutes as this fault rather than as a slow test.

## How the fault was found

The evidence, in order, in case it is ever needed again:

1. `sample <xcodebuild pid>` showed it waiting in
   `-[Xcode3CommandLineBuildTool waitForBuildWithBuildLog:…]`, which pointed at
   the build; the build service was idle, so that was wrong.
2. The run then reached the application launch, which proved the build was fine.
3. `sample <application pid>` showed the injected test bundle blocked in
   `-[XCTestDriver _prepareTestConfigurationAndIDESession]` → `-[XCTFuture value]`:
   waiting for the test session, which named the real fault.
4. Killing `testmanagerd` cleared it, and the same command then ran 137 tests.
5. The interface journeys still failed after that, which is a second and
   separate fault: `automationmodetool` reported Automation Mode disabled and
   authentication required.

## Seeing a view when the screen cannot be captured

This machine refuses both permissions a screen capture needs:

```
$ swift -e 'import CoreGraphics; import ApplicationServices; print(CGPreflightScreenCaptureAccess(), AXIsProcessTrusted())'
false false
```

So `screencapture` and `System Events` are both dead ends. Two routes need
neither permission.

**A preview snapshot.** Xcode runs an MCP server. Add a `#Preview` to the view,
then ask Xcode to render it:

```
xcrun mcpbridge          # the stdio bridge; Xcode must be running
```

`XcodeListWindows` gives the `tabIdentifier`, and `RenderPreview` takes that and
a source file path and writes a PNG.
`threatmodeller/LayoutPreviews.swift` holds the previews that show each layout
fault at the column size it appears in.

**A hosting view, for a test.** `hostedDrawing(of:width:height:)` in
`threatmodellerTests/HostedDrawing.swift` puts the view in an offscreen window
and reads the pixels back.

Use it rather than `ImageRenderer` for any view whose content scrolls.
`ImageRenderer` lays a view out with no scroll geometry, so a `LazyVStack`
inside a `ScrollView` never fills in and the picture comes back blank.
`LayoutFitTests` reads margins and content from these pictures.

## When RenderPreview reports the app did not launch

**Symptom.**

```
Failed to launch app ”threatmodeller.app” in reasonable time
The app ”threatmodeller.app” did not launch on ”My Mac” in 30 seconds.
```

`RunCodeSnippet` reports the same.

**Cause.** A test run leaves its host copy of the application running. The
preview agent then cannot start its own.

**Recovery.** Stop the host copy, then build once before rendering again:

```
pkill -x threatmodeller
```

Then `BuildProject`, then `RenderPreview`. The build alone clears a second
fault with the same symptom, in which the preview pipeline reports
`FailedToAddDependency` after a source file changes under it.

When the same error repeats and `pgrep -x threatmodeller` shows a new process
each time, the preview daemon is holding the old session. Stop it as well, and
`launchd` starts it again:

```
pkill -x threatmodeller
kill -9 $(pgrep -f PreviewsOSSupport.framework/Support/previewsd)
```

Wait three seconds, then render.

**Prevention.** Run `pkill -x threatmodeller` after every `RunAllTests` or
`RunSomeTests`, before the next preview or snippet.

## What listing the threat choices costs

The custom technology editor lists every threat a technology can carry, and
`TechnologyLookup` reads the same set. Both used to walk every technology and
ask for its threats, which is one read of the catalogue per technology.
`TechnologyCatalogue.everyThreat()` answers in one read from an index the
gateway builds as it parses the file.

Measured in a release build, over the vendored catalogue's 286 technologies,
each figure the mean of a hundred calls:

| What | Time |
| --- | --- |
| `ListThreatChoices`, walking every technology | 0.00073 s |
| `ListThreatChoices`, one indexed read | 0.00004 s |

## What one resolution costs, and what the history costs

`ThreatResolver.resolve` is what the threat list and the risk summary both
read. One change used to run it twice: the list ran one and the summary ran
another. `ThreatResolutionCache` keeps the answer against the model's
revision, so one change runs it once.

Measured in a release build, sixty components in one zone with fifty-nine
flows:

| What | Cost |
| --- | --- |
| One `ThreatResolver.resolve` | 0.0056 s |
| The undo history, at its full depth of 100 snapshots | 736 KB resident |

The history holds a whole model per step. At sixty components that is about
7 KB a step, and the depth is capped at
`InMemoryThreatModelGateway.historyLimit`, which is 100, so a session holds
under a megabyte of history whatever a person does.

## What a compile costs

`threatmodeller compile` scores a model and draws nothing. Zone membership is a
field on the component, set from the nesting the `.arch` file states, so the
compile path runs no layout search. Measured in a release build, by the method
the section below states, with sixty components in one zone and fifty-nine
flows:

| What | Time |
| --- | --- |
| `CompileControls.execute`, before the field | 0.512 s |
| `LayOutModel.execute` alone | 0.502 s |
| `CompileControls.execute`, after the field | 0.010 s |

## What listing the systems costs

`threatmodeller list` resolves each system once and draws nothing: it reads the
canvas for the counts and the assessment for the scores, and no code in the
path places a component. Measured in a debug build by
`SystemListTests.readsAProjectOfManySystemsQuickly`, with twenty systems of two
components, one zone and one flow each:

| What | Time |
| --- | --- |
| `list` over 20 systems | 0.445 s |
| one system | 0.022 s |

Run it again with:

```sh
cd ThreatModelKit
THREATMODELLER_MEASURE=1 swift test --filter readsAProjectOfManySystemsQuickly
```

## What reading the history costs

`threatmodeller history` and `threatmodeller report` compile the model once per
sampled commit, so the cost grows with the bound. Measured in a release build,
by the method the next section states, with a fake git gateway so no `git`
process is in the number:

| Model | Commits | Time |
| --- | --- | --- |
| 60 components, one system | 100 | 0.376 s |

That is the compile and the assessment of every commit, and it is why the
default bound is 50 and why nothing reads the history when a window opens.
Reading `git` itself adds one `git log` and one `git show` per file per commit,
which the number above does not hold.

Measure it again the way the layout is measured: write a probe under
`ThreatModelKit/Tests/UnitTests/`, build the model in it, time
`ReadRiskHistory.execute`, run `swift test -c release --filter <the probe>`,
then remove the probe. Do not measure through Xcode's `RunCodeSnippet`.

## What a layout costs

Measured in a release build on 2026-09-15, by the method the section below
states, with the components in one zone and one flow between each pair in a
line:

| Components | Time |
| --- | --- |
| 10 | 0.010 s |
| 20 | 0.025 s |
| 30 | 0.061 s |
| 40 | 0.106 s |
| 60 | 0.238 s |

## Measuring what a layout costs

`LayOutModel` is the slow part of opening a model. Measure it in the package,
in a release build, because a debug build is about seventeen times slower and
weights the parts differently: the change that took a release layout from
0.069 s to 0.051 s moved a debug one only from 0.861 s to 0.824 s.

Write a probe under `ThreatModelKit/Tests/UnitTests/`, build a `.arch` source
in it, read it with `HclArchitectureSource`, and time
`LayOutModel().execute(LayOutModelRequest(source:))`. Twelve components and
eleven flows is enough to compare one build against another and runs in
seconds. Remove the probe afterwards; a printed timing on every test run is
noise.

```
cd ThreatModelKit && swift test -c release --filter <the probe>
```

The first release build takes about three minutes. Do not measure this through
Xcode's `RunCodeSnippet`: it launches the whole application, and one attempt
ran seven minutes and printed nothing.
