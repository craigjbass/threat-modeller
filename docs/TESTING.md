# Running the tests

```
cd ThreatModelKit && swift test          # the package: fast, no application
xcodebuild test -project threatmodeller.xcodeproj \
  -scheme threatmodeller -destination 'platform=macOS'
```

The second command runs the application tests. There are no interface journeys:
they needed macOS Automation Mode, which this machine will not enable without
authentication, so a test nobody could run was worse than no test. What they
covered is now split between `threatmodellerTests/ViewRenderTests.swift`, which
draws each view with `ImageRenderer` and reads the pixels back, and the session
tests, which state what each control does.

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
