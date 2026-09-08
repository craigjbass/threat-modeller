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
