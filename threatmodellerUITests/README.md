# No journeys live here

The interface journeys that used to be in this target were deleted.

They needed macOS Automation Mode. This machine asks for authentication every
time Automation Mode is enabled, so a run put up a panel and failed after sixty
seconds when nobody answered it:

```
Failed to initialize for UI testing: … "Timed out while enabling automation mode."
```

A test nobody can run is worse than no test, so the behaviour they covered moved
to `threatmodellerTests/ViewRenderTests.swift`, which draws each view with
`ImageRenderer` and needs no automation, and to the session tests beside it,
which state what each control does.

The target is kept, and empty, so the project file stays whole. Nothing builds
it: the shared scheme names only `threatmodellerTests` in its test action.

`docs/TESTING.md` says what to do if Automation Mode is ever wanted again.
