# Focus on one component

**Status:** decided, 16 September 2026.

## The problem

A person reading one component wants the picture around it and nothing else.
The canvas draws the whole model, and the tag filter (#127, #128) needs a tag
written on the model first. A person who has not tagged anything has no way
to narrow the canvas to one component.

## The decision

### What Focus is

Focus is view state on `CanvasState`, held as `focusedComponentId: String?`.
It writes no file and changes no score, the same rule the tag filter states.

Focus draws one component, and every component the walk reaches from it
within `tagFilter.neighbourDepth` flows, either direction, and the flows
between the drawn components. Focus reuses `TagFilter.walk`, the same walk
the tag filter's neighbours stepper (#128) uses, so the two features widen a
selection by the same rule.

### Focus and the tag filter do not combine

Turning Focus on always clears the tag filter. A person who focuses a
component the tag filter was hiding sees it at once, because there is no
state where a picked tag still hides the one component Focus draws. A person
who focuses a component the tag filter was already showing sees the same
component either way, so clearing the tag filter changes nothing they see.

One state governs what the canvas draws at a time: the tag filter, or Focus,
never both. `CanvasState.focus(componentId:)` clears `tagFilter` before it
sets `focusedComponentId`.

### Clear Filter clears Focus too

The toolbar's Clear Filter button already draws the whole model again for
the tag filter. `CanvasState.clearTagFilter()` also clears
`focusedComponentId`, so the one button undoes whichever of the two narrowed
the canvas.

### Where Focus is offered

Focus is a row in the component context menu (`ElementMenu.component`) and a
button in the component panel (`ComponentPanel`), both calling
`CanvasState.focus(componentId:)`. Neither writes to `ThreatModelSession`.

### Zones

Focus draws no zone. The tag filter draws a zone that holds a picked tag of
its own; Focus has no matching rule for a zone, and the issue asks only for
the component and its neighbours. A zone a focused component sits inside
still draws its components at their usual positions; the zone's own
rectangle does not.
