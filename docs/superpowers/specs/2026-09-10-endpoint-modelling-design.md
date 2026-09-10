# Host and endpoint modelling: design

Date: 2026-09-10. Status: approved in conversation, ready for an implementation
plan.

## 1. What this fixes

A user modelled a macOS endpoint and a security product that protects it. The
model came out wrong in ways the application caused, not ways the user chose.

| # | Fault | Evidence from that model |
| --- | --- | --- |
| 1 | An implemented control never lowers a score | "Unauthorized Access — Developer Secrets" stays critical at 12 with 3 of 5 controls implemented |
| 2 | Every flow is treated as a network link with TLS | 110 of 268 controls answered `not_applicable`, 41% of the file |
| 3 | A zone is a network boundary only | A `uid 501` to `uid 0` boundary had to be written as `network = "management"` |
| 4 | A component cannot mitigate a threat on another component | The product that answers about 20 threats appears only as repeated compensating prose |
| 5 | A component cannot state the privilege it runs at | One tool had to be drawn twice, as `devtools` and `rootdevtools`, in two zones |
| 6 | The catalogue is cloud-shaped | "Deploy load balancers with DDoS protection" was raised against a keychain call |
| 7 | A recommendation has nowhere to live | Three hardening outcomes were hidden inside `accepted` notes |
| 8 | The report scores threats one at a time | No attack path from the source actor to the restricted component appears |

Fault 1 also creates a perverse incentive: to make the number honest, a user
restates an implemented control as compensating prose.

## 2. The decisions this design fixes

1. **An implemented control lowers the score, by coverage.** The reduction is
   `implemented / applicable`, capped at 70%. It needs no new authoring: the
   answers a user has already typed start counting at the next compile.

2. **`accepted` never lowers a score.** An accepted risk stays in the
   denominator. `not_applicable` leaves the denominator, because a control
   that does not apply is not work anybody skipped.

3. **A flow states its kind.** `network`, `ipc`, `file`, `syscall` or `human`.
   A flow that states no kind is a network flow, so every existing `.arch`
   file keeps its meaning.

4. **A threat states the flow kinds it applies to.** A threat that states none
   applies to network flows only. That one default removes the TLS-shaped
   threats from every local flow, and the vendored catalogue needs no change.

5. **A zone states its boundary.** `network` or `privilege`. A privilege zone
   raises the privilege threat set, and a network zone raises the network
   threat set. Neither raises the other's.

6. **A component states the privilege it runs at.** `runs_as` takes a level
   from a fixed ladder. A threat may name the levels it applies to, and a flow
   whose ends run at different levels crosses a privilege boundary. Both make
   the duplicated component unnecessary.

7. **A component may mitigate a named threat on another component.** The
   `mitigates` statement carries the threat ids and the reduction. Two edges
   on one threat give the stronger, never the sum, which is the rule the
   pathway mitigations and the compensating controls already follow.

8. **The tamper surface is derived and reported, never scored.** The report
   states which reductions rest on which protector, and what is unanswered on
   that protector. Scaling a reduction by the protector's own residual score
   would invent arithmetic nobody can defend in a review.

9. **A library may define a pathway threat and a pathway mitigation.** The
   limit stated in `LANGUAGE.md` section 6.3 is lifted. Without it a library
   cannot describe an endpoint, where nearly every threat is a pathway.

10. **The endpoint content ships as a library, not as a catalogue change.**
    The vendored catalogue is a third-party repository, pinned by tag and
    checksum. `scripts/update-catalogue.sh verify` must keep passing.

11. **A recommendation is data on a threat.** It is not a note on an accepted
    control. The report gives it its own section.

12. **The report shows attack paths.** A walk of the connection graph from an
    entry component to a sensitive component, with the residual score of each
    hop.

13. **Rationale is carried by `description`, not by a comment.** The writer
    drops comments and this design does not change that. `description` on a
    flow and on a zone is data the model keeps, so a rewrite keeps it.

14. **A report diff between two runs is out of scope.** A diff needs a stored
    baseline artefact, which is its own design.

## 3. The scoring pipeline

Today `ThreatResolver` scores in this order: severity rank times sensitivity
rank, then the zone multiplier, then the pathway mitigation, then the
compensating control. This design adds two stages.

```
base      = severity.rank * sensitivity.rank            # 1 to 16
zoned     = round(base * zoneMultiplier)
covered   = max(1, round(zoned * (1 - coverage * 0.70)))    # NEW, section 3.1
pathway   = the strongest upstream pathway mitigation
mitigated = the strongest mitigates edge                    # NEW, section 6
residual  = the strongest compensating control
```

The thresholds in `RiskScore.level` do not change: 12 and above is critical, 8
is high, 4 is medium.

### 3.1 Control coverage

```
applicable  = the controls whose status is not not_applicable
implemented = the applicable controls whose status is implemented
coverage    = applicable.isEmpty ? 0 : implemented / applicable
covered     = max(1, round(zoned * (1 - coverage * ControlCoverage.maxReduction)))
```

`ControlCoverage.maxReduction` is `0.70`, held in one place in the domain. The
cap stops a threat reaching zero from answered checkboxes alone, and the floor
of 1 stops a threat leaving the report.

The worked example from the model that started this design: a threat with a
zoned score of 12 and 3 of 5 controls implemented scores
`round(12 * (1 - 0.6 * 0.70))` = 7, which is high, not critical.

### 3.2 What the report shows

`ResolvedThreat` gains `scoreBeforeControls`. `ReportThreat` gains
`inherentScore`, which is the score before the coverage stage. Every report
shows both, so a reader sees what the controls bought.

The `score` attribute the `.controls` writer restates stays the residual score.
`LANGUAGE.md` section 5.3 already warns that the application recomputes it.

## 4. Flow kinds

### 4.1 The language

`flow` becomes a block with an optional body. The statement form stays legal,
so no existing file changes.

```hcl
flow api -> ledger                       # legal, kind = "network"

flow opfilter -> secret_store {
  kind        = "ipc"
  description = "XPC call, entitlement-gated"
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `kind` | string | `network`, `ipc`, `file`, `syscall`, `human` | `network` |
| `description` | string | any | none |

A `kind` outside the vocabulary is an error that names the field, the value and
the five values the application holds.

### 4.2 The domain

`FlowKind` is an application-owned enum, as `DataSensitivity` and `NetworkZone`
are. `Connection` gains `kind: FlowKind` and `description: String?`.

### 4.3 Threat selection

A `Threat` gains `appliesToFlowKinds: [FlowKind]`. `ThreatResolver` raises a
connection threat on a flow when:

- the threat's `appliesToFlowKinds` holds that flow's kind, or
- the threat's `appliesToFlowKinds` is empty and the flow's kind is `network`.

The second rule is what keeps the vendored catalogue correct without editing
it. Its 5 connection threats state no kinds, so they apply to network flows
only.

## 5. Zone boundaries and privilege levels

### 5.1 Zone boundary

```hcl
zone "root" {
  boundary = "privilege"
  kind     = "private"
  name     = "uid 0"
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `boundary` | string | `network`, `privilege` | `network` |

`ZoneBoundary` is an application-owned enum. `Zone` gains
`boundary: ZoneBoundary` and `description: String?`.

A `Threat` gains `boundary: ZoneBoundary?`, which serves a zone threat and a
connection threat alike. A private zone raises a zone threat when:

- the threat's `boundary` equals the zone's boundary, or
- the threat's `boundary` is nil and the zone's boundary is `network`.

The risk reduction rules do not change. A privilege zone reduces risk through
`reduces_risk` and `reduces_risk_by`, the same way a network zone does.

### 5.2 Component privilege

```hcl
component "devtools" {
  technology = "endpoint-launchd"
  runs_as    = "root"
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `runs_as` | string | `user`, `admin`, `root`, `system`, `kernel` | `user` |

`PrivilegeLevel` is an application-owned enum with a rank, so two levels
compare. `Component` gains `runsAs: PrivilegeLevel`.

A `Threat` gains `appliesToPrivilegeLevels: [PrivilegeLevel]`. A component
threat is raised when the list is empty, or when it holds the component's
level. One `devtools` component now replaces the `devtools` and `rootdevtools`
pair.

### 5.3 A derived privilege crossing

A flow whose two ends have different `runs_as` levels raises the privilege
threat set as well as the threat set of its own kind. The privilege threat set
is every connection threat whose `boundary` is `privilege`.

So a privilege crossing needs no zone and no second component. A user draws the
flow, states the two levels, and the crossing appears.

## 6. `mitigates` edges

### 6.1 The language

A statement at the top level of the `system` block, shaped like `flow`:

```hcl
mitigates opfilter -> secret_store {
  threats         = ["credential-theft", "endpoint-raw-device-read"]
  reduces_risk_by = 80
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `threats` | list of strings | threat ids | **required** |
| `reduces_risk_by` | number | 0 to 100 | **required** |

Both ends are bare identifiers and both must name a declared component. An
empty `threats` list is the error
`the mitigates edge "<id>" names no threats`. A `reduces_risk_by` outside 0 to
100 is the error `reduces_risk_by is <n>; it runs from 0 to 100`.

The edge's identifier is `<source>-><target>`, minted the way a flow's is.

### 6.2 The scoring

`ThreatResolver` applies a `mitigates` edge to a threat when the edge names the
threat id and the threat's source is the edge's target component. The stage
sits after the pathway mitigation and before the compensating control. Two
edges that both name one threat give the stronger reduction, not the sum.

`ResolvedThreat` gains `mitigatedByComponents: [ComponentMitigation]` so a
report can name what bought the reduction.
`ComponentMitigation` holds the protector's id, the protector's display name
and the reduction percentage.

### 6.3 The derived tamper surface

For each `mitigates` edge the report states:

- the protector, the target, the threats the edge answers and the reduction
- every threat raised on the protector, with its residual score and whether it
  is answered

`AssessThreatModel` raises the warning
`<n> risk reductions depend on "<protector>", which has <m> unanswered threats`
when a protector carries an unanswered threat whose residual level is high or
critical.

## 7. The library language

### 7.1 New attributes

```hcl
threat "dylib-injection" {
  name        = "Dynamic library injection"
  severity    = "high"
  applies_to  = ["file", "ipc"]
  runs_as     = ["user", "admin", "root"]
  pathway     = true
}

threat "privilege-escalation" {
  name     = "Privilege escalation"
  severity = "critical"
  zone     = true
  boundary = "privilege"
}

mitigation "endpoint-security-client" {
  name            = "Endpoint Security client"
  mitigates       = ["dylib-injection", "unsigned-code-load"]
  provided_by     = ["endpoint-es-client"]
  reduces_risk_by = 60
}
```

| Block | Attribute | Type | Values | Default |
| --- | --- | --- | --- | --- |
| `threat` | `applies_to` | list of strings | flow kinds | empty |
| | `boundary` | string | `network`, `privilege` | none |
| | `runs_as` | list of strings | privilege levels | empty |
| | `pathway` | boolean | `true`, `false` | `false` |
| `mitigation` | `name` | string | any | **required** |
| | `mitigates` | list of strings | threat ids | **required** |
| | `provided_by` | list of strings | technology ids | **required** |
| | `reduces_risk_by` | number | 0 to 100 | **required** |

`applies_to` only means something on a threat whose `connection` is `true`.
`boundary` means something on a threat whose `zone` is `true`, and also on a
connection threat: `boundary = "privilege"` there raises the threat only where
the flow crosses a privilege level, and the code reads `boundary` before
`applies_to`, so `applies_to` has no effect on that threat.

A `mitigation` block becomes a `PathwayMitigationDefinition`, the value the
vendored `mitigations/pathway-mitigations.json` already produces. Its id and
the ids in `provided_by` take the library's label as a prefix, the rule
`Library.build` already follows.

`LANGUAGE.md` section 6.3 states that a library cannot define a pathway threat
or a pathway mitigation. This design deletes that sentence.

### 7.2 The endpoint library

A new file `libraries/endpoint.lib`, label `endpoint`. It is a file a person
copies into a project's `library` directory. It is not vendored and it is not
in the lock file, because it is this repository's own content.

Technologies: system extension, Endpoint Security client, keychain, MDM
channel, TCC, Gatekeeper, launchd, kernel extension, XPC service, unix socket.

Threats: raw-device read, dylib injection, persistence, TCC bypass, profile
injection, privilege escalation, sandbox escape, boundary bypass, keychain item
theft, unsigned code load.

Every threat states its kinds, its boundary and its levels, so the library
proves the three new vocabularies work end to end.

## 8. Recommendations

### 8.1 The language

```hcl
threat "endpoint-profile-injection" on component "managed-prefs" {
  recommendation "Protect the managed preferences plist with an ES rule" {
    note = "Deny write from anything but the MDM daemon."
  }
}
```

| Block | Label | Attribute | Type | Default |
| --- | --- | --- | --- | --- |
| `recommendation` | what to do | `note` | string | none |

A threat may hold more than one. The compile keeps a recommendation whole, the
way it keeps a compensating control, and a recommendation on a threat the
architecture no longer raises moves into the `stale` block with the rest of the
answer.

A recommendation is not an answer. `threatmodeller check` still exits 1 when a
threat holds no answered control and no compensating control.

### 8.2 The report

A "Recommendations" section, grouped by the source that raised the threat and
ordered by the threat's residual score, worst first. Each line names the
threat, the residual score and the recommendation, and prints the note under
it.

## 9. Attack paths

`UpstreamGraph` already holds the connection graph. A new
`AttackPaths` domain type walks it.

- **A start.** A component with no inbound flow, or a component in a public
  zone.
- **An end.** A component whose sensitivity is `confidential` or `restricted`.
- **A path.** The flows from a start to an end, at most 6 hops. A cycle stops
  the walk.
- **A path's score.** The highest residual score among the threats raised on
  the components and the flows along it.
- **What the report shows.** The top 20 paths by score. Each hop names the
  component, the flow kind and the worst residual threat on it, and states
  where a `mitigates` edge or a pathway mitigation reduced it.

WARNING: the walk is bounded. When the walk drops a path, the report states
`<n> further paths are not listed`, because a silent truncation reads as full
coverage.

## 10. Report rollups

| Section | What it holds |
| --- | --- |
| Per zone | the zone, its component count, its threat count by level and its worst residual |
| Top residual | the 20 worst threats, with the inherent score, the residual score and what reduced it |
| By source kind | the counts for components, flows and zones, so a reader sees where the risk sits |

## 11. Data assets

```hcl
component "secret-store" {
  technology = "endpoint-keychain"
  asset "ssh-keys"        { data = "restricted" }
  asset "browser-cookies" { data = "confidential" }
}
```

| Block | Label | Attribute | Values | Default |
| --- | --- | --- | --- | --- |
| `asset` | the asset name | `data` | `public`, `internal`, `confidential`, `restricted` | `internal` |

A component that declares assets scores at the highest sensitivity among its
`data` attribute and every asset's `data`. A component that declares no asset
behaves exactly as it does today.

The report gains an assets column on the component table. Per-asset threat
scoring is **out of scope**: one asset list per component is what removes the
"secret-store is one blob" fault, and a full per-asset resolution is a
different design.

## 12. What does not change

- The vendored catalogue files and their checksums.
- The `.controls` threat key, `<threat id>@<kind>:<identifier>`. A flow keeps
  the key `…@connection:<source>-><target>` whatever its kind.
- `RiskScore.level` thresholds.
- The rule that a rewrite drops comments.
- The layout rule: the source holds no coordinates.

## 13. Delivery

Seventeen agents in five waves on one branch. Agents inside a wave own
disjoint files. A wave that needs new types starts with one contract task that
adds the types, the fields and the call sites and changes no behaviour, so the
consumer tasks of that wave never wait on each other.

| Wave | Agents | What each owns |
| --- | --- | --- |
| 1 | 1, 2, 3 | the coverage stage in the assessment domain; the two scores in the report tree and the three renderers; the language reference |
| 2 | 4, 5, 6, 7 | the vocabularies, the model fields and the resolver hooks; the architecture language; the library language; the controls language and the reference |
| 3 | 8, 9, 10, 11, 12 | threat applicability; the `mitigates` scoring and the derived tamper surface; the document format; the window's three pickers; `libraries/endpoint.lib` |
| 4 | 13, 14, 15, 16 | the four report sections in the report tree; recommendations and protection dependencies; attack paths; the rollups |
| 5 | 17 | one acceptance test of an endpoint model, from source to report |

Each packet states the files it owns, the contract it must not change, the
failing test it writes first, and the command that proves it. The plan is
`docs/superpowers/plans/2026-09-10-host-and-endpoint-modelling.md`.

## 14. What this design leaves out

| Left out | Why |
| --- | --- |
| A report diff between two runs | It needs a stored baseline artefact, which is its own design. |
| Per-asset threat resolution | One asset list per component removes the "one blob" fault. Resolving a threat per asset is a different design. |
| Editing an asset in the window | An asset is written in the `.arch` file and read by the report. |
| The four new sections in the PDF | The PDF gains the inherent score. The new sections are Markdown and report tree. |
| Answer templates and answer reuse | Section 4 removes the reason for most of them: a local flow stops raising the threats a user was answering `not_applicable` dozens of times. |
| Keeping comments through a rewrite | `description` on a flow and on a zone carries the rationale as data the model keeps. |
