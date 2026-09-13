# Threat actors as first-class elements — design

Date: 2026-09-13
Status: approved for planning

## 1. Why

The model scores a threat by how bad it is and by how often an attack of that
kind happens. The second number, the likelihood, comes from one of two places:
the catalogue states a tier on the threat, or a person writes one `likelihood`
finding in the `.controls` file, one threat at a time.

Neither place holds the reason a team actually gives. A team says "we face
organised crime and a disgruntled operator, and we do not face a nation state".
That sentence sets the likelihood of every threat at once, and the model has
nowhere to write it down.

`2026-09-13-report-professional-structure-design.md` section 11 names this as
work the report needs and the model cannot supply: "Threat actors as
first-class elements, with capability, intent and access, and threats tied to
them."

The application already holds `Resources/Actors/actors.json`. That file is a
different thing with the same word in its name: it lists external entities a
person drags onto a diagram, such as `actor-user` and `actor-browser`. It
states no capability and performs no threat. This design does not change it,
and section 3.5 states how the two names stay apart.

## 2. Scope

**In scope.** A `threat_actor` block in the library language; a `faces` list
and a local `threat_actor` block in the architecture language; a rule that
turns the faced actors into one likelihood per threat; a built-in
`commodity-crimeware` actor; a report section; two read-only lines on the
threat card.

**Out of scope.** The MITRE ATT&CK import, which is
`2026-09-13-mitre-attack-import-design.md` and reads this design's block as
its output format.

**Out of scope.** An actor's reach: where the actor starts, what privilege it
holds, and which elements it can touch. A later design may add it. This design
changes no zone multiplier and no threat applicability.

**Out of scope.** `threatmodeller check`. An unprofiled model is not a failing
model.

**Out of scope.** Any editor in the application. Actors are authored in files.

## 3. The language

### 3.1 `threat_actor` in a `.lib` file

```hcl
library "acme" {
  threat_actor "insider" {
    name        = "Disgruntled operator"
    description = "A person with production access who has resigned."
    aliases     = ["leaver"]
    capability  = "commodity"
    intent      = "sabotage"
    performs    = ["data-exfiltration", "credential-theft"]
    techniques  = ["T1078", "T1530"]
  }
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `name` | string | any | **required** |
| `description` | string | any | empty |
| `aliases` | list of strings | any | empty |
| `capability` | string | `commodity`, `targeted`, `research` | `targeted` |
| `intent` | string | any | empty |
| `performs` | list of strings | threat ids | empty |
| `techniques` | list of strings | MITRE technique ids | empty |
| `performs_catalogue_tier` | string | `commodity`, `targeted`, `research` | none |

`capability` reuses the three tier words the likelihood already holds, and it
carries the same factor: `commodity` 1.0, `targeted` 0.6, `research` 0.25. A
capability is a statement about how many attackers of this kind there are, not
about how skilled one of them is.

`performs_catalogue_tier` names a tier rather than a threat. An actor that
states it performs every threat the catalogue marks at that tier. Section 3.4
uses it for one built-in actor, and a person may use it for their own.

### 3.2 `faces` and a local `threat_actor` in a `.arch` file

```hcl
system "Payments" {
  faces = ["commodity-crimeware", "acme-insider"]

  threat_actor "contractor" {
    name       = "Third-party contractor"
    capability = "targeted"
    intent     = "financial"
    performs   = ["supply-chain-compromise"]
  }
}
```

| Entry | Type | Meaning |
| --- | --- | --- |
| `faces` | list of strings | the actor ids this system faces |
| `threat_actor` | block | an actor declared in this file, the way `technology` is |

A system states `faces` once. A second `faces` keeps the last value, which is
the rule section 3 of `LANGUAGE.md` already gives for a repeated attribute.

A local `threat_actor` block takes the same attributes as the library block.
Its id is the label, with no provider prefix, so `faces = ["contractor"]`
names it.

A local block whose label matches a library actor id overrides that actor for
this system. The override is whole: the local block's attributes are the
actor, and the library's are not merged in. This is how a person changes one
imported group's `capability` without editing a vendored file.

### 3.3 Identity

A library's actor id is minted `<library label>-<block label>`, which is the
rule the library language already applies to a technology id and a threat id.
So `threat_actor "insider"` in `library "acme"` is `acme-insider`.

An actor declared in a `.arch` file takes its label unchanged.

### 3.4 The built-in actor

The application holds one actor of its own, in the same place it holds the
vendored catalogue:

```hcl
threat_actor "commodity-crimeware" {
  name                    = "Commodity crimeware"
  description             = "Malware families and untargeted campaigns running today."
  capability              = "commodity"
  intent                  = "opportunistic"
  performs_catalogue_tier = "commodity"
}
```

A system that lists `commodity-crimeware` in `faces` keeps every score it has
today, because every threat the catalogue marks `commodity` keeps the factor
1.0. A system that leaves it out says the untargeted attacker is not in its
model.

### 3.5 The word "actor"

Two things in this application carry the word. They never mix:

| Name in code | File | What it is | Who names it |
| --- | --- | --- | --- |
| `ExternalActor` | `Resources/Actors/actors.json` | a box on the diagram, such as a browser | a component's `technology` |
| `ThreatActor` | a `.lib` or `.arch` file | an adversary with a capability | a system's `faces` |

The palette word stays "External Actors". The report word is "Threat actors".
`ActorsJSON.swift` and `Resources/Actors/actors.json` keep the names they have,
because renaming them changes a shipped resource and answers no question this
design asks. Every type this design adds carries the word `ThreatActor` in
full.

### 3.6 What the parsers refuse

Errors, which stop the project opening:

| Check | Message |
| --- | --- |
| a `threat_actor` block with no `name` | `the threat actor "<id>" has no name` |
| a `capability` outside the three tiers | `capability is "<word>"; this application holds "commodity", "targeted", "research"` |
| a `performs_catalogue_tier` outside the three tiers | `performs_catalogue_tier is "<word>"; this application holds "commodity", "targeted", "research"` |
| a duplicate actor id in one library | `the threat actor "<id>" is declared twice` |
| a `faces` entry naming no actor | `this project holds no threat actor called "<id>"` |

Warnings, which do not:

| Check | Message |
| --- | --- |
| a faced actor that performs no threat this model raises | `the threat actor "<id>" performs no threat this model raises` |
| a `performs` entry naming a threat no catalogue holds | `the threat actor "<id>" performs "<threat id>", which no catalogue holds` |

A `techniques` entry that matches no threat is neither an error nor a warning.
ATT&CK holds 697 live techniques and the vendored catalogue names 33, so an
unmatched technique is the normal case, not a fault.

## 4. The domain

### 4.1 `ThreatActor`

`catalogue/domain/ThreatActor.swift`:

```swift
public struct ThreatActor: Equatable, Sendable {
    public let id: ThreatActorId
    public let name: String
    public let description: String
    public let aliases: [String]
    /// The tier, which carries the factor the score uses.
    public let capability: Likelihood
    public let intent: String
    public let performs: [ThreatId]
    /// MITRE technique ids, matched at parent level.
    public let techniques: [String]
    /// When set, this actor performs every threat the catalogue marks at
    /// this tier.
    public let performsCatalogueTier: Likelihood?
}
```

`ThreatActorId` joins the five identifier types in
`catalogue/domain/Identifiers.swift`.

### 4.2 `ActorLikelihood`

`assessment/domain/ActorLikelihood.swift` is a pure function of its inputs. It
reads no gateway and holds no state.

```swift
public enum ActorLikelihood {
    public static func performers(of threat: Threat, among actors: [ThreatActor]) -> [ThreatActor]
    public static func likelihood(of threat: Threat, faced actors: [ThreatActor]) -> LikelihoodSource
}
```

An actor performs a threat when any one of three tests passes:

1. `performs` holds the threat's id.
2. `techniques` holds a technique id whose parent matches the parent of one of
   the threat's `mitreTechniques`. A parent is the text before the first full
   stop, so `T1550.001` and `T1550` share the parent `T1550`.
3. `performsCatalogueTier` equals the threat's catalogue likelihood.

The likelihood is the highest `factor` among the performers. A threat with no
performer keeps the catalogue's own likelihood.

| Faced actors | Threat's catalogue tier | Performers | Result |
| --- | --- | --- | --- |
| crimeware, FIN7 | commodity | both | commodity, 1.0 |
| FIN7 | commodity | FIN7 | targeted, 0.6 |
| FIN7 | research | FIN7 | targeted, 0.6 |
| FIN7 | commodity | none | commodity, 1.0 |
| none | commodity | none | commodity, 1.0 |

Row four is the rule that keeps this design safe: a short or wrong actor list
never lowers a score by leaving a threat out.

### 4.3 `LikelihoodSource`

A reader who sees a score fall has to see why. `assessment/domain/
LikelihoodSource.swift` carries the tier and the reason together:

```swift
public enum LikelihoodSource: Equatable, Sendable {
    case catalogue(Likelihood)
    case actor(Likelihood, actorId: ThreatActorId, actorName: String)
    case finding(LikelihoodFinding)
}
```

`AssessThreatModel` applies them in one order, strongest claim first:

1. a `likelihood` finding in the `.controls` file;
2. the actor-derived likelihood, when the system faces an actor that performs
   the threat;
3. the catalogue's own tier.

A person who disagrees with what the actors say writes a finding, which is the
mechanism the `.controls` file already holds.

### 4.4 The catalogue gateway

`TechnologyCatalogue` gains two methods:

```swift
func threatActors() -> [ThreatActor]
func findActor(_ id: ThreatActorId) -> ThreatActor?
```

Every conformer implements them: `BundledTechnologyCatalogue`,
`MergedCatalogue`, `InMemoryTechnologyCatalogue`, and the contract test in
`TechnologyCatalogueContract.swift`. The bundled one returns the single
built-in actor of section 3.4 plus, once
`2026-09-13-mitre-attack-import-design.md` is done, the imported groups.

### 4.5 The model

`ThreatModel` gains two values:

| Value | Type | Meaning |
| --- | --- | --- |
| `facedActorIds` | `[String]` | what the `.arch` file's `faces` states, in file order |
| `localActors` | `[ThreatActor]` | the actors the `.arch` file declares |

`AssessThreatModel` resolves the faced ids against the local actors first and
the catalogue second, which is the rule the library language already applies
to a threat id inside a library.

## 5. The report

### 5.1 The new section

`## Threat actors` sits after `## Assumptions` and before the threat register.
A model that faces no actor writes no section.

```markdown
## Threat actors

This assessment is written against these adversaries. A threat no actor here
performs keeps the catalogue's own likelihood.

| Actor | Capability | Intent | Threats performed |
| --- | --- | --- | --- |
| Commodity crimeware | Commodity | Opportunistic | 31 |
| FIN7 (G0046) | Targeted | Financial | 22 |
| Disgruntled operator | Commodity | Sabotage | 4 |
```

### 5.2 The threat stanza

`MarkdownThreatStanza` gains one line under the existing MITRE line, and
changes the likelihood line to name its source:

```markdown
- MITRE ATT&CK: T1552, T1078
- Performed by: Commodity crimeware, FIN7
- Likelihood: Targeted, set by FIN7
```

A threat whose likelihood comes from the catalogue writes
`- Likelihood: Commodity, from the catalogue`. A threat answered by a
`likelihood` finding keeps the wording that section already writes.

## 6. The application

`ThreatCard` shows the two lines of section 5.2, read-only, under the threat's
existing MITRE line. Nothing on screen writes an actor. A person who wants a
different actor set edits the `.arch` file, and the application reloads it the
way it reloads every other change to that file.

## 7. What this design does not do

- It does not change how a score is computed. It changes which likelihood goes
  into the arithmetic that is there.
- It does not fail a build. `threatmodeller check` reads no actor.
- It does not model where an actor starts or what it can reach.
- It does not let one actor raise a threat two tiers, or hold a prior between
  the tiers. An actor states one of the three tiers.

## 8. Testing

| Test | Says |
| --- | --- |
| `ActorLikelihoodTests` | the five rows of the table in section 4.2, each as one test |
| | a profile's `T1550.001` performs a threat that names `T1550` |
| | a threat that names `T1550.001` is performed by a profile that names `T1550` |
| | `performs_catalogue_tier` performs every threat at that tier and no other |
| `ThreatActorLanguageTests` | the library block parses, round-trips through the writer, and mints `acme-insider` |
| | the `.arch` `faces` list and local block parse and round-trip |
| | a local block overrides a library actor whole |
| | each row of the two diagnostics tables in section 3.6 |
| `AssessThreatModelTests` | the three-step precedence of section 4.3 |
| | a model that faces no actor scores exactly what it scores today |
| `MarkdownThreatActorsTests` | the section of 5.1, and no section when a model faces nobody |
| `MarkdownThreatStanzaTests` | the three likelihood wordings of section 5.2 |
| `TechnologyCatalogueContract` | every conformer returns the built-in actor and finds it by id |

The regression test that matters is the second `AssessThreatModelTests` row.
Every sample model in `Resources/Samples/` faces no actor, so every score in
every existing test stays where it is.

## 9. Where the code goes

| File | Change |
| --- | --- |
| `catalogue/domain/ThreatActor.swift` | new |
| `catalogue/domain/Identifiers.swift` | `ThreatActorId` |
| `catalogue/domain/MergedCatalogue.swift` | merges actors across providers |
| `catalogue/gateway/TechnologyCatalogue.swift` | two methods |
| `assessment/domain/ActorLikelihood.swift` | new |
| `assessment/domain/LikelihoodSource.swift` | new |
| `assessment/usecase/AssessThreatModel.swift` | applies the precedence; carries performers onto the assessed threat |
| `modelling/domain/ThreatModel.swift` | `facedActorIds`, `localActors` |
| `architecture/domain/ArchitectureSource.swift` | `faces`, `threat_actor` |
| `architecture/domain/LibrarySource.swift` | `threat_actor` |
| `ArchitectureDSL/ArchitectureParser.swift` | reads both |
| `ArchitectureDSL/ArchitectureWriter.swift` | writes both |
| `ArchitectureDSL/LibraryParser.swift` | reads the block |
| `ArchitectureDSL/LibraryWriter.swift` | writes the block |
| `CatalogueGateways/BundledTechnologyCatalogue.swift` | serves the built-in actor |
| `CatalogueGateways/Resources/Actors/threat-actors.json` | new, holds `commodity-crimeware` |
| `reporting/domain/Report.swift` | the actor section and the stanza fields |
| `reporting/usecase/BuildThreatModelReport.swift` | fills them |
| `reporting/usecase/MarkdownThreatActors.swift` | new |
| `reporting/usecase/MarkdownThreatStanza.swift` | two lines |
| `reporting/usecase/ExportModelAsMarkdown.swift` | places the section |
| `threatmodeller/sidebar/ThreatCard.swift` | two lines |
| `docs/LANGUAGE.md` | the keyword lists, section 4 and section 6 |

## 10. The risk in this design

A team writes a short actor list, reads a lower set of scores, and believes the
list is complete. Two things hold that back, and the spec keeps both.

The first is row four of section 4.2: a threat no faced actor performs keeps
its catalogue likelihood. Leaving an actor out never lowers a score.

The second is the report wording of section 5.1, which states in the section
itself that an unperformed threat keeps the catalogue's number. A reader of
the report sees the rule beside the table it applies to.
