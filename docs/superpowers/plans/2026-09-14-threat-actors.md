# Threat actors as first-class elements — implementation plan

Date: 2026-09-14
Spec: `docs/superpowers/specs/2026-09-13-threat-actors-design.md`
Status: delivered

## Order of work

1. **The domain.** `ThreatActorId` in `catalogue/domain/Identifiers.swift`;
   `catalogue/domain/ThreatActor.swift`; `assessment/domain/LikelihoodSource.swift`;
   `assessment/domain/ActorLikelihood.swift`. `ActorLikelihood` is a pure
   function of its inputs, so it is written and tested before any gateway.
2. **The catalogue gateway.** `threatActors()` and `findActor(_:)` on
   `TechnologyCatalogue`, then on `BundledTechnologyCatalogue`,
   `MergedCatalogue` and `InMemoryTechnologyCatalogue`.
   `Resources/Actors/threat-actors.json` holds `commodity-crimeware`; it sits
   outside `Library/`, because `scripts/update-catalogue.sh` rewrites that
   directory and this file is the application's own.
3. **The model.** `facedActorIds` and `localActors` on `ThreatModel`, and
   `modelling/domain/ThreatActorLookup.swift`, which resolves a faced id
   against the model first and the catalogue second.
4. **The languages.** `SourceThreatActor` in
   `architecture/domain/LibrarySource.swift`; `faces` and `threatActors` on
   `ArchitectureSource`; `parseThreatActor()` in both parsers; the block in
   both writers. `Library.build` mints `<label>-<id>`. `ImportArchitecture`
   carries `faces` and the local blocks onto the model, refuses a faced id
   nothing holds, and warns about an actor that performs nothing.
5. **The score.** `ThreatResolver` resolves the faced actors once and applies
   the precedence: a `likelihood` finding, then the actors, then the
   catalogue's own tier. `ResolvedThreat` carries `likelihoodSource` and
   `performedBy`; `AssessedThreat` carries `likelihoodReason` and
   `performedByLabels`.
6. **The report.** `ReportThreatActor`; `MarkdownThreatActors`; two lines in
   `MarkdownThreatStanza`; the section placed after `## Assumptions` and
   before the glossary and the threat register in `ExportModelAsMarkdown`.
7. **The application.** Two read-only lines on `ThreatCard`.
8. **The documentation.** `docs/LANGUAGE.md`: the keyword lists, the
   architecture grammar and attribute table, the library block, the identity
   rule and both diagnostics tables.

## The regression that matters

A model that faces nobody must score exactly what it scored before. Every
bundled sample faces nobody, so the whole existing suite is that test;
`FacingThreatActorsTests.scoresAModelThatFacesNobodyTheWayItAlwaysDid` states
it directly.

## What this plan leaves out

An actor's reach, any editor in the application, and `threatmodeller check`,
which reads no actor. The MITRE ATT&CK import is
`2026-09-13-mitre-attack-import-design.md` and writes this design's block.
