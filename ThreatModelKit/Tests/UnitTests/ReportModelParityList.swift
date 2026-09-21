import Foundation
import ThreatModelKit

/// The report parity list itself: what the analysis, the report and the
/// exports do about every attribute every language reads.
///
/// `ReportModelParityTests` walks `LanguageVocabulary` against this list. Read
/// the test file first; this file is the table.
extension ReportModelParityTests {
    /// The rows of one block, keyed the way `LanguageVocabulary.attributeKeys`
    /// keys them.
    static func rows(
        _ language: String,
        _ block: String,
        _ pairs: [(String, Row)]
    ) -> [String: Row] {
        var found: [String: Row] = [:]
        for pair in pairs { found["\(language).\(block).\(pair.0)"] = pair.1 }
        return found
    }

    static func row(
        _ analysis: Reading,
        _ report: Reading,
        _ exports: Set<Export> = []
    ) -> Row {
        Row(analysis: analysis, report: report, exports: exports)
    }

    /// The analysis that reads the value.
    static func analysis(_ place: String) -> Reading { .reads(place) }

    /// The reason no analysis reads the value.
    static func noAnalysis(_ reason: String) -> Reading { .nothingReads(reason) }

    /// The report section that states the value.
    static func section(_ name: String) -> Reading { .reads(name) }

    /// The reason no report section states the value.
    static func noSection(_ reason: String) -> Reading { .nothingReads(reason) }

    /// A word that names a nested block. The block has rows of its own.
    static func nested(_ block: String) -> Row {
        Row(
            analysis: .nothingReads("a nested block; the \(block) rows state what reads it"),
            report: .nothingReads("a nested block; the \(block) rows state what states it"),
            exports: []
        )
    }

    /// A value a person writes as evidence for a reader, which no arithmetic
    /// reads.
    static var evidenceOnly: Reading {
        .nothingReads("evidence a reader checks; no arithmetic reads it")
    }
}

// MARK: the architecture language

extension ReportModelParityTests {
    static let architecture: [String: Row] = {
        var all: [String: Row] = [:]
        for block in [archSystem, archPeople, archFacts, archElements] {
            all.merge(block) { first, _ in first }
        }
        return all
    }()

    static let archSystem: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("arch", "system", [
            ("catalogue", row(
                noAnalysis("the compile writes the tag back; LoadLibraries warns on a library that drifts"),
                section("Document control"),
                [.json]
            )),
            ("owner", row(
                analysis("PolicyRules, for system_requires_owner"),
                section("Document control"),
                [.otm, .threatcl, .json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Document control"),
                [.otm, .threatcl, .json]
            )),
            ("authors", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Document control"),
                [.threatcl, .json]
            )),
            ("links", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Document control"),
                [.threatcl, .json]
            )),
            ("repositories", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Document control"),
                [.threatcl, .json]
            )),
            ("created", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Document control"),
                [.json]
            )),
            ("reviewed", row(
                noAnalysis("no arithmetic reads the date; the report states how old it is"),
                section("Document control, and the executive summary"),
                [.json]
            )),
            ("version", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Document control"),
                [.json]
            )),
            ("attribute", nested("attribute")),
            ("technology", nested("technology")),
            ("zone", nested("zone")),
            ("component", nested("component")),
            ("user", nested("user")),
            ("adversary", nested("adversary")),
            ("flow", nested("flow")),
            ("mitigates", nested("mitigates")),
            ("risk_tolerance", row(
                analysis("CheckControlAnswers"),
                section("Findings, and Methodology"),
                [.json]
            )),
            ("requires_evidence_above", row(
                analysis("CompileControls, and AttackTreeContext"),
                section("Policy"),
                []
            )),
            ("assumption", nested("assumption")),
            ("use_case", nested("use_case")),
            ("exclusion", nested("exclusion")),
            ("asset", nested("asset (in system)")),
            ("third_party", nested("third_party")),
            ("diagram", nested("diagram")),
            ("faces", row(
                analysis("ActorReach, and ThreatResolver"),
                section("Threat actors"),
                [.json]
            )),
            ("threat_actor", nested("threat_actor")),
            ("clearance", nested("clearance"))
        ])) { first, _ in first }
        all.merge(rows("arch", "attribute", [
            ("value", row(
                noAnalysis("a field a team names for itself; no arithmetic reads it"),
                section("Document control"),
                []
            ))
        ])) { first, _ in first }
        return all
    }()

    static let archPeople: [String: Row] = {
        var all: [String: Row] = [:]
        let user: [(String, Row)] = [
            ("name", row(
                analysis("ClearanceCover, which names the users a cover is held by"),
                section("Scope"),
                [.otm, .json]
            )),
            ("role", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Scope"),
                [.json]
            )),
            ("access", row(
                analysis("ThreatResolver, which sets crossesPrivilege"),
                section("Scope"),
                [.otm, .json]
            )),
            ("uses", row(
                analysis("ActorReach"),
                section("Scope"),
                [.json]
            )),
            ("reaches", row(
                analysis("ActorReach"),
                section("Scope"),
                [.json]
            )),
            ("threat_actor", row(
                analysis("ActorReach, and ThreatModel"),
                section("Scope"),
                [.json]
            )),
            ("clearance", row(
                analysis("ClearanceCover"),
                section("Scope, and Methodology"),
                [.otm, .json]
            ))
        ]
        all.merge(rows("arch", "user", user)) { first, _ in first }
        all.merge(rows("arch", "adversary", user)) { first, _ in first }
        all.merge(rows("arch", "use", [
            ("reaches", row(
                analysis("ActorReach"),
                section("Scope, in the clause that names the client"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "clearance", [
            ("name", row(
                analysis("ClearanceCover"),
                section("Scope, and the threat stanza, in Compensated by"),
                [.otm, .json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                noSection("no section states it; the Scope line names the clearance a user holds"),
                []
            )),
            ("reduces_insider_risk_by", row(
                analysis("ClearanceCover"),
                section("the threat stanza, in Compensated by"),
                [.threatcl, .json]
            )),
            ("rationale", row(
                analysis("ClearanceCover, which carries it onto the compensating control"),
                section("the threat stanza, in Compensated by"),
                [.threatcl, .json]
            )),
            ("sources", row(
                evidenceOnly,
                section("the threat stanza, in Compensated by"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "threat_actor", threatActor)) { first, _ in first }
        return all
    }()

    /// A threat actor reads the same way in an `.arch` file and in a library.
    static let threatActor: [(String, Row)] = [
        ("name", row(
            analysis("ActorLikelihood"),
            section("Threat actors"),
            [.json]
        )),
        ("description", row(
            noAnalysis("prose for a reader; no arithmetic reads it"),
            noSection("no section states an actor's description"),
            []
        )),
        ("aliases", row(
            noAnalysis("other names for the same actor; no arithmetic reads them"),
            noSection("no section states an actor's aliases"),
            []
        )),
        ("capability", row(
            analysis("ActorLikelihood, and ThreatResolver"),
            section("Threat actors"),
            [.json]
        )),
        ("intent", row(
            noAnalysis("prose for a reader; no arithmetic reads it"),
            section("Threat actors"),
            [.json]
        )),
        ("performs", row(
            analysis("ActorLikelihood"),
            section("Threat actors, and the threat stanza, in Performed by"),
            [.json]
        )),
        ("techniques", row(
            analysis("ActorLikelihood"),
            noSection("no section states the techniques an actor performs"),
            []
        )),
        ("performs_catalogue_tier", row(
            analysis("ActorLikelihood"),
            noSection("no section states the catalogue tier an actor performs"),
            []
        ))
    ]

    static let archFacts: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("arch", "assumption", [
            ("text", row(
                analysis("ArchitectureParser, which warns on an assumption nothing names"),
                section("Assumptions"),
                [.threatcl, .json]
            )),
            ("owner", row(
                analysis("PolicyRules, for assumptions_require_owner"),
                section("Assumptions"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "diagram", [
            ("kind", row(
                noAnalysis("a picture a team keeps; no arithmetic reads it"),
                section("Diagrams, which names the kind on the fence"),
                [.threatcl, .json]
            )),
            ("text", row(
                noAnalysis("a picture a team keeps; no arithmetic reads it"),
                section("Diagrams"),
                [.threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "third_party", [
            ("name", row(
                analysis("ArchitectureParser, which refuses a party nothing provides"),
                section("Third parties"),
                [.threatcl, .json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Third parties"),
                [.threatcl, .json]
            )),
            ("kind", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Third parties"),
                [.threatcl, .json]
            )),
            ("paying_customer", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Third parties"),
                [.threatcl, .json]
            )),
            ("uptime", row(
                analysis("ArchitectureParser, which warns on a hard dependency no assumption names"),
                section("Third parties, and the executive summary"),
                [.threatcl, .json]
            )),
            ("uptime_notes", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Third parties"),
                [.threatcl, .json]
            )),
            ("owner", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Third parties"),
                [.json]
            )),
            ("link", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Third parties"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "asset (in system)", [
            ("name", row(
                analysis("ImportArchitecture, which binds the asset to what holds it"),
                section("Data inventory"),
                [.threatcl, .json]
            )),
            ("classification", row(
                analysis("ImportArchitecture, and RiskScore"),
                section("Data inventory"),
                [.threatcl, .json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Data inventory"),
                [.threatcl, .json]
            )),
            ("owner", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Data inventory"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "use_case", [
            ("text", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Scope, under Use cases"),
                [.threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "exclusion", [
            ("text", row(
                analysis("ArchitectureParser, which refuses an exclusion with no rationale"),
                section("Scope, under Exclusions"),
                [.threatcl, .json]
            )),
            ("rationale", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Scope, under Exclusions"),
                [.threatcl, .json]
            ))
        ])) { first, _ in first }
        return all
    }()

    static let archElements: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("arch", "technology", technology)) { first, _ in first }
        all.merge(rows("arch", "zone", [
            ("kind", row(
                analysis("ZoneMultiplier, and ThreatResolver"),
                section("Appendix B, in the zone list"),
                [.otm, .json]
            )),
            ("network", row(
                noAnalysis("the kind carries the reduction; the network type is prose"),
                section("Appendix B, in the zone list"),
                [.otm, .json]
            )),
            ("name", row(
                analysis("ThreatResolver, which raises a zone threat on it"),
                section("By zone, and Appendix B"),
                [.otm, .threatcl, .json]
            )),
            ("reduces_risk", row(
                analysis("ZoneMultiplier"),
                section("Appendix B, and Methodology"),
                [.otm, .json]
            )),
            ("reduces_risk_by", row(
                analysis("ZoneMultiplier"),
                section("Appendix B, and Methodology"),
                [.otm, .json]
            )),
            ("component", nested("component")),
            ("boundary", row(
                analysis("ThreatApplicability"),
                section("Appendix B, in the zone list"),
                [.json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Appendix B, in the zone list"),
                []
            )),
            ("source", row(
                noAnalysis("provenance an import writes; no arithmetic reads it"),
                section("Appendix B, in the zone list"),
                []
            )),
            ("tags", row(
                noAnalysis("a word a team files by; the canvas filter reads it"),
                section("Appendix B, in the zone list"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "component", [
            ("technology", row(
                analysis("ThreatResolver, which raises the technology's threats on it"),
                section("Appendix B, in the components table"),
                [.otm, .json]
            )),
            ("name", row(
                analysis("ThreatResolver, which names the element a threat sits on"),
                section("Appendix B, in the components table"),
                [.otm, .threatcl, .json]
            )),
            ("zone", row(
                analysis("ThreatResolver, and ZoneMultiplier"),
                section("By zone, and Appendix B"),
                [.otm, .threatcl, .json]
            )),
            ("data", row(
                analysis("Component, and RiskScore"),
                section("Appendix B, in the components table"),
                [.otm, .json]
            )),
            ("status", row(
                noAnalysis("no arithmetic reads the build state; the table states it"),
                section("Appendix B, in the components table"),
                [.otm, .json]
            )),
            ("version", row(
                noAnalysis("VulnerabilityLikelihood reads the CVEs, not the version"),
                section("Appendix B, and Known vulnerabilities"),
                [.json]
            )),
            ("cves", row(
                analysis("ThreatResolver, and VulnerabilityLikelihood"),
                section("Known vulnerabilities"),
                [.json]
            )),
            ("holds", row(
                analysis("ImportArchitecture, and RiskScore"),
                section("Data inventory"),
                [.threatcl, .json]
            )),
            ("provided_by", row(
                noAnalysis("no arithmetic reads it; the party's own uptime carries the risk"),
                section("Third parties, in the Provides column"),
                [.json]
            )),
            ("source", row(
                noAnalysis("provenance an import writes; no arithmetic reads it"),
                section("Appendix B, in the components table"),
                []
            )),
            ("threats", row(
                analysis("ThreatResolver, which raises nothing on the component"),
                section("Appendix B, which states the component raises no threats"),
                []
            )),
            ("runs_as", row(
                analysis("ThreatApplicability, and ThreatResolver"),
                section("Appendix B, and the executive summary"),
                [.otm, .json]
            )),
            ("shape", row(
                noAnalysis("a drawing choice; no arithmetic reads it"),
                noSection("no section names the shape; the diagrams draw it"),
                [.threatcl]
            )),
            ("tags", row(
                noAnalysis("a word a team files by; the canvas filter reads it"),
                section("Appendix B, in the components table"),
                [.otm]
            )),
            ("asset", nested("asset (in component)"))
        ])) { first, _ in first }
        all.merge(rows("arch", "asset (in component)", [
            ("data", row(
                analysis("Component, and RiskScore"),
                section("Appendix B, and Data inventory"),
                [.threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "flow", [
            ("kind", row(
                analysis("ThreatApplicability, and ThreatResolver"),
                section("Appendix B, and Attack paths"),
                [.otm, .threatcl, .json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Appendix B, in the connection list"),
                [.otm, .json]
            )),
            ("carries", row(
                analysis("ImportArchitecture, which binds the asset to the flow"),
                section("Data inventory, in the Carried by column"),
                [.json]
            )),
            ("tags", row(
                noAnalysis("a word a team files by; the canvas filter reads it"),
                section("Appendix B, in the connection list"),
                [.otm]
            ))
        ])) { first, _ in first }
        all.merge(rows("arch", "mitigates", [
            ("threats", row(
                analysis("ComponentMitigations, and EdgeGuards"),
                section("the threat stanza, in Reduced by, and Protection dependencies"),
                [.json]
            )),
            ("reduces_risk_by", row(
                analysis("ComponentMitigations"),
                section("the threat stanza, in Reduced by"),
                [.json]
            )),
            ("status", row(
                analysis("ThreatResolver, and AssessLeverage"),
                section("Assumptions, under Assumed mitigations"),
                [.json]
            )),
            ("recommendation", nested("recommendation (in mitigates)"))
        ])) { first, _ in first }
        all.merge(rows("arch", "recommendation (in mitigates)", [
            ("text", row(
                analysis("Action, and AssessLeverage"),
                section("What removes the most risk"),
                [.json]
            )),
            ("note", row(
                analysis("Action, which carries it onto the leverage row"),
                section("What removes the most risk"),
                [.json]
            )),
            ("blocked_by", row(
                analysis("ArchitectureParser, which refuses an undeclared blocker"),
                section("What removes the most risk, and the executive summary"),
                [.json]
            )),
            ("sources", row(
                evidenceOnly,
                section("What removes the most risk"),
                [.json]
            ))
        ])) { first, _ in first }
        return all
    }()

    /// A technology reads the same way in an `.arch` file and in a library.
    static let technology: [(String, Row)] = [
        ("name", row(
            analysis("ThreatResolver, which matches the catalogue by it"),
            section("Appendix B, in the components table"),
            [.otm, .json]
        )),
        ("category", row(
            analysis("Component, which picks the shape from it"),
            section("Appendix B, in the components table"),
            [.otm, .json]
        )),
        ("description", row(
            noAnalysis("prose for a reader; no arithmetic reads it"),
            section("Appendix B, under the components table"),
            []
        )),
        ("threats", row(
            analysis("ThreatResolver, which raises each one"),
            section("Findings, and Appendix A, as one stanza per threat"),
            [.otm, .threatcl, .json]
        )),
        ("encrypts", row(
            analysis("ConnectionEncryption, which sets a flag and moves no score"),
            noSection("no section states that a technology encrypts what it carries"),
            []
        )),
        ("control", row(
            analysis("ThreatResolver, and ControlCoverage"),
            section("the threat stanza, under Controls"),
            [.otm, .threatcl, .json]
        ))
    ]
}

// MARK: the controls language and the attack tree language

extension ReportModelParityTests {
    static let controlsAndTrees: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(controlsDocument) { first, _ in first }
        all.merge(controlsThreat) { first, _ in first }
        all.merge(attackTrees) { first, _ in first }
        return all
    }()

    static let controlsDocument: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("controls", "controls for", [
            ("catalogue", row(
                noAnalysis("CompileControls writes the tag back on every compile"),
                noSection("the Document control row states the tag the `.arch` file holds"),
                []
            )),
            ("tolerance", row(
                analysis("CheckControlAnswers"),
                section("Findings, and Methodology"),
                [.json]
            )),
            ("threat", nested("threat")),
            ("tree", nested("tree")),
            ("stale threat", row(
                analysis("CompileControls, which moves an answer whose threat is gone"),
                noSection("no section states a stale answer; the check states the count"),
                []
            )),
            ("stale tree", row(
                analysis("CompileControls, and AttackTreeBinding"),
                section("Attack trees, whose heading states the tree no longer binds"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("controls", "tree", [
            ("goal", row(
                analysis("AttackTreeBinding, and AttackTreeScoring"),
                section("Attack trees"),
                [.json]
            )),
            ("chain", row(
                analysis("AttackTreeScoring, which scales the raise by the open part"),
                section("Attack trees, in the ordered chain"),
                []
            )),
            ("raises_risk_by", row(
                analysis("AttackTreeScoring"),
                section("Attack trees, which states the percentage"),
                [.json]
            )),
            ("score", row(
                noAnalysis("AttackTreeScoring computes it again on every compile"),
                section("Attack trees, in the heading"),
                [.json]
            )),
            ("score_before", row(
                noAnalysis("AttackTreeScoring computes it again on every compile"),
                section("Attack trees, in the heading"),
                [.json]
            )),
            ("closed_by", row(
                analysis("AttackTreeBinding"),
                section("Attack trees, in the heading"),
                [.json]
            )),
            ("sufficient", nested("sufficient")),
            ("step", nested("step"))
        ])) { first, _ in first }
        all.merge(rows("controls", "sufficient", [
            ("state", row(
                analysis("AttackTreeBinding, which closes the whole route"),
                section("Attack trees, under Sufficient controls"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("controls", "step", [
            ("state", row(
                analysis("RouteClosing"),
                section("Attack trees, in the step table"),
                [.json]
            )),
            ("by", row(
                analysis("AttackTreeBinding"),
                section("Attack trees, in the Closed by column"),
                [.json]
            )),
            ("position", row(
                analysis("AttackTreeBinding, which orders the chain by it"),
                section("Attack trees, in the ordered chain"),
                []
            ))
        ])) { first, _ in first }
        return all
    }()

    static let controlsThreat: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("controls", "threat", [
            ("severity", row(
                noAnalysis("ThreatResolver decides the severity again on every compile"),
                section("the threat stanza"),
                [.otm, .threatcl, .json]
            )),
            ("score", row(
                noAnalysis("ThreatResolver computes the score again on every compile"),
                section("the threat stanza, in Risk"),
                [.otm, .threatcl, .json]
            )),
            ("impacts", row(
                analysis("ApplyControlAnswers"),
                section("the threat stanza, in Impact"),
                [.otm, .threatcl, .json]
            )),
            ("likelihood", nested("likelihood")),
            ("severity_override", nested("severity_override")),
            ("control", nested("control")),
            ("compensating", nested("compensating")),
            ("recommendation", nested("recommendation"))
        ])) { first, _ in first }
        all.merge(rows("controls", "likelihood", [
            ("tier", row(
                analysis("Likelihood, and ThreatResolver"),
                section("the threat stanza, and Methodology"),
                [.otm, .threatcl, .json]
            )),
            ("prior", row(
                analysis("Likelihood, which multiplies the score by it"),
                section("the threat stanza, in Likelihood"),
                [.otm, .json]
            )),
            ("rationale", row(
                analysis("ControlsParser, which refuses a finding with no rationale"),
                section("the threat stanza, in Rationale"),
                [.threatcl, .json]
            )),
            ("sources", row(
                evidenceOnly,
                section("the threat stanza, in the source lines"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("controls", "severity_override", [
            ("rationale", row(
                evidenceOnly,
                section("the threat stanza, in Severity decided"),
                [.json]
            )),
            ("sources", row(
                evidenceOnly,
                section("the threat stanza, in Severity decided"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("controls", "control", [
            ("status", row(
                analysis("ControlCoverage"),
                section("the threat stanza, under Controls"),
                [.otm, .threatcl, .json]
            )),
            ("note", row(
                analysis("ApplyControlAnswers, which carries it onto the answer"),
                section("the threat stanza, under Controls"),
                []
            )),
            ("mitigated_by", row(
                analysis("ApplyControlAnswers, and ControlCoverage, which drops a mapped control"),
                section("the threat stanza, under Controls"),
                []
            )),
            ("evidence", row(
                analysis("CompileControls, PolicyRules, and AttackTreeBinding"),
                section("the threat stanza, under Controls"),
                [.otm, .threatcl, .json]
            )),
            ("reference", row(
                evidenceOnly,
                section("the threat stanza, folded into the evidence the control states"),
                [.otm, .threatcl, .json]
            )),
            ("verified_on", row(
                noAnalysis("no arithmetic compares the date to today"),
                section("the threat stanza, folded into the evidence the control states"),
                [.otm, .threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("controls", "compensating", [
            ("reduces_risk_by", row(
                analysis("ThreatResolver, which takes the stronger of two"),
                section("the threat stanza, in Compensated by"),
                [.threatcl, .json]
            )),
            ("rationale", row(
                analysis("ControlsParser, which refuses a compensating control with no rationale"),
                section("the threat stanza, in Compensated by"),
                [.threatcl, .json]
            )),
            ("sources", row(
                evidenceOnly,
                section("the threat stanza, in Compensated by"),
                [.json]
            )),
            ("evidence", row(
                evidenceOnly,
                section("the threat stanza, in Compensated by"),
                [.json]
            )),
            ("reference", row(
                evidenceOnly,
                section("the threat stanza, folded into the evidence the control states"),
                [.json]
            )),
            ("verified_on", row(
                noAnalysis("no arithmetic compares the date to today"),
                section("the threat stanza, folded into the evidence the control states"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("controls", "recommendation", [
            ("note", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Recommendations"),
                [.json]
            )),
            ("sources", row(
                evidenceOnly,
                section("Recommendations"),
                [.json]
            ))
        ])) { first, _ in first }
        return all
    }()

    static let attackTrees: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("attacktree", "attack_trees for", [
            ("catalogue", row(
                noAnalysis("WriteAttackTree writes the tag back; no arithmetic reads it"),
                noSection("the Document control row states the tag the `.arch` file holds"),
                []
            )),
            ("tree", nested("tree"))
        ])) { first, _ in first }
        all.merge(rows("attacktree", "tree", [
            ("name", row(
                analysis("AttackTreeBinding"),
                section("Attack trees, in the heading"),
                [.json]
            )),
            ("description", row(
                analysis("AttackTreeBinding, which carries it onto the bound tree"),
                section("Attack trees"),
                [.json]
            )),
            ("raises_risk_by", row(
                analysis("AttackTreeScoring"),
                section("Attack trees, which states the percentage"),
                [.json]
            )),
            ("closed_by", row(
                analysis("AttackTreeBinding, and RouteClosing"),
                section("Attack trees, in the heading"),
                [.json]
            )),
            ("goal", row(
                analysis("AttackTreeBinding"),
                section("Attack trees"),
                [.json]
            )),
            ("all_of", row(
                analysis("AttackTreeBinding, which takes the weakest child"),
                section("Attack trees, under Structure"),
                []
            )),
            ("any_of", row(
                analysis("AttackTreeBinding, which takes the easiest open child"),
                section("Attack trees, under Structure"),
                []
            )),
            ("then", row(
                analysis("AttackTreeBinding, which orders the chain"),
                section("Attack trees, under Structure and in the ordered chain"),
                []
            )),
            ("step", row(
                analysis("AttackTreeBinding, which binds the step to a threat"),
                section("Attack trees, in the step table"),
                [.json]
            ))
        ])) { first, _ in first }
        all.merge(rows("attacktree", "step", [
            ("note", row(
                noAnalysis("AttackTreeBinding carries it and no arithmetic reads it"),
                noSection("no section states a step's note"),
                []
            ))
        ])) { first, _ in first }
        for node in ["all_of", "any_of", "then"] {
            all.merge(rows("attacktree", node, [
                ("step", row(
                    analysis("AttackTreeBinding, which binds the step to a threat"),
                    section("Attack trees, under Structure"),
                    [.json]
                )),
                ("all_of", row(
                    analysis("AttackTreeBinding, which takes the weakest child"),
                    section("Attack trees, under Structure"),
                    []
                )),
                ("any_of", row(
                    analysis("AttackTreeBinding, which takes the easiest open child"),
                    section("Attack trees, under Structure"),
                    []
                )),
                ("then", row(
                    analysis("AttackTreeBinding, which orders the chain"),
                    section("Attack trees, under Structure"),
                    []
                ))
            ])) { first, _ in first }
        }
        return all
    }()
}

// MARK: the governance language and the policy language

extension ReportModelParityTests {
    static let governanceAndPolicy: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("governance", "governance for", [
            ("threat", nested("threat")),
            ("action", nested("work and action")),
            ("stale threat", row(
                analysis("CheckGovernance, which names the answer whose threat is gone"),
                noSection("no section states a stale decision; the check states it"),
                []
            )),
            ("stale action", row(
                analysis("CheckGovernance, which names the action nothing declares"),
                noSection("no section states a stale action; the check states it"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("governance", "threat", [
            ("accepted", nested("accepted")),
            ("work", nested("work and action")),
            ("stale accepted", row(
                analysis("CheckGovernance"),
                noSection("no section states a stale decision; the check states it"),
                []
            )),
            ("stale work", row(
                analysis("CheckGovernance"),
                noSection("no section states stale work; the check states it"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("governance", "accepted", [
            ("owner", row(
                analysis("PolicyRules, and CheckGovernance"),
                section("Accepted risks"),
                [.json]
            )),
            ("accepted_on", row(
                analysis("ApplyGovernance"),
                section("Accepted risks"),
                [.json]
            )),
            ("review_by", row(
                analysis("RiskAcceptance, CheckGovernance, and PolicyRules"),
                section("Accepted risks, which marks an overdue date"),
                [.json]
            )),
            ("rationale", row(
                analysis("ApplyGovernance, which carries it onto the accepted risk"),
                section("Accepted risks"),
                [.json]
            )),
            ("sources", row(
                evidenceOnly,
                section("Accepted risks, in the Sources column"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("governance", "work and action", [
            ("owner", row(
                analysis("PlannedWork"),
                section("Recommendations, in the line the plan states"),
                [.json]
            )),
            ("effort", row(
                analysis("PlannedWork"),
                section("Recommendations, in the line the plan states"),
                [.json]
            )),
            ("due_by", row(
                analysis("PlannedWork"),
                section("Recommendations, in the line the plan states"),
                [.json]
            )),
            ("status", row(
                analysis("PlannedWork"),
                section("Recommendations, in the line the plan states"),
                [.json]
            )),
            ("acceptance", row(
                noAnalysis("what a reviewer checks; no arithmetic reads it"),
                section("Recommendations, in Acceptance"),
                []
            )),
            ("note", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                section("Recommendations"),
                []
            )),
            ("sources", row(
                evidenceOnly,
                section("Recommendations"),
                []
            ))
        ])) { first, _ in first }

        let rulePairs = PolicySource.ruleNames.map { name in
            (name, row(
                analysis("PolicyRules, which states every breach of the rule"),
                section("Policy, which states the rule and every breach of it"),
                []
            ))
        }
        all.merge(rows("policy", "policy", rulePairs)) { first, _ in first }
        all.merge(rows("policy", "policy", [
            ("template", row(
                analysis("ReadReportTemplate, which reads the file the path names"),
                noSection("no section states the template path in use"),
                []
            )),
            ("cve_cvss_threshold", row(
                analysis("VulnerabilityPriority"),
                section("Policy, and Known vulnerabilities"),
                []
            )),
            ("cve_epss_threshold", row(
                analysis("VulnerabilityPriority"),
                section("Policy, and Known vulnerabilities"),
                []
            ))
        ])) { first, _ in first }
        return all
    }()
}

// MARK: the library language

extension ReportModelParityTests {
    static let library: [String: Row] = {
        var all: [String: Row] = [:]
        all.merge(rows("lib", "library", [
            ("name", row(
                analysis("Library, which names the library that changed a threat"),
                section("the threat stanza, in Changed by the library"),
                [.json]
            )),
            ("catalogue", row(
                analysis("LoadLibraries, which warns when the tag drifts"),
                noSection("the Document control row states the tag the `.arch` file holds"),
                []
            )),
            ("technology", nested("technology")),
            ("threat", nested("threat")),
            ("mitigation", nested("mitigation")),
            ("threat_actor", nested("threat_actor")),
            ("category", nested("category")),
            ("severity", nested("severity")),
            ("stride", nested("stride")),
            ("override", nested("override")),
            ("classification", nested("classification"))
        ])) { first, _ in first }
        all.merge(rows("lib", "classification", [
            ("name", row(
                analysis("Library, and RiskScore"),
                section("Data inventory, in the Classification column"),
                [.threatcl, .json]
            )),
            ("colour", row(
                noAnalysis("a drawing choice; no arithmetic reads it"),
                noSection("no section states a colour; the canvas paints the chip"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "override", [
            ("severity", row(
                analysis("Library, which changes the threat the catalogue states"),
                section("the threat stanza, in Changed by the library"),
                [.otm, .threatcl, .json]
            )),
            ("likelihood", row(
                analysis("Library, which changes the threat the catalogue states"),
                section("the threat stanza, in Changed by the library"),
                [.otm, .threatcl, .json]
            )),
            ("description", row(
                analysis("Library, which changes the threat the catalogue states"),
                section("the threat stanza, in Changed by the library"),
                [.otm, .threatcl, .json]
            )),
            ("control", row(
                analysis("Library, which changes the threat the catalogue states"),
                section("the threat stanza, under Controls"),
                [.otm, .threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "category", [
            ("name", row(
                analysis("Library, which names the category a technology sits in"),
                section("Appendix B, in the components table"),
                [.otm, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "severity", [
            ("name", row(
                analysis("Library, which names the severity a threat states"),
                section("the threat stanza, in Severity"),
                [.otm, .threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "stride", [
            ("name", row(
                analysis("Library, which names the stride word a threat states"),
                section("the threat stanza, in STRIDE"),
                [.otm, .threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "technology", technology)) { first, _ in first }
        all.merge(rows("lib", "threat", [
            ("name", row(
                analysis("ThreatResolver"),
                section("the threat stanza, in the heading"),
                [.otm, .threatcl, .json]
            )),
            ("description", row(
                analysis("ThreatResolver, which carries it onto the resolved threat"),
                section("the threat stanza"),
                [.otm, .threatcl, .json]
            )),
            ("severity", row(
                analysis("ThreatResolver, and RiskScore"),
                section("the threat stanza, in Severity"),
                [.otm, .threatcl, .json]
            )),
            ("stride", row(
                analysis("Library, which reads the stride words the threat states"),
                section("the threat stanza, in STRIDE"),
                [.otm, .threatcl, .json]
            )),
            ("impacts", row(
                analysis("ThreatResolver, and RiskScore"),
                section("the threat stanza, in Impact"),
                [.otm, .threatcl, .json]
            )),
            ("connection", row(
                analysis("ThreatResolver, which raises the threat on a flow"),
                section("the threat stanza, in Raised by"),
                [.otm, .json]
            )),
            ("zone", row(
                analysis("ThreatResolver, which raises the threat on a zone"),
                section("the threat stanza, in Raised by"),
                [.otm, .json]
            )),
            ("zone_context", row(
                analysis("ThreatResolver, which narrows the threat to the zone it names"),
                section("the threat stanza, in Narrowed to this element"),
                []
            )),
            ("mitre", nested("mitre")),
            ("control", row(
                analysis("ThreatResolver, and ControlCoverage"),
                section("the threat stanza, under Controls"),
                [.otm, .threatcl, .json]
            )),
            ("applies_to", row(
                analysis("ThreatApplicability, which narrows the threat to a flow kind"),
                section("the threat stanza, in Narrowed to this element"),
                []
            )),
            ("boundary", row(
                analysis("ThreatApplicability, which narrows the threat to a boundary"),
                section("the threat stanza, in Narrowed to this element"),
                []
            )),
            ("runs_as", row(
                analysis("ThreatApplicability, which narrows the threat to a privilege"),
                section("the threat stanza, in Narrowed to this element"),
                []
            )),
            ("pathway", row(
                analysis("ThreatResolver, which reads what feeds the element"),
                section("the threat stanza, in Narrowed to this element"),
                []
            )),
            ("likelihood", row(
                analysis("LibraryParser, and Likelihood"),
                section("the threat stanza, in Likelihood"),
                [.otm, .threatcl, .json]
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "mitigation", [
            ("name", row(
                analysis("PathwayMitigation, and ThreatResolver"),
                section("the threat stanza, in Answered upstream by"),
                [.json]
            )),
            ("description", row(
                noAnalysis("prose for a reader; no arithmetic reads it"),
                noSection("no section states a pathway mitigation's description"),
                []
            )),
            ("mitigates", row(
                analysis("ThreatResolver, which answers the threats it names"),
                section("the threat stanza, in Answered upstream by"),
                [.json]
            )),
            ("provided_by", row(
                analysis("ThreatResolver, which reads what provides the mitigation"),
                section("the threat stanza, in Answered upstream by"),
                []
            )),
            ("reduces_risk_by", row(
                analysis("ThreatResolver, which takes the stronger of two"),
                section("the threat stanza, in Answered upstream by"),
                []
            )),
            ("mode", row(
                analysis("PathwayMitigation, where remove drops the threat"),
                section("the threat stanza, in Answered upstream by"),
                []
            ))
        ])) { first, _ in first }
        all.merge(rows("lib", "threat_actor", threatActor)) { first, _ in first }
        all.merge(rows("lib", "mitre", [
            ("name", row(
                analysis("Library, which carries the technique onto the threat"),
                noSection("the threat stanza names the technique from the ATT&CK data on this machine"),
                []
            )),
            ("tactic", row(
                analysis("Library, which carries the technique onto the threat"),
                noSection("no section states the tactic a library names"),
                []
            ))
        ])) { first, _ in first }
        return all
    }()
}
