import Foundation

/// The parity list itself: what the window does about every attribute every
/// language reads.
///
/// `WindowModelParityTests` walks `LanguageVocabulary` against this list. Read
/// the test file first; this file is the table.
extension WindowModelParityTests {
    /// The rows of one block, keyed the way `LanguageVocabulary.attributeKeys`
    /// keys them.
    static func rows(
        _ language: String,
        _ block: String,
        _ pairs: [(String, Parity)]
    ) -> [String: Parity] {
        var found: [String: Parity] = [:]
        for pair in pairs { found["\(language).\(block).\(pair.0)"] = pair.1 }
        return found
    }

    /// A word that names a nested block. The block has rows of its own.
    static func nested(_ block: String) -> Parity {
        .stated("a nested block; the \(block) rows state its controls")
    }

    // MARK: the architecture language

    static let architecture: [String: Parity] = {
        var all: [String: Parity] = [:]
        for block in [archSystem, archElements, archFacts] {
            all.merge(block) { first, _ in first }
        }
        return all
    }()

    static let archSystem: [String: Parity] = {
        var all: [String: Parity] = [:]
        all.merge(rows("arch", "system", [
            ("catalogue", .writes("take-catalogue-in-use")),
            ("owner", .writes("system-owner")),
            ("description", .writes("system-description")),
            ("authors", .writes("system-authors")),
            ("links", .writes("system-links")),
            ("repositories", .writes("system-repositories")),
            ("created", .writes("system-created")),
            ("reviewed", .writes("system-reviewed")),
            ("version", .writes("system-version")),
            ("attribute", nested("attribute")),
            ("technology", nested("technology")),
            ("zone", nested("zone")),
            ("component", nested("component")),
            ("user", nested("user")),
            ("flow", nested("flow")),
            ("mitigates", nested("mitigates")),
            ("risk_tolerance", .writes("risk-tolerance")),
            ("requires_evidence_above", .gap(160)),
            ("assumption", nested("assumption")),
            ("use_case", nested("use_case")),
            ("exclusion", nested("exclusion")),
            ("asset", nested("asset (in system)")),
            ("third_party", nested("third_party")),
            ("diagram", nested("diagram")),
            ("faces", .writes("faces-")),
            ("threat_actor", nested("threat_actor"))
        ])) { first, _ in first }
        all.merge(rows("arch", "user", [
            ("name", .writes("user-name")),
            ("role", .writes("user-role")),
            ("access", .writes("user-access")),
            ("reaches", .writes("user-reaches")),
            ("threat_actor", .writes("user-threat-actor"))
        ])) { first, _ in first }
        all.merge(rows("arch", "attribute", [
            ("value", .writes("system-attribute-value"))
        ])) { first, _ in first }
        return all
    }()

    static let archFacts: [String: Parity] = {
        var all: [String: Parity] = [:]
        all.merge(rows("arch", "assumption", [
            ("text", .writes("assumption-text")),
            ("owner", .writes("assumption-owner"))
        ])) { first, _ in first }
        all.merge(rows("arch", "diagram", [
            ("kind", .gap(161)),
            ("text", .writes("diagram-text"))
        ])) { first, _ in first }
        all.merge(rows("arch", "third_party", [
            ("name", .writes("third-party-name")),
            ("description", .writes("third-party-description")),
            ("kind", .writes("third-party-kind")),
            ("paying_customer", .writes("third-party-paying-customer")),
            ("uptime", .writes("third-party-uptime")),
            ("uptime_notes", .writes("third-party-uptime-notes")),
            ("owner", .writes("third-party-owner")),
            ("link", .writes("third-party-link"))
        ])) { first, _ in first }
        all.merge(rows("arch", "asset (in system)", [
            ("name", .writes("asset-name")),
            ("classification", .writes("asset-classification")),
            ("description", .gap(162)),
            ("owner", .writes("asset-owner"))
        ])) { first, _ in first }
        all.merge(rows("arch", "use_case", [
            ("text", .writes("use-case-text"))
        ])) { first, _ in first }
        all.merge(rows("arch", "exclusion", [
            ("text", .writes("exclusion-text")),
            ("rationale", .writes("exclusion-rationale"))
        ])) { first, _ in first }
        all.merge(rows("arch", "threat_actor", [
            ("name", .writes("threat-actor-name")),
            ("description", .writes("threat-actor-description")),
            ("aliases", .gap(163)),
            ("capability", .writes("threat-actor-capability")),
            ("intent", .writes("threat-actor-intent")),
            ("performs", .writes("threat-actor-performs")),
            ("techniques", .writes("threat-actor-techniques")),
            ("performs_catalogue_tier", .writes("threat-actor-catalogue-tier"))
        ])) { first, _ in first }
        return all
    }()

    static let archElements: [String: Parity] = {
        var all: [String: Parity] = [:]
        all.merge(rows("arch", "technology", [
            ("name", .writes("technology-name")),
            ("category", .writes("technology-category")),
            ("description", .writes("technology-description")),
            ("threats", .writes("threat-choice-")),
            ("encrypts", .writes("technology-enforces-encryption")),
            ("control", .writes("technology-controls"))
        ])) { first, _ in first }
        all.merge(rows("arch", "zone", [
            ("kind", .writes("zone-kind")),
            ("network", .writes("zone-network-type")),
            ("name", .writes("zone-name")),
            ("reduces_risk", .writes("zone-reduction-enabled")),
            ("reduces_risk_by", .writes("zone-reduction-percent")),
            ("component", nested("component")),
            ("boundary", .writes("zone-boundary")),
            ("description", .writes("zone-description")),
            ("source", .stated(
                "provenance an import writes; no control changes it, and a save keeps it"
            )),
            ("tags", .writes("zone-tags"))
        ])) { first, _ in first }
        all.merge(rows("arch", "component", [
            ("technology", .writes("component-technology")),
            ("name", .writes("component-name")),
            ("zone", .stated("the drag writes it: a component sits in the zone its centre is in")),
            ("data", .writes("component-sensitivity")),
            ("status", .writes("component-status")),
            ("version", .writes("component-version")),
            ("cves", .writes("component-cves")),
            ("holds", .writes("component-holds")),
            ("provided_by", .writes("component-provided-by")),
            ("source", .stated(
                "provenance an import writes; no control changes it, and a save keeps it"
            )),
            ("threats", .writes("component-threats-raised")),
            ("runs_as", .writes("component-runs-as")),
            ("shape", .writes("component-shape")),
            ("tags", .writes("component-tags")),
            ("asset", .writes("add-component-asset"))
        ])) { first, _ in first }
        all.merge(rows("arch", "asset (in component)", [
            ("data", .writes("component-asset-data"))
        ])) { first, _ in first }
        all.merge(rows("arch", "flow", [
            ("kind", .writes("connection-kind")),
            ("description", .writes("connection-description")),
            ("carries", .writes("connection-carries")),
            ("tags", .writes("connection-tags"))
        ])) { first, _ in first }
        all.merge(rows("arch", "mitigates", [
            ("threats", .writes("mitigates-threat-")),
            ("reduces_risk_by", .writes("mitigates-percent")),
            ("status", .writes("mitigates-status")),
            ("recommendation", nested("recommendation (in mitigates)"))
        ])) { first, _ in first }
        all.merge(rows("arch", "recommendation (in mitigates)", [
            ("text", .writes("mitigates-action-text")),
            ("note", .writes("mitigates-action-note")),
            ("blocked_by", .writes("mitigates-action-blocked-by")),
            ("sources", .writes("mitigates-action-sources"))
        ])) { first, _ in first }
        return all
    }()

    // MARK: the controls language and the attack tree language

    static let controlsAndTrees: [String: Parity] = {
        var all: [String: Parity] = [:]
        all.merge(rows("controls", "controls for", [
            ("catalogue", .writes("take-catalogue-in-use")),
            ("tolerance", .writes("risk-tolerance")),
            ("threat", nested("threat")),
            ("tree", nested("tree")),
            ("stale threat", .stated("read only: the compile marks an answer stale")),
            ("stale tree", .stated("read only: the compile marks a tree stale"))
        ])) { first, _ in first }
        all.merge(rows("controls", "tree", [
            ("goal", .writes("tree-selection-set-goal")),
            ("chain", .stated("read only: the tree's own shape gives it")),
            ("raises_risk_by", .writes("attack-tree-raises-risk-by")),
            ("score", .stated("read only: the scoring gives it")),
            ("score_before", .stated("read only: the scoring gives it")),
            ("closed_by", .writes("tree-sufficient-add")),
            ("sufficient", nested("sufficient")),
            ("step", nested("step"))
        ])) { first, _ in first }
        all.merge(rows("controls", "sufficient", [
            ("state", .stated("read only: the control's own status gives it"))
        ])) { first, _ in first }
        all.merge(rows("controls", "step", [
            ("state", .writes("control-status-")),
            ("by", .writes("control-status-")),
            ("position", .stated("read only: the step's place in its chain gives it"))
        ])) { first, _ in first }
        all.merge(rows("controls", "threat", [
            ("severity", .writes("severity-decision-severity")),
            ("score", .stated("read only: the scoring gives it")),
            ("impacts", .writes("impact-")),
            ("likelihood", nested("likelihood")),
            ("severity_override", nested("severity_override")),
            ("control", nested("control")),
            ("compensating", nested("compensating")),
            ("recommendation", nested("recommendation"))
        ])) { first, _ in first }
        all.merge(rows("controls", "likelihood", [
            ("tier", .writes("likelihood-tier")),
            ("prior", .writes("likelihood-prior")),
            ("rationale", .writes("likelihood-rationale")),
            ("sources", .writes("likelihood-sources"))
        ])) { first, _ in first }
        all.merge(rows("controls", "severity_override", [
            ("rationale", .writes("severity-decision-rationale")),
            ("sources", .writes("severity-decision-sources"))
        ])) { first, _ in first }
        all.merge(rows("controls", "control", [
            ("status", .writes("control-status-")),
            ("note", .writes("control-note")),
            ("evidence", .writes("evidence-tier")),
            ("reference", .writes("evidence-reference")),
            ("verified_on", .writes("evidence-verified-on"))
        ])) { first, _ in first }
        all.merge(rows("controls", "compensating", [
            ("reduces_risk_by", .writes("compensating-percent")),
            ("rationale", .writes("compensating-rationale")),
            ("sources", .writes("compensating-sources")),
            ("evidence", .writes("compensating-evidence-tier")),
            ("reference", .writes("compensating-evidence-reference")),
            ("verified_on", .writes("compensating-verified-on"))
        ])) { first, _ in first }
        all.merge(rows("controls", "recommendation", [
            ("note", .writes("recommendation-note")),
            ("sources", .writes("recommendation-sources"))
        ])) { first, _ in first }

        all.merge(rows("attacktree", "attack_trees for", [
            ("catalogue", .writes("take-attack-tree-catalogue-in-use")),
            ("tree", nested("tree"))
        ])) { first, _ in first }
        all.merge(rows("attacktree", "tree", [
            ("name", .writes("attack-tree-name")),
            ("description", .writes("attack-tree-description")),
            ("raises_risk_by", .writes("attack-tree-raises-risk-by")),
            ("closed_by", .writes("tree-sufficient-add")),
            ("goal", .writes("tree-selection-set-goal")),
            ("all_of", .writes("tree-element-junction-all")),
            ("any_of", .writes("tree-element-junction-any")),
            ("then", .writes("tree-node-")),
            ("step", .writes("tree-element-placeholder"))
        ])) { first, _ in first }
        all.merge(rows("attacktree", "step", [
            ("note", .writes("tree-step-note"))
        ])) { first, _ in first }
        for node in ["all_of", "any_of", "then"] {
            all.merge(rows("attacktree", node, [
                ("step", .writes("tree-element-placeholder")),
                ("all_of", .writes("tree-element-junction-all")),
                ("any_of", .writes("tree-element-junction-any")),
                ("then", .writes("tree-node-"))
            ])) { first, _ in first }
        }
        return all
    }()
}

// MARK: the governance language and the policy language

extension WindowModelParityTests {
    /// A value the window draws and no control changes.
    static func readOnly(_ where_: String) -> Parity {
        .stated("read only in the window: \(where_)")
    }

    static let governanceAndPolicy: [String: Parity] = {
        var all: [String: Parity] = [:]
        all.merge(rows("governance", "governance for", [
            ("threat", nested("threat")),
            ("action", nested("work and action")),
            ("stale threat", readOnly("the compile marks an answer stale")),
            ("stale action", readOnly("the compile marks an action stale"))
        ])) { first, _ in first }
        all.merge(rows("governance", "threat", [
            ("accepted", nested("accepted")),
            ("work", nested("work and action")),
            ("stale accepted", readOnly("the compile marks an accepted risk stale")),
            ("stale work", readOnly("the compile marks planned work stale"))
        ])) { first, _ in first }
        all.merge(rows("governance", "accepted", [
            ("owner", .writes("governance-owner")),
            ("accepted_on", .writes("governance-accepted-on")),
            ("review_by", .writes("governance-review-by")),
            ("rationale", .writes("governance-rationale")),
            ("sources", .writes("governance-sources"))
        ])) { first, _ in first }
        all.merge(rows("governance", "work and action", [
            ("owner", .writes("planned-work-owner")),
            ("effort", .writes("planned-work-effort")),
            ("due_by", .writes("planned-work-due-by")),
            ("status", .writes("planned-work-status")),
            ("acceptance", .writes("planned-work-acceptance")),
            ("note", .writes("planned-work-note")),
            ("sources", .writes("planned-work-sources"))
        ])) { first, _ in first }

        // A policy file states the rules a project is held to. The window
        // reads it and reports the verdicts; a team writes the file.
        let policyRows = [
            "max_open_at_level", "accepted_requires_owner", "accepted_requires_review_by",
            "implemented_requires_evidence_above",
            "restricted_data_stays_out_of_public_zones", "assumptions_require_owner",
            "system_requires_owner"
        ].map { ($0, readOnly("the diagnostics sheet lists every rule in force")) }
        all.merge(rows("policy", "policy", policyRows)) { first, _ in first }
        all.merge(rows("policy", "policy", [
            ("template", readOnly("the report stage states the template path in use")),
            ("cve_cvss_threshold", readOnly("the report stage states both thresholds")),
            ("cve_epss_threshold", readOnly("the report stage states both thresholds"))
        ])) { first, _ in first }
        return all
    }()
}

// MARK: the library language

extension WindowModelParityTests {
    /// A library file is the catalogue a project reads. The window draws what
    /// a library states; a library author writes the file. `technology` is the
    /// one block the window writes, through Move to library.
    static let library: [String: Parity] = {
        var all: [String: Parity] = [:]
        all.merge(rows("lib", "library", [
            ("name", readOnly("the libraries sheet lists every library by name")),
            ("catalogue", readOnly("the diagnostics sheet warns when the tag drifts")),
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
            ("name", readOnly("the sensitivity picker lists every classification by name")),
            ("colour", .gap(171))
        ])) { first, _ in first }
        all.merge(rows("lib", "override", [
            ("severity", readOnly("the threat card states the severity the override gives")),
            ("likelihood", readOnly("the threat card states the likelihood the override gives")),
            ("description", readOnly("the threat card draws the description the override gives")),
            ("control", readOnly("the threat card lists the controls the override gives"))
        ])) { first, _ in first }
        for taxonomy in ["category", "severity", "stride"] {
            all.merge(rows("lib", taxonomy, [
                ("name", readOnly("the window labels the \(taxonomy) with the name"))
            ])) { first, _ in first }
        }
        all.merge(rows("lib", "technology", [
            ("name", .writes("technology-name")),
            ("category", .writes("technology-category")),
            ("description", .writes("technology-description")),
            ("threats", .writes("threat-choice-")),
            ("encrypts", .writes("technology-enforces-encryption")),
            ("control", .writes("technology-controls"))
        ])) { first, _ in first }
        all.merge(rows("lib", "threat", [
            ("name", readOnly("the threat card names the threat")),
            ("description", readOnly("the threat card draws the description")),
            ("severity", readOnly("the threat card states the severity")),
            ("stride", readOnly("the threat card draws a chip for every stride word")),
            ("impacts", readOnly("the threat card draws a chip for every impact")),
            ("connection", .gap(172)),
            ("zone", .gap(172)),
            ("zone_context", readOnly("the threat card draws the zone context as its body")),
            ("mitre", nested("mitre")),
            ("control", readOnly("the threat card lists every control the threat offers")),
            ("applies_to", .gap(172)),
            ("boundary", .gap(172)),
            ("runs_as", .gap(172)),
            ("pathway", .gap(172)),
            ("likelihood", readOnly("the threat card states what the threat takes to happen"))
        ])) { first, _ in first }
        all.merge(rows("lib", "mitigation", [
            ("name", readOnly("the pathway mitigations panel names every mitigation")),
            ("description", .gap(173)),
            ("mitigates", readOnly("the threat card lists what a mitigation took off the score")),
            ("provided_by", readOnly("the pathway row names what would provide the mitigation")),
            ("reduces_risk_by", readOnly("the pathway row states the percentage the library gives")),
            ("mode", readOnly("the pathway row states the mode the library gives"))
        ])) { first, _ in first }
        all.merge(rows("lib", "threat_actor", [
            ("name", readOnly("a library actor is read; the arch threat_actor rows state the controls")),
            ("description", readOnly("a library actor is read; the arch threat_actor rows state the controls")),
            ("aliases", .gap(163)),
            ("capability", readOnly("a library actor is read; the arch threat_actor rows state the controls")),
            ("intent", readOnly("a library actor is read; the arch threat_actor rows state the controls")),
            ("performs", readOnly("a library actor is read; the arch threat_actor rows state the controls")),
            ("techniques", readOnly("a library actor is read; the arch threat_actor rows state the controls")),
            ("performs_catalogue_tier", readOnly("a library actor is read; the arch threat_actor rows state the controls"))
        ])) { first, _ in first }
        all.merge(rows("lib", "mitre", [
            ("name", readOnly("the threat card names the technique beside its link")),
            ("tactic", readOnly("the threat card names the tactic beside its link"))
        ])) { first, _ in first }
        return all
    }()
}
