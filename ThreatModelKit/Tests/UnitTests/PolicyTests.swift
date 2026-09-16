import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Reading a policy file")
struct PolicyParserTests {
    private let gateway = HclPolicySource()

    private func errors(_ text: String) -> [String] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    @Test func readsEveryRule() throws {
        let policy = try #require(gateway.read("""
        policy {
          max_open_at_level                         = "high"
          accepted_requires_owner                   = true
          accepted_requires_review_by               = true
          implemented_requires_evidence_above       = "medium"
          restricted_data_stays_out_of_public_zones = true
          assumptions_require_owner                 = true
          system_requires_owner                     = true
        }
        """).source)

        #expect(policy.maxOpenAtLevel == .high)
        #expect(policy.acceptedRequiresOwner)
        #expect(policy.acceptedRequiresReviewBy)
        #expect(policy.implementedRequiresEvidenceAbove == .medium)
        #expect(policy.restrictedDataStaysOutOfPublicZones)
        #expect(policy.assumptionsRequireOwner)
        #expect(policy.systemRequiresOwner)
        #expect(policy.inForce.count == 7)
    }

    @Test func readsARuleTurnedOffAsNotInForce() throws {
        let policy = try #require(gateway.read("""
        policy {
          accepted_requires_owner = false
        }
        """).source)

        #expect(policy.acceptedRequiresOwner == false)
        #expect(policy.isEmpty)
    }

    @Test func readsAnEmptyPolicyAsNoRules() throws {
        #expect(try #require(gateway.read("policy { }").source).isEmpty)
    }

    @Test func refusesANameOutsideTheSet() {
        #expect(
            errors("""
            policy {
              no_critical_threats = true
            }
            """).first?.hasPrefix("a policy holds max_open_at_level, ") == true
        )
        #expect(errors("policy { no_critical_threats = true }").first?.contains(
            "not \"no_critical_threats\""
        ) == true)
    }

    @Test func refusesALevelOutsideTheFour() {
        #expect(
            errors("""
            policy {
              max_open_at_level = "enormous"
            }
            """) == [
                "max_open_at_level is \"enormous\"; this application holds "
                    + "\"low\", \"medium\", \"high\", \"critical\""
            ]
        )
    }

    @Test func readsTheCveThresholds() throws {
        let policy = try #require(gateway.read("""
        policy {
          cve_cvss_threshold = 7.0
          cve_epss_threshold = 0.1
        }
        """).source)

        #expect(policy.cveCvssThreshold == 7.0)
        #expect(policy.cveEpssThreshold == 0.1)
        #expect(policy.isEmpty)
    }

    @Test func aPolicyStatingNoThresholdHoldsNone() throws {
        let policy = try #require(gateway.read("policy { }").source)

        #expect(policy.cveCvssThreshold == nil)
        #expect(policy.cveEpssThreshold == nil)
    }

    @Test func refusesAThresholdOutsideItsRange() {
        #expect(
            errors("policy { cve_cvss_threshold = 11.0 }")
                == ["cve_cvss_threshold is 11.0; this application holds 0.0 to 10.0"]
        )
        #expect(
            errors("policy { cve_epss_threshold = 2 }")
                == ["cve_epss_threshold is 2; this application holds 0.0 to 1.0"]
        )
    }

    @Test func refusesAThresholdThatIsNotANumber() {
        #expect(errors("policy { cve_cvss_threshold = \"high\" }") == ["expected a number"])
    }

    @Test func refusesAFileThatDoesNotStartWithPolicy() {
        #expect(errors("rules { }").first == "expected policy, not \"rules\"")
    }
}

/// Each of the seven rules, breached and satisfied.
@Suite("What a policy rule asks of a system")
struct PolicyRuleTests {
    private func threat(
        _ id: String = "credential-theft",
        level: RiskLevel = .critical,
        beforeControls: RiskLevel = .critical,
        isAnswered: Bool = true,
        unevidenced: [String] = [],
        accepted: [String] = []
    ) -> PolicyRules.Threat {
        PolicyRules.Threat(
            key: ThreatKey(threatId: id, sourceId: "component:api"),
            threatId: id,
            sourceKind: "component",
            sourceId: "api",
            riskLevel: level,
            levelBeforeControls: beforeControls,
            isAnswered: isAnswered,
            unevidencedControls: unevidenced,
            acceptedControls: accepted
        )
    }

    private func breaches(
        _ policy: PolicySource,
        _ reading: PolicyRules.Reading
    ) -> [String] {
        PolicyRules.evaluate(policy, reading: reading).flatMap(\.breaches)
    }

    @Test func maxOpenAtLevelBreachesForAnOpenThreatAtThatLevel() {
        let breached = breaches(
            PolicySource(maxOpenAtLevel: .high),
            PolicyRules.Reading(threats: [threat(isAnswered: false)])
        )

        #expect(
            breached == [
                "credential-theft on component \"api\" (Critical) is open at or above high"
            ]
        )
    }

    @Test func maxOpenAtLevelHoldsWhenTheThreatIsAnswered() {
        #expect(
            breaches(
                PolicySource(maxOpenAtLevel: .high),
                PolicyRules.Reading(threats: [threat(isAnswered: true)])
            ).isEmpty
        )
    }

    @Test func maxOpenAtLevelHoldsBelowTheLevel() {
        #expect(
            breaches(
                PolicySource(maxOpenAtLevel: .critical),
                PolicyRules.Reading(threats: [threat(level: .high, isAnswered: false)])
            ).isEmpty
        )
    }

    @Test func acceptedRequiresOwnerBreachesWhenNobodyIsNamed() {
        let breached = breaches(
            PolicySource(acceptedRequiresOwner: true),
            PolicyRules.Reading(
                threats: [threat(accepted: ["Enforce MFA"])],
                acceptedRisks: [
                    ThreatKey(threatId: "credential-theft", sourceId: "component:api"): [
                        RiskAcceptance(control: "Enforce MFA")
                    ]
                ]
            )
        )

        #expect(breached == ["credential-theft@component:api is accepted by nobody"])
    }

    @Test func acceptedRequiresOwnerHoldsWhenSomebodyIsNamed() {
        #expect(
            breaches(
                PolicySource(acceptedRequiresOwner: true),
                PolicyRules.Reading(
                    threats: [threat(accepted: ["Enforce MFA"])],
                    acceptedRisks: [
                        ThreatKey(threatId: "credential-theft", sourceId: "component:api"): [
                            RiskAcceptance(control: "Enforce MFA", owner: "Head of Platform")
                        ]
                    ]
                )
            ).isEmpty
        )
    }

    @Test func acceptedRequiresReviewByBreachesWithNoDate() {
        #expect(
            breaches(
                PolicySource(acceptedRequiresReviewBy: true),
                PolicyRules.Reading(
                    threats: [threat(accepted: ["Enforce MFA"])],
                    acceptedRisks: [
                        ThreatKey(threatId: "credential-theft", sourceId: "component:api"): [
                            RiskAcceptance(control: "Enforce MFA", owner: "Head of Platform")
                        ]
                    ]
                )
            ) == ["credential-theft@component:api is accepted with no review date"]
        )
    }

    @Test func acceptedRequiresReviewByHoldsWithADate() throws {
        let date = try #require(try? GovernanceDate.read("2027-03-01").get())

        #expect(
            breaches(
                PolicySource(acceptedRequiresReviewBy: true),
                PolicyRules.Reading(
                    threats: [threat(accepted: ["Enforce MFA"])],
                    acceptedRisks: [
                        ThreatKey(threatId: "credential-theft", sourceId: "component:api"): [
                            RiskAcceptance(control: "Enforce MFA", reviewBy: date)
                        ]
                    ]
                )
            ).isEmpty
        )
    }

    @Test func implementedRequiresEvidenceAboveBreachesWithNoTier() {
        #expect(
            breaches(
                PolicySource(implementedRequiresEvidenceAbove: .high),
                PolicyRules.Reading(threats: [threat(unevidenced: ["Enforce MFA"])])
            ) == [
                "credential-theft@component:api: \"Enforce MFA\" is implemented above "
                    + "high risk with no evidence"
            ]
        )
    }

    @Test func implementedRequiresEvidenceAboveHoldsWhenEveryControlStatesOne() {
        #expect(
            breaches(
                PolicySource(implementedRequiresEvidenceAbove: .high),
                PolicyRules.Reading(threats: [threat(unevidenced: [])])
            ).isEmpty
        )
    }

    @Test func restrictedDataBreachesInAPublicZoneAndOutsideEveryZone() {
        let breached = breaches(
            PolicySource(restrictedDataStaysOutOfPublicZones: true),
            PolicyRules.Reading(
                elements: [
                    PolicyRules.Element(id: "ledger", sensitivity: .restricted, zone: .publicZone),
                    PolicyRules.Element(id: "loose", sensitivity: .restricted, zone: nil)
                ]
            )
        )

        #expect(
            breached == [
                "\"ledger\" holds restricted data in a public zone",
                "\"loose\" holds restricted data outside every zone"
            ]
        )
    }

    @Test func restrictedDataHoldsInAPrivateZone() {
        #expect(
            breaches(
                PolicySource(restrictedDataStaysOutOfPublicZones: true),
                PolicyRules.Reading(
                    elements: [
                        PolicyRules.Element(
                            id: "ledger",
                            sensitivity: .restricted,
                            zone: .privateZone
                        )
                    ]
                )
            ).isEmpty
        )
    }

    @Test func assumptionsRequireOwnerBreachesForAnUnownedAssumption() {
        #expect(
            breaches(
                PolicySource(assumptionsRequireOwner: true),
                PolicyRules.Reading(assumptions: [("the MDM is trusted", "")])
            ) == ["the assumption \"the MDM is trusted\" names no owner"]
        )
    }

    @Test func assumptionsRequireOwnerHoldsWhenEveryOneNamesAnOwner() {
        #expect(
            breaches(
                PolicySource(assumptionsRequireOwner: true),
                PolicyRules.Reading(assumptions: [("the MDM is trusted", "Endpoint team")])
            ).isEmpty
        )
    }

    @Test func systemRequiresOwnerBreachesForASystemThatStatesNobody() {
        #expect(
            breaches(PolicySource(systemRequiresOwner: true), PolicyRules.Reading())
                == ["this system states no owner"]
        )
    }

    @Test func systemRequiresOwnerHoldsWhenTheFileStatesOne() {
        #expect(
            breaches(
                PolicySource(systemRequiresOwner: true),
                PolicyRules.Reading(systemOwner: "Payments team")
            ).isEmpty
        )
    }

    @Test func aProjectWithNoRulesBreachesNothing() {
        #expect(
            PolicyRules.evaluate(
                PolicySource(),
                reading: PolicyRules.Reading(threats: [threat(isAnswered: false)])
            ).isEmpty
        )
    }
}

@Suite("The policy section of the report")
struct MarkdownPolicyTests {
    @Test func writesNoSectionForAProjectWithNoPolicy() {
        #expect(MarkdownPolicy.lines([]).isEmpty)
    }

    @Test func writesOneRowPerRule() {
        let lines = MarkdownPolicy.lines([
            ReportPolicyRule(
                name: "max_open_at_level",
                asks: "no threat at high or worse is unanswered",
                breaches: [
                    "T-1 on component \"api\" (high) is open at or above high",
                    "T-2 on component \"api\" (high) is open at or above high",
                    "T-3 on component \"db\" (critical) is open at or above high"
                ]
            ),
            ReportPolicyRule(
                name: "system_requires_owner",
                asks: "the file states an owner",
                breaches: []
            ),
            ReportPolicyRule(
                name: "assumptions_require_owner",
                asks: "every assumption names an owner",
                breaches: ["the assumption \"tls\" names no owner"]
            )
        ])
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Policy")
        #expect(text.contains("The rules this project enforces, and whether this system keeps them."))
        #expect(text.contains("| Rule | Asks | Holds |"))
        #expect(
            text.contains(
                "| max_open_at_level | no threat at high or worse is unanswered"
                    + " | no \u{2014} 3 breaches |"
            )
        )
        #expect(text.contains("| system_requires_owner | the file states an owner | yes |"))
        #expect(text.contains("| assumptions_require_owner | every assumption names an owner"
            + " | no \u{2014} 1 breach |"))
    }
}
