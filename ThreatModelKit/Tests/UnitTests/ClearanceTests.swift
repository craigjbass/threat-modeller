import Testing
import ThreatModelKit
import TestSupport

/// A library whose one technology carries one threat an insider performs.
private func insiderLibrary() -> Library {
    let source = LibrarySource(
        label: "endpoint",
        technologies: [
            SourceTechnology(
                id: "laptop",
                name: "Laptop",
                category: "compute",
                threatIds: ["key-copying"]
            )
        ],
        threats: [
            SourceLibraryThreat(
                id: "key-copying",
                name: "An operator copies a key",
                severityLabel: "critical",
                likelihood: "insider"
            )
        ]
    )
    let (library, faults) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
    precondition(faults.isEmpty, "library build faults: \(faults)")
    return library!
}

@Suite("A security clearance answers the threats an insider performs")
struct ClearanceTests {
    private let app = TestDependencies()

    private static let clearance = """
      clearance "sc" {
        name                    = "Security Check"
        description             = "Five years of history are checked."
        reduces_insider_risk_by = 60
        rationale               = "The vetting reads the whole employment record."
        sources                 = ["https://example.test/vetting"]
      }
    """

    private static func system(_ blocks: String) -> String {
        """
        system "Payments" {
        \(clearance)

          component "api" {
            technology = "endpoint-laptop"
            data       = "restricted"
          }

        \(blocks)
        }

        """
    }

    private func open(_ text: String) {
        app.useLibraries([insiderLibrary()])
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))
    }

    private func threat() throws -> AssessedThreat {
        try #require(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first)
    }

    // MARK: the weakest clearance among the users that reach the component

    @Test func oneUnclearedUserLeavesTheScoreWhereItWas() throws {
        open(
            Self.system(
                """
                  user "alice" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }

                  user "bob" {
                    reaches = ["api"]
                  }
                """
            )
        )

        let scored = try threat()

        #expect(scored.likelihoodId == "insider")
        #expect(scored.riskScore == 10)
        #expect(scored.compensatingLabels.isEmpty)
    }

    @Test func aClearanceEveryUserHoldsReducesTheInsiderThreat() throws {
        open(
            Self.system(
                """
                  user "alice" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }

                  user "bob" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                """
            )
        )

        let scored = try threat()

        #expect(scored.riskScore == 4)
        #expect(scored.scoreBeforeCompensation == 10)
        #expect(
            scored.compensatingLabels
                == ["Security clearance \"Security Check\", held by alice and bob"]
        )
    }

    @Test func anAdversaryWithAClearanceReducesNothing() throws {
        open(
            Self.system(
                """
                  adversary "mallory" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                """
            )
        )
        #expect(try threat().riskScore == 10)

        let legitimate = TestDependencies()
        legitimate.useLibraries([insiderLibrary()])
        _ = legitimate.importArchitecture().execute(
            ImportArchitectureRequest(
                text: Self.system(
                    """
                      user "mallory" {
                        reaches   = ["api"]
                        clearance = "sc"
                      }
                    """
                )
            )
        )

        let scored = legitimate.assessThreatModel().execute(AssessThreatModelRequest()).threats
        #expect(scored.first?.riskScore == 4)
    }

    @Test func aClearanceAndACompensatingBlockGiveTheStronger() throws {
        open(
            Self.system(
                """
                  user "alice" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                """
            )
        )
        let key = try threat().threatKey

        #expect(
            app.setCompensatingControl().execute(
                SetCompensatingControlRequest(
                    threatKey: key,
                    label: "Break-glass account watched by the SIEM",
                    reducesRiskBy: 30,
                    rationale: "The SIEM alerts on every use."
                )
            ) == .recorded
        )
        #expect(try threat().riskScore == 4)

        #expect(
            app.setCompensatingControl().execute(
                SetCompensatingControlRequest(
                    threatKey: key,
                    label: "Break-glass account watched by the SIEM",
                    reducesRiskBy: 80,
                    rationale: "The SIEM alerts on every use."
                )
            ) == .recorded
        )
        #expect(try threat().riskScore == 2)
    }

    @Test func aClearanceAnswersNoThreatAnInsiderDoesNotPerform() throws {
        app.useLibraries([
            {
                let source = LibrarySource(
                    label: "endpoint",
                    technologies: [
                        SourceTechnology(
                            id: "laptop",
                            name: "Laptop",
                            category: "compute",
                            threatIds: ["theft"]
                        )
                    ],
                    threats: [
                        SourceLibraryThreat(
                            id: "theft",
                            name: "A laptop is stolen",
                            severityLabel: "critical",
                            likelihood: "commodity"
                        )
                    ]
                )
                let (library, _) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
                return library!
            }()
        ])
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: Self.system(
                    """
                      user "alice" {
                        reaches   = ["api"]
                        clearance = "sc"
                      }
                    """
                )
            )
        )

        let scored = try threat()

        #expect(scored.likelihoodId == "commodity")
        #expect(scored.riskScore == 16)
    }

    // MARK: the language

    @Test func aUserNamingAClearanceNothingDeclaresRefusesTheProject() throws {
        app.useLibraries([insiderLibrary()])
        let answer = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "endpoint-laptop"
                  }

                  user "alice" {
                    reaches   = ["api"]
                    clearance = "dv"
                  }
                }

                """
            )
        )

        guard case .refused(let diagnostics) = answer else {
            Issue.record("the import was not refused: \(answer)")
            return
        }
        #expect(
            diagnostics.map(\.message) == [
                "the user \"alice\" names the clearance \"dv\", "
                    + "which no clearance block declares"
            ]
        )
    }

    @Test func theFileRoundTripsTheClearanceAndTheUsersPick() throws {
        open(
            Self.system(
                """
                  user "alice" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                """
            )
        )

        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(written.contains("clearance \"sc\" {"))
        #expect(written.contains("reduces_insider_risk_by = 60"))
        #expect(written.contains("rationale               = \"The vetting reads the whole employment record.\""))
        #expect(written.contains("clearance = \"sc\""))
    }

    @Test func aClearanceWithNoRationaleIsRefused() throws {
        app.useLibraries([insiderLibrary()])
        let answer = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  clearance "sc" {
                    name                    = "Security Check"
                    reduces_insider_risk_by = 60
                  }
                }

                """
            )
        )

        guard case .refused(let diagnostics) = answer else {
            Issue.record("the import was not refused: \(answer)")
            return
        }
        #expect(
            diagnostics.contains { $0.message == "the clearance \"sc\" has no rationale" }
        )
    }

    @Test func aReductionOutsideTheRangeIsRefused() throws {
        app.useLibraries([insiderLibrary()])
        let answer = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  clearance "sc" {
                    name                    = "Security Check"
                    reduces_insider_risk_by = 140
                    rationale               = "It is thorough."
                  }
                }

                """
            )
        )

        guard case .refused(let diagnostics) = answer else {
            Issue.record("the import was not refused: \(answer)")
            return
        }
        #expect(
            diagnostics.contains {
                $0.message == "reduces_insider_risk_by is 140; a reduction is 0 to 100"
            }
        )
    }

    // MARK: the report

    @Test func theScopeSectionStatesEachUsersClearance() throws {
        open(
            Self.system(
                """
                  user "alice" {
                    name      = "Alice"
                    role      = "Operator"
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                """
            )
        )

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(
            markdown.contains(
                "- Alice (Operator, User): reaches Laptop; holds the clearance Security Check"
            )
        )
    }

    @Test func theMethodologyStatesTheClearanceRule() throws {
        open(
            Self.system(
                """
                  user "alice" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                """
            )
        )

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(
            markdown.contains(
                "A security clearance is a compensating control on a threat an insider performs."
            )
        )
    }
}
