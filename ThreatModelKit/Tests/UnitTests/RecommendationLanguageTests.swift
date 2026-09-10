import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

struct RecommendationLanguageTests {
    private func read(_ text: String) -> ControlsRead {
        HclControlsSource().read(text)
    }

    @Test func aThreatCarriesARecommendation() throws {
        let source = try #require(read("""
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Protect the managed preferences plist" {
              note = "Deny write from anything but the MDM daemon."
            }
          }
        }
        """).source)
        let answer = try #require(source.answers.first)
        #expect(answer.recommendations.first?.text == "Protect the managed preferences plist")
        #expect(answer.recommendations.first?.note == "Deny write from anything but the MDM daemon.")
    }

    @Test func aRecommendationNeedsNoNote() throws {
        let source = try #require(read("""
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """).source)
        #expect(source.answers.first?.recommendations.first?.note == nil)
    }

    @Test func aRecommendationIsNotAnAnswer() throws {
        let source = try #require(read("""
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """).source)
        #expect(source.answers.first?.isAnswered == false)
    }

    @Test func aRewriteKeepsTheRecommendation() throws {
        let text = """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" {
              note = "An endpoint rule, not a control the catalogue offers."
            }
          }
        }

        """
        let source = try #require(read(text).source)
        #expect(HclControlsSource().write(source) == text)
    }

    @Test func theCompileKeepsARecommendationWholeAcrossARewrite() throws {
        let architecture = """
        system "S" {
          component "c1" { technology = "aws-ec2" data = "confidential" }
        }
        """
        let controls = """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """
        let response = CompileControls(
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        ).execute(CompileControlsRequest(architectureText: architecture, controlsText: controls))

        guard case .compiled(let text, _, _, _, _) = response else {
            Issue.record("the compile refused the file")
            return
        }
        #expect(text.contains("recommendation \"Deny reads of /dev/rdisk**\""))
    }

    @Test func savingTheSystemKeepsTheRecommendation() throws {
        let app = TestDependencies()
        let architecture = """
        system "S" {
          component "c1" { technology = "aws-ec2" data = "confidential" }
        }

        """
        let existingControls = """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """
        app.project.put(architecture, at: "/project/threatmodel/s.arch")
        app.project.put(existingControls, at: "/project/threatmodel/s.controls")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))

        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let written = try #require(app.project.text(at: "/project/threatmodel/s.controls"))
        #expect(written.contains("recommendation \"Deny reads of /dev/rdisk**\""))
    }

    @Test func aStaleAnswerKeepsItsRecommendation() throws {
        let architectureRaisingTheThreat = """
        system "S" {
          component "c1" { technology = "aws-ec2" data = "confidential" }
        }
        """
        let architectureWithNoSuchComponent = """
        system "S" {
        }
        """
        let controlsWithRecommendation = """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """
        let compile = CompileControls(
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        )

        // A person adds a recommendation while the architecture still raises
        // the threat.
        guard case .compiled(let firstText, _, _, _, _) = compile.execute(
            CompileControlsRequest(
                architectureText: architectureRaisingTheThreat,
                controlsText: controlsWithRecommendation
            )
        ) else {
            Issue.record("the first compile refused the file")
            return
        }

        // The component leaves the architecture, so the threat is no longer
        // raised, and the answer moves into a stale block.
        guard case .compiled(let secondText, _, _, let stale, _) = compile.execute(
            CompileControlsRequest(
                architectureText: architectureWithNoSuchComponent,
                controlsText: firstText
            )
        ) else {
            Issue.record("the second compile refused the file")
            return
        }

        #expect(stale > 0)
        #expect(secondText.contains("stale threat \"credential-theft\""))
        #expect(secondText.contains("recommendation \"Deny reads of /dev/rdisk**\""))
    }
}
