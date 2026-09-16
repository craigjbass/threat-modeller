import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Answers for threats the architecture no longer raises")
struct StaleAnswerTests {
    private let app = TestDependencies()

    /// A project whose controls file answers a threat on a component the
    /// architecture has since lost, which is what makes an answer stale.
    private func aProjectWithAStaleAnswer() {
        app.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        app.project.put(
            """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Something a person answered" { status = "implemented" }
              }
            }
            """,
            at: "/work/threatmodel/payments.controls"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
    }

    private func stale() -> [StaleAnswer] {
        guard case .listed(let answers) = app.listStaleAnswers().execute(
            ListStaleAnswersRequest(root: "/work", systemName: "payments")
        ) else { return [] }
        return answers
    }

    @Test func listsWhatTheArchitectureNoLongerRaises() {
        aProjectWithAStaleAnswer()

        let answers = stale()

        #expect(answers.count == 1)
        #expect(answers.first?.threatId == "t-old")
        #expect(answers.first?.sourceKind == "component")
        #expect(answers.first?.sourceId == "gone")
    }

    @Test func listsNothingForAProjectWithNoStaleAnswer() {
        app.project.put(
            "system \"Payments\" { component \"api\" { technology = \"aws-ec2\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        #expect(stale().isEmpty)
    }

    /// Nothing deletes a stale answer on its own. A person deletes it, and
    /// this is how.
    @Test func removesOneAPersonChoseToDelete() throws {
        aProjectWithAStaleAnswer()

        let response = app.removeStaleAnswer().execute(
            RemoveStaleAnswerRequest(
                root: "/work",
                systemName: "payments",
                threatId: "t-old",
                sourceKind: "component",
                sourceId: "gone"
            )
        )

        #expect(response == .removed)
        #expect(stale().isEmpty)
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("t-old") == false)
    }

    @Test func saysSoWhenNoSuchAnswerIsThere() {
        aProjectWithAStaleAnswer()

        let response = app.removeStaleAnswer().execute(
            RemoveStaleAnswerRequest(
                root: "/work",
                systemName: "payments",
                threatId: "t-nothing",
                sourceKind: "component",
                sourceId: "gone"
            )
        )

        #expect(response == .noSuchAnswer)
        #expect(stale().count == 1)
    }

    // MARK: deleting every stale answer at once

    /// One read, one write, three stanzas gone, and the answer that is still
    /// raised is written back byte for byte.
    @Test func removesEveryStaleAnswerInOneCall() throws {
        app.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        let controls = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            severity = "critical"
            score    = 16

            control "Kept, and still raised" { status = "implemented" }
          }

          stale threat "t-old" on component "gone" {
            control "Answered" { status = "implemented" }
          }

          stale threat "t-older" on component "also-gone" {
            control "Answered too" { status = "implemented" }
          }

          stale threat "t-oldest" on component "gone-as-well" {
            control "Answered as well" { status = "implemented" }
          }
        }
        """
        app.project.put(controls, at: "/work/threatmodel/payments.controls")
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let response = app.removeStaleAnswers().execute(
            RemoveStaleAnswersRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .removed(count: 3))
        #expect(stale().isEmpty)
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("stale") == false)
        let source = try #require(HclControlsSource().read(written).source)
        let kept = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(kept.controls.first?.description == "Kept, and still raised")
        #expect(kept.isStale == false)
    }

    @Test func removesNothingWhenTheSystemHoldsNoStaleAnswer() {
        app.project.put(
            "system \"Payments\" { component \"api\" { technology = \"aws-ec2\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        let before = app.project.text(at: "/work/threatmodel/payments.controls")

        let response = app.removeStaleAnswers().execute(
            RemoveStaleAnswersRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .removed(count: 0))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == before)
    }

    @Test func removesNoStaleAnswersWhenTheSystemDoesNotExist() {
        aProjectWithAStaleAnswer()

        let response = app.removeStaleAnswers().execute(
            RemoveStaleAnswersRequest(root: "/work", systemName: "gone")
        )

        #expect(response == .noSuchSystem)
        #expect(stale().count == 1)
    }

    /// Deleting one stale answer leaves every other answer alone.
    @Test func leavesTheAnswersThatAreStillRaised() throws {
        app.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        app.project.put(
            """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Answered" { status = "implemented" }
              }

              stale threat "t-older" on component "also-gone" {
                control "Answered too" { status = "implemented" }
              }
            }
            """,
            at: "/work/threatmodel/payments.controls"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        _ = app.removeStaleAnswer().execute(
            RemoveStaleAnswerRequest(
                root: "/work",
                systemName: "payments",
                threatId: "t-old",
                sourceKind: "component",
                sourceId: "gone"
            )
        )

        #expect(stale().map(\.threatId) == ["t-older"])
    }
}
