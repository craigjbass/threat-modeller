import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Bringing ATT&CK onto this machine from the window.
@MainActor
@Suite("Synchronising ATT&CK from the window")
struct AttackSynchroniseTests {
    private static let bundle = """
    {
      "type": "bundle",
      "objects": [
        {
          "type": "intrusion-set",
          "id": "intrusion-set--1",
          "name": "FIN7",
          "external_references": [
            { "source_name": "mitre-attack", "external_id": "G0046" }
          ]
        },
        {
          "type": "attack-pattern",
          "id": "attack-pattern--1",
          "name": "Phishing",
          "external_references": [
            { "source_name": "mitre-attack", "external_id": "T1566" }
          ]
        },
        {
          "type": "relationship",
          "relationship_type": "uses",
          "source_ref": "intrusion-set--1",
          "target_ref": "attack-pattern--1"
        }
      ]
    }
    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        useCases.attackDownloader.put(
            Data(Self.bundle.utf8),
            at: AttackRelease.address(of: AttackRelease.default)
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    /// While it runs the window says a synchronise is running, with its size,
    /// and not "Reading the project\u{2026}".
    @Test func whileItRunsTheWindowSaysSo() async {
        let (session, useCases) = await aProject()
        useCases.attackDownloader.hold()

        let running = Task { await session.synchroniseAttack() }
        while session.loading == nil { await Task.yield() }

        #expect(session.loading == .synchronisingAttack)
        #expect(session.loading?.says.contains("ATT&CK") == true)
        #expect(session.loading?.says.contains("53 MB") == true)

        useCases.attackDownloader.release()
        await running.value
        // A synchronise that worked starts a reload, and the reload has
        // stages of its own, so the test waits it out.
        await session.settle()
        #expect(session.loading == nil)
    }

    /// What the machine holds is readable at any time, not for four seconds.
    @Test func whatTheMachineHoldsIsReadableAtAnyTime() async {
        let (session, useCases) = await aProject()
        #expect(session.attackHolding == .nothingHeld)

        await session.synchroniseAttack()

        #expect(
            session.attackHolding
                == .held(
                    tag: AttackRelease.default,
                    groups: 1,
                    techniques: 1,
                    writtenAt: useCases.attackData.now
                )
        )
    }

    /// A failed synchronise stays on screen after the message wait ends, and
    /// goes when a person dismisses it.
    @Test func aFailedSynchroniseStaysUntilDismissed() async {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        useCases.attackDownloader.refuse(
            .curlIsNotInstalled,
            at: AttackRelease.address(of: AttackRelease.default)
        )
        let timer = FakeCoalescer()
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults(),
            messageTimer: timer
        )
        await session.open(root: "/work")

        await session.synchroniseAttack()

        // The failure states what to do about it.
        #expect(session.errorMessage?.contains("try again") == true)
        // The wait that clears a message ends, and the failure is still there.
        timer.fire()
        #expect(session.errorMessage != nil)

        session.dismissDiagnostics()
        #expect(session.errorMessage == nil)
    }

    /// The question states what the data is for, not only its size.
    @Test func theQuestionStatesWhatTheDataIsFor() async {
        let (session, _) = await aProject()

        let question = session.attackSynchroniseQuestion

        #expect(question.contains("technique"))
        #expect(question.contains("threat actors"))
    }

    /// The question states the tag, the address and the size.
    @Test func theQuestionStatesWhatItWillDo() async {
        let (session, _) = await aProject()

        let question = session.attackSynchroniseQuestion

        #expect(question.contains(AttackRelease.default))
        #expect(question.contains("attack-stix-data"))
        #expect(question.contains("53 MB"))
    }

    @Test func aSynchroniseWritesTheDataAndTheLockFile() async throws {
        let (session, useCases) = await aProject()

        await session.synchroniseAttack()

        #expect(useCases.attackData.read(fileName: AttackDataLocation.groupsFileName) != nil)
        #expect(useCases.project.text(at: "/work/threatmodel/\(AttackLock.fileName)") != nil)
        #expect(session.errorMessage == nil)
        #expect(session.loading == nil)
    }

    @Test func aSynchroniseThatFailsSaysWhy() async {
        let (session, useCases) = await aProject()
        useCases.attackDownloader.refuse(
            .curlIsNotInstalled,
            at: AttackRelease.address(of: AttackRelease.default)
        )

        await session.synchroniseAttack()

        #expect(session.errorMessage?.contains("curl is not installed") == true)
    }

    /// The window reaches the network only while a person is synchronising.
    @Test func openingDrawingAndSavingReachNoNetwork() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.add(technologyId: "aws-rds", x: 400, y: 0)
        await session.save()
        session.compileReport()

        // No network call. A report reads `techniques.json` on the machine to
        // print a technique's name, which is a local file and not a fetch.
        #expect(useCases.attackDownloader.downloads.isEmpty)
        #expect(useCases.attackData.reads.contains(AttackDataLocation.groupsFileName) == false)
    }

    @Test func theTagIsTheOneTheProjectStates() async throws {
        let (session, useCases) = await aProject()
        useCases.project.put(
            """
            {
              "bundle" : "enterprise-attack/enterprise-attack-18.0.json",
              "files" : { },
              "repository" : "mitre-attack/attack-stix-data",
              "tag" : "v18.0"
            }
            """,
            at: "/work/threatmodel/\(AttackLock.fileName)"
        )

        #expect(session.attackTag == "v18.0")
        #expect(session.attackSynchroniseQuestion.contains("v18.0"))
    }
}
