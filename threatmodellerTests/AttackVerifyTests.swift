import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Checking the ATT&CK data against the lock file from the window.
@MainActor
@Suite("Verifying ATT&CK from the window")
struct AttackVerifyTests {
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

    /// Data a synchronise wrote is the data the lock file states.
    @Test func dataTheLockFileStatesMatches() async {
        let (session, _) = await aProject()

        await session.synchroniseAttack()

        #expect(session.attackAgreement == .matches(tag: AttackRelease.default))
    }

    /// A file that drifted from the lock file is named.
    @Test func aDriftedFileIsNamed() async {
        let (session, useCases) = await aProject()
        await session.synchroniseAttack()

        useCases.attackData.put("drifted", fileName: AttackDataLocation.groupsFileName)

        #expect(
            session.attackAgreement
                == .doesNotMatch(
                    tag: AttackRelease.default,
                    fileName: AttackDataLocation.groupsFileName
                )
        )
    }

    /// A project that never synchronised states no release to check against.
    @Test func aProjectWithNoLockFileSaysSo() async {
        let (session, _) = await aProject()

        #expect(session.attackAgreement == .noLockFile)
    }
}
