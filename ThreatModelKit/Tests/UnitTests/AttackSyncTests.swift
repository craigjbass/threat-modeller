import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Bringing the ATT&CK matrix onto this machine.
@Suite("Synchronising ATT&CK")
struct AttackSyncTests {
    /// A small STIX bundle: two groups, two techniques, one tool.
    private var bundle: Data {
        let text = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "intrusion-set",
              "id": "intrusion-set--1",
              "name": "FIN7",
              "aliases": ["FIN7", "Carbon Spider"],
              "description": "FIN7 is a financially motivated threat group.\\n\\nMore words.",
              "external_references": [
                { "source_name": "mitre-attack", "external_id": "G0046" }
              ]
            },
            {
              "type": "intrusion-set",
              "id": "intrusion-set--2",
              "name": "Old Group",
              "revoked": true,
              "external_references": [
                { "source_name": "mitre-attack", "external_id": "G0002" }
              ]
            },
            {
              "type": "intrusion-set",
              "id": "intrusion-set--3",
              "name": "Quiet Crew",
              "external_references": [
                { "source_name": "mitre-attack", "external_id": "G0003" }
              ]
            },
            {
              "type": "attack-pattern",
              "id": "attack-pattern--1",
              "name": "Phishing",
              "kill_chain_phases": [
                { "kill_chain_name": "mitre-attack", "phase_name": "initial-access" }
              ],
              "external_references": [
                { "source_name": "mitre-attack", "external_id": "T1566" }
              ]
            },
            {
              "type": "attack-pattern",
              "id": "attack-pattern--2",
              "name": "Valid Accounts",
              "kill_chain_phases": [
                { "kill_chain_name": "mitre-attack", "phase_name": "defense-evasion" }
              ],
              "external_references": [
                { "source_name": "mitre-attack", "external_id": "T1078" }
              ]
            },
            {
              "type": "attack-pattern",
              "id": "attack-pattern--3",
              "name": "Gone",
              "x_mitre_deprecated": true,
              "external_references": [
                { "source_name": "mitre-attack", "external_id": "T9999" }
              ]
            },
            { "type": "tool", "id": "tool--1", "name": "Cobalt Strike" },
            {
              "type": "relationship",
              "relationship_type": "uses",
              "source_ref": "intrusion-set--1",
              "target_ref": "attack-pattern--1"
            },
            {
              "type": "relationship",
              "relationship_type": "uses",
              "source_ref": "intrusion-set--1",
              "target_ref": "tool--1"
            },
            {
              "type": "relationship",
              "relationship_type": "uses",
              "source_ref": "tool--1",
              "target_ref": "attack-pattern--2"
            }
          ]
        }
        """
        return Data(text.utf8)
    }

    private func app() -> TestDependencies {
        let app = TestDependencies()
        app.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        app.attackDownloader.put(bundle, at: AttackRelease.address(of: AttackRelease.default))
        return app
    }

    // MARK: the extraction

    @Test func readsTheGroupsAndTheTechniques() throws {
        let extracted = try AttackBundle.extract(bundle)

        #expect(extracted.groups.map(\.id) == ["fin7", "quiet-crew"])
        #expect(extracted.techniques.map(\.id) == ["T1078", "T1566"])
    }

    @Test func dropsWhatIsRevokedOrDeprecated() throws {
        let extracted = try AttackBundle.extract(bundle)

        #expect(extracted.groups.contains { $0.name == "Old Group" } == false)
        #expect(extracted.techniques.contains { $0.id == "T9999" } == false)
    }

    /// A group's own techniques and the techniques of the software it uses are
    /// two different claims, and the file states them apart.
    @Test func statesSoftwareTechniquesApartFromTheGroupsOwn() throws {
        let extracted = try AttackBundle.extract(bundle)
        let fin7 = try #require(extracted.groups.first { $0.id == "fin7" })

        #expect(fin7.techniques == ["T1566"])
        #expect(fin7.techniquesViaSoftware == ["T1078"])
    }

    @Test func aGroupWithNoTechniquePerformsNothing() throws {
        let extracted = try AttackBundle.extract(bundle)
        let quiet = try #require(extracted.groups.first { $0.id == "quiet-crew" })

        #expect(quiet.techniques.isEmpty)
    }

    @Test func refusesAFileThatIsNotABundle() {
        #expect(throws: AttackBundle.Fault.notAStixBundle) {
            try AttackBundle.extract(Data("not json".utf8))
        }
    }

    @Test func mintsTheGroupIdentifierFromTheName() {
        #expect(AttackBundle.identifier(of: "FIN7") == "fin7")
        #expect(AttackBundle.identifier(of: "Lazarus Group") == "lazarus-group")
        #expect(AttackBundle.identifier(of: "admin@338") == "admin-338")
    }

    // MARK: the synchronise

    @Test func writesBothFilesAndTheLockFile() throws {
        let app = app()

        let response = app.synchroniseAttack().execute(SynchroniseAttackRequest(root: "/work"))

        #expect(response == .synchronised(tag: AttackRelease.default, groups: 2, techniques: 2))
        #expect(app.attackData.read(fileName: AttackDataLocation.groupsFileName) != nil)
        #expect(app.attackData.read(fileName: AttackDataLocation.techniquesFileName) != nil)

        let lockText = try #require(app.project.text(at: "/work/threatmodel/\(AttackLock.fileName)"))
        let lock = try #require(AttackLock.read(lockText))
        #expect(lock.tag == AttackRelease.default)
        #expect(lock.repository == AttackRelease.repository)
        #expect(lock.files.count == 2)
    }

    @Test func takesTheTagAPersonNames() throws {
        let app = app()
        app.attackDownloader.put(bundle, at: AttackRelease.address(of: "v18.0"))

        let response = app.synchroniseAttack()
            .execute(SynchroniseAttackRequest(root: "/work", tag: "v18.0"))

        #expect(response == .synchronised(tag: "v18.0", groups: 2, techniques: 2))
        #expect(app.attackDownloader.downloads == [AttackRelease.address(of: "v18.0")])
    }

    /// A download that fails leaves what was there and says what failed.
    @Test func aFailedDownloadLeavesThePreviousDataInPlace() throws {
        let app = app()
        _ = app.synchroniseAttack().execute(SynchroniseAttackRequest(root: "/work"))
        let held = app.attackData.read(fileName: AttackDataLocation.groupsFileName)

        app.attackDownloader.refuse(
            .cannotRead(reason: "curl: (6) Could not resolve host"),
            at: AttackRelease.address(of: "v18.0")
        )
        let response = app.synchroniseAttack()
            .execute(SynchroniseAttackRequest(root: "/work", tag: "v18.0"))

        #expect(response == .cannotDownload(reason: "curl: (6) Could not resolve host"))
        #expect(app.attackData.read(fileName: AttackDataLocation.groupsFileName) == held)
    }

    @Test func aBundleThatDoesNotExtractLeavesThePreviousDataInPlace() throws {
        let app = app()
        _ = app.synchroniseAttack().execute(SynchroniseAttackRequest(root: "/work"))
        let held = app.attackData.read(fileName: AttackDataLocation.groupsFileName)

        app.attackDownloader.put(Data("not a bundle".utf8), at: AttackRelease.address(of: "v18.0"))
        let response = app.synchroniseAttack()
            .execute(SynchroniseAttackRequest(root: "/work", tag: "v18.0"))

        guard case .cannotExtract = response else {
            Issue.record("expected the extraction to fail, got \(response)")
            return
        }
        #expect(app.attackData.read(fileName: AttackDataLocation.groupsFileName) == held)
    }

    // MARK: the verify

    @Test func verifySaysTheDataMatchesTheLockFile() {
        let app = app()
        _ = app.synchroniseAttack().execute(SynchroniseAttackRequest(root: "/work"))

        #expect(
            app.verifyAttack().execute(VerifyAttackRequest(root: "/work"))
                == .matches(tag: AttackRelease.default)
        )
    }

    @Test func verifySaysWhenTheProjectStatesNoRelease() {
        #expect(app().verifyAttack().execute(VerifyAttackRequest(root: "/work")) == .noLockFile)
    }

    @Test func verifySaysWhenTheMachineHoldsNoData() throws {
        let app = app()
        _ = app.synchroniseAttack().execute(SynchroniseAttackRequest(root: "/work"))
        let lock = try #require(app.project.text(at: "/work/threatmodel/\(AttackLock.fileName)"))

        // Another machine: the project's lock file, and no data.
        let fresh = TestDependencies()
        fresh.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        fresh.project.put(lock, at: "/work/threatmodel/\(AttackLock.fileName)")

        #expect(
            fresh.verifyAttack().execute(VerifyAttackRequest(root: "/work"))
                == .notSynchronised(tag: AttackRelease.default)
        )
    }

    @Test func verifySaysWhichFileDoesNotMatch() {
        let app = app()
        _ = app.synchroniseAttack().execute(SynchroniseAttackRequest(root: "/work"))
        app.attackData.put("{}", fileName: AttackDataLocation.groupsFileName)

        #expect(
            app.verifyAttack().execute(VerifyAttackRequest(root: "/work"))
                == .doesNotMatch(
                    tag: AttackRelease.default,
                    fileName: AttackDataLocation.groupsFileName
                )
        )
    }
}
