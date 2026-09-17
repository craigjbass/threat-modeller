import Foundation
import Observation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The one control every MITRE ATT&CK id goes through.
///
/// Issue #148 and
/// `docs/superpowers/specs/2026-09-17-mitre-id-field-design.md`: a person
/// searches the synchronised matrix by id and by name, picks a row, and the
/// pick becomes a token. An id the matrix lacks is kept and marked.
@MainActor
@Suite("The MITRE id field")
struct MitreIdFieldTests {
    // MARK: the data a test states

    private static let techniques = """
    {
      "release": "v19.2",
      "techniques": [
        {
          "id": "T1190",
          "name": "Exploit Public-Facing Application",
          "tactics": ["initial-access"],
          "subtechnique": false
        },
        {
          "id": "T1059",
          "name": "Command and Scripting Interpreter",
          "tactics": ["execution"],
          "subtechnique": false
        },
        {
          "id": "T1059.001",
          "name": "PowerShell",
          "tactics": ["execution"],
          "subtechnique": true
        },
        {
          "id": "T1059.003",
          "name": "Windows Command Shell",
          "tactics": ["execution"],
          "subtechnique": true
        },
        {
          "id": "T1078",
          "name": "Valid Accounts",
          "tactics": ["defense-evasion"],
          "subtechnique": false
        }
      ]
    }
    """

    private static let groups = """
    {
      "release": "v19.2",
      "groups": [
        {
          "id": "apt29",
          "attackId": "G0016",
          "name": "APT29",
          "aliases": ["Cozy Bear"],
          "description": "A state group.",
          "techniques": ["T1078"],
          "techniquesViaSoftware": []
        }
      ]
    }
    """

    /// What one field writes, so a test reads the ids back without a window.
    @Observable
    final class Held {
        var ids: [String]

        init(_ ids: [String] = []) { self.ids = ids }

        var binding: Binding<[String]> {
            Binding(get: { self.ids }, set: { self.ids = $0 })
        }
    }

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    /// A project with a system open, and the ATT&CK data this machine holds.
    private func aProject(withData: Bool = true) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        if withData {
            useCases.attackData.put(
                Self.techniques,
                fileName: AttackDataLocation.techniquesFileName
            )
            useCases.attackData.put(Self.groups, fileName: AttackDataLocation.groupsFileName)
        }
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func aField(
        _ session: ThreatModelSession,
        held: Held,
        typed: String = "",
        kind: AttackSearchKind = .technique,
        allowsMany: Bool = true
    ) -> MitreIdField {
        MitreIdField(
            title: "Techniques",
            identifier: "test-mitre-ids",
            kind: kind,
            allowsMany: allowsMany,
            ids: held.binding,
            search: { text, kind in session.searchAttackData(text, kind: kind) },
            synchronise: session.onSynchroniseAttack,
            typed: typed
        )
    }

    // MARK: the search

    @Test func typingWordsListsTheTechniqueTheyNameFirst() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let field = aField(model, held: Held(), typed: "exploit pub")

        let first = try #require(field.rows.first)
        #expect(MitreIdField.label(of: first) == "T1190 Exploit Public-Facing Application")
    }

    @Test func typingAPartOfAnIdListsTheSubTechniques() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let field = aField(model, held: Held(), typed: "t1059.0")

        #expect(field.rows.map(\.id) == ["T1059.001", "T1059.003"])
    }

    @Test func pickingARowAddsTheIdAsAToken() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let held = Held()
        let field = aField(model, held: held, typed: "t1059.0")

        let first = try #require(field.rows.first)
        field.pick(first)

        #expect(held.ids == ["T1059.001"])
        #expect(field.isUnknown("T1059.001") == false)
        #expect(field.name(of: "T1059.001") == "PowerShell")
    }

    /// A token already held is not offered again, so nobody picks one twice.
    @Test func aRowAlreadyHeldIsNotOffered() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let field = aField(model, held: Held(["T1059.001"]), typed: "t1059.0")

        #expect(field.rows.map(\.id) == ["T1059.003"])
    }

    @Test func aSingleFieldHoldsOneToken() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let held = Held(["T1190"])
        let field = aField(model, held: held, typed: "t1078", allowsMany: false)

        field.pick(try #require(field.rows.first))

        #expect(held.ids == ["T1078"])
    }

    @Test func aTokenComesOff() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let held = Held(["T1190", "T1078"])
        let field = aField(model, held: held)

        field.remove("T1190")

        #expect(held.ids == ["T1078"])
    }

    // MARK: an id the matrix lacks

    @Test func keepsAnIdTheDataLacksAndMarksItUnknown() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let held = Held()
        let field = aField(model, held: held, typed: "T9999")

        #expect(field.rows.isEmpty)
        field.commitTyped()

        #expect(held.ids == ["T9999"])
        #expect(field.isUnknown("T9999"))
        #expect(field.says.contains("T9999"))
        #expect(field.says.contains("not in the synchronised matrix"))

        // The id the matrix lacks is written, so the file round trips.
        model.setLocalThreatActor(
            id: "contractor",
            name: "Third-party contractor",
            capability: "targeted",
            techniques: held.ids
        )
        await session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("[\"T9999\"]"))
    }

    // MARK: no data at all

    @Test func withNoDataTakesAnIdByHandAndOffersTheSynchroniseAction() async throws {
        let (session, _) = await aProject(withData: false)
        let model = try #require(session.model)
        let held = Held()
        let field = aField(model, held: held, typed: "T1190")

        #expect(field.holdsData == false)
        #expect(field.canSynchronise)
        #expect(field.says.contains("Synchronise"))

        field.commitTyped()

        #expect(held.ids == ["T1190"])
        // Nothing is marked unknown while this machine holds no matrix to
        // check an id against.
        #expect(field.isUnknown("T1190") == false)
    }

    // MARK: groups

    @Test func searchesTheGroupsByIdAndByName() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        #expect(aField(model, held: Held(), typed: "apt29", kind: .group).rows.first?.id == "G0016")
        #expect(aField(model, held: Held(), typed: "G0016", kind: .group).rows.first?.name == "APT29")
    }

    // MARK: no plain MITRE text box is left

    /// The application's own source directory.
    private static let source = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("threatmodeller")

    /// The placeholder words a plain MITRE text box states. A field added
    /// later fails this until it takes `MitreIdField`.
    private static let gone = [
        "Technique ids, separated by a comma",
        "Technique id",
        "MITRE id",
        "ATT&CK id",
        "Group id"
    ]

    @Test func noPlainTextBoxTakesAMitreId() throws {
        let files = try FileManager.default.subpathsOfDirectory(atPath: Self.source.path)
            .filter { $0.hasSuffix(".swift") }
        #expect(files.isEmpty == false, "no Swift file found under \(Self.source.path)")

        for file in files {
            let text = try String(
                contentsOf: Self.source.appendingPathComponent(file),
                encoding: .utf8
            )
            for line in text.split(separator: "\n") where line.contains("TextField(") {
                for word in Self.gone {
                    #expect(
                        line.contains(word) == false,
                        Comment(rawValue: "\(file) takes a MITRE id in a plain text box: \(line)")
                    )
                }
            }
        }
    }
}
