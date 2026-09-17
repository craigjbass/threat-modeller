import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Searching the synchronised ATT&CK data by id and by name.
///
/// Issue #148 and
/// `docs/superpowers/specs/2026-09-17-mitre-id-field-design.md`: the window
/// picks a MITRE id from this list rather than taking one typed from memory.
@Suite("The synchronised ATT&CK data, searched")
struct SearchAttackDataTests {
    private let techniques = """
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
          "id": "T1203",
          "name": "Exploitation for Client Execution",
          "tactics": ["execution"],
          "subtechnique": false
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

    private let groups = """
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
        },
        {
          "id": "fin7",
          "attackId": "G0046",
          "name": "FIN7",
          "aliases": ["Carbon Spider"],
          "description": "A financially motivated group.",
          "techniques": ["T1566"],
          "techniquesViaSoftware": []
        }
      ]
    }
    """

    private func app(withData: Bool = true) -> TestDependencies {
        let app = TestDependencies()
        if withData {
            app.attackData.put(techniques, fileName: AttackDataLocation.techniquesFileName)
            app.attackData.put(groups, fileName: AttackDataLocation.groupsFileName)
        }
        return app
    }

    private func search(
        _ app: TestDependencies,
        _ text: String,
        kind: AttackSearchKind = .technique,
        limit: Int = 12
    ) -> SearchAttackDataResponse {
        app.searchAttackData()
            .execute(SearchAttackDataRequest(text: text, kind: kind, limit: limit))
    }

    // MARK: by name

    @Test func namesTheTechniqueTheWordsStart() {
        let response = search(app(), "exploit pub")

        #expect(response.rows.first?.id == "T1190")
        #expect(response.rows.first?.name == "Exploit Public-Facing Application")
        #expect(response.holdsData)
    }

    /// A name the words start beats a name that holds the words further in.
    @Test func aNameTheWordsStartSortsFirst() {
        let response = search(app(), "command")

        #expect(response.rows.map(\.id) == ["T1059", "T1059.003"])
    }

    // MARK: by id

    @Test func listsTheSubTechniquesOfATechniqueId() {
        let response = search(app(), "t1059.0")

        #expect(response.rows.map(\.id) == ["T1059.001", "T1059.003"])
        #expect(response.rows.filter(\.isSubTechnique).count == response.rows.count)
    }

    @Test func theWholeIdSortsFirst() {
        let response = search(app(), "T1059")

        #expect(response.rows.first?.id == "T1059")
        #expect(response.rows.map(\.id) == ["T1059", "T1059.001", "T1059.003"])
    }

    // MARK: groups

    @Test func findsAGroupByItsIdAndByItsName() {
        #expect(search(app(), "G0016", kind: .group).rows.first?.name == "APT29")
        #expect(search(app(), "apt29", kind: .group).rows.first?.id == "G0016")
        #expect(search(app(), "cozy", kind: .group).rows.first?.id == "G0016")
    }

    // MARK: what the field needs

    @Test func takesNoRowForWordsNothingMatches() {
        #expect(search(app(), "nothing matches this").rows.isEmpty)
    }

    @Test func statesNoDataWhenNothingIsSynchronised() {
        let response = search(app(withData: false), "T1190")

        #expect(response.rows.isEmpty)
        #expect(response.holdsData == false)
    }

    @Test func takesNoMoreRowsThanTheLimit() {
        #expect(search(app(), "t", limit: 2).rows.count == 2)
    }

    /// Empty words take no row, so a field nobody has typed into draws no
    /// list. It still states whether this machine holds the data, because the
    /// field says how to synchronise before anybody types.
    @Test func emptyWordsTakeNoRow() {
        let response = search(app(), "   ")

        #expect(response.rows.isEmpty)
        #expect(response.holdsData)
    }

    /// The search reads each file once, however many times a person types.
    @Test func readsTheFileOnce() {
        let app = app()

        _ = search(app, "exploit")
        _ = search(app, "exploit pub")
        _ = search(app, "t1059")

        #expect(app.attackData.reads == [AttackDataLocation.techniquesFileName])
    }
}
