import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// A technology one system defines, moved where every system reads it.
@Suite("Moving a technology into a library")
struct MoveTechnologyToLibraryTests {
    private let app = TestDependencies()

    private func drawn() -> String {
        app.project.put(
            "system \"Payments\" { }",
            at: "/work/threatmodel/payments.arch"
        )
        guard case .created(let technologyId) = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Our Ledger",
                categoryId: "database",
                description: "The ledger we wrote ourselves",
                threatIds: ["misconfiguration"],
                enforcesEncryption: true,
                controls: ["Every write is signed"]
            )
        ) else { return "" }
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "internal")
        )
        return technologyId
    }

    private func move(_ technologyId: String, into label: String = "acme") -> MoveTechnologyToLibraryResponse {
        app.moveTechnologyToLibrary().execute(
            MoveTechnologyToLibraryRequest(
                root: "/work",
                technologyId: technologyId,
                libraryLabel: label
            )
        )
    }

    @Test func writesTheTechnologyIntoTheProjectsLibrary() throws {
        let technologyId = drawn()

        guard case .moved(let newId, let path) = move(technologyId) else {
            Issue.record("expected the technology to move")
            return
        }

        #expect(path == "/work/threatmodel/library/acme.lib")
        let written = try #require(app.project.text(at: path))
        let library = try #require(HclLibrarySource().read(written).source)
        #expect(library.label == "acme")
        #expect(library.technologies.first?.name == "Our Ledger")
        #expect(library.technologies.first?.controlDescriptions == ["Every write is signed"])
        #expect(newId == "acme-\(library.technologies[0].id)")
    }

    @Test func theModelNoLongerDefinesIt() {
        let technologyId = drawn()

        _ = move(technologyId)

        #expect(app.modelStore.current().customTechnologies.isEmpty)
    }

    @Test func everyComponentNamesTheLibrarysIdentifier() throws {
        let technologyId = drawn()

        guard case .moved(let newId, _) = move(technologyId) else { return }

        #expect(app.modelStore.current().components.allSatisfy {
            $0.technologyId == TechnologyId(newId)
        })
    }

    /// The library the project holds is read by every system in it, so the
    /// technology is stated once and read by both.
    @Test func everySystemInTheProjectReadsIt() throws {
        let technologyId = drawn()
        app.project.put(
            "system \"Reporting\" { }",
            at: "/work/threatmodel/reporting.arch"
        )
        guard case .moved(let newId, _) = move(technologyId) else { return }

        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the library to load")
            return
        }
        app.useLibraries(libraries)

        #expect(app.catalogueInUse.findById(TechnologyId(newId))?.name == "Our Ledger")
    }

    @Test func refusesATechnologyTheModelDoesNotDefine() {
        _ = drawn()

        #expect(move("not-a-technology") == .unknownTechnology)
    }

    @Test func refusesToWriteTheSameTechnologyTwice() throws {
        let technologyId = drawn()
        guard case .moved(let newId, _) = move(technologyId) else { return }

        // The same technology, defined again under the same name, meets the
        // one already in the library.
        guard case .created(let again) = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Our Ledger, again",
                categoryId: "database",
                description: "",
                threatIds: [],
                enforcesEncryption: false
            )
        ) else { return }
        // Give it the identifier the library already holds.
        _ = app.modelStore.mutate { model in
            let index = model.customTechnologies.firstIndex { $0.id.value == again }
            if let index {
                let held = model.customTechnologies[index]
                model.customTechnologies[index] = CustomTechnology(
                    id: TechnologyId(newId.replacingOccurrences(of: "acme-", with: "custom-")),
                    name: held.name,
                    category: held.category,
                    description: held.description,
                    threatIds: held.threatIds
                )
            }
        }

        let response = move(newId.replacingOccurrences(of: "acme-", with: "custom-"))

        #expect(response == .alreadyInTheLibrary(technologyId: newId))
    }

    @Test func addsToALibraryTheProjectAlreadyHolds() throws {
        app.project.put(
            """
            library "acme" {
              name = "Acme Platform"

              technology "cribl-stream" {
                name     = "Cribl Stream"
                category = "compute"
              }
            }
            """,
            at: "/work/threatmodel/library/acme.lib"
        )
        let technologyId = drawn()

        guard case .moved(_, let path) = move(technologyId) else { return }

        let library = try #require(HclLibrarySource().read(app.project.text(at: path) ?? "").source)
        #expect(library.displayName == "Acme Platform")
        #expect(library.technologies.map(\.name) == ["Cribl Stream", "Our Ledger"])
    }

    @Test func costsOneUndo() throws {
        let technologyId = drawn()

        _ = move(technologyId)
        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(app.modelStore.current().customTechnologies.count == 1)
        #expect(app.modelStore.current().components.first?.technologyId
            == TechnologyId(technologyId))
    }
}
