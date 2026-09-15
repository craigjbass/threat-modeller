import Testing
import ThreatModelKit
import TestSupport

/// What an index holds, and what the application does with it.
@Suite("The library index")
struct LibraryIndexTests {
    private let index = """
    {
      "version": 1,
      "libraries": [
        {
          "label": "acme",
          "name": "Acme Platform",
          "description": "Acme's own services, and the threats they carry.",
          "repository": "https://example.internal/acme/threat-library",
          "tags": ["v1.1.0", "v1.2.0"],
          "homepage": "https://acme.example"
        },
        {
          "label": "beta",
          "name": "Beta Tooling",
          "repository": "https://example.internal/beta/library"
        }
      ]
    }
    """

    private func app(with text: String? = nil) -> TestDependencies {
        let app = TestDependencies()
        app.libraryIndex.put(text ?? index, at: ProjectConvention.defaultLibraryIndex)
        return app
    }

    private func read(_ app: TestDependencies, repository: String? = nil) -> ReadLibraryIndexResponse {
        app.readLibraryIndex().execute(ReadLibraryIndexRequest(repository: repository))
    }

    @Test func listsWhatTheIndexHolds() throws {
        guard case .read(let libraries) = read(app()) else {
            Issue.record("expected the index to be read")
            return
        }

        #expect(libraries.map(\.label) == ["acme", "beta"])
        #expect(libraries[0].name == "Acme Platform")
        #expect(libraries[0].repository == "https://example.internal/acme/threat-library")
        #expect(libraries[0].homepage == "https://acme.example")
    }

    /// The tag *Add* offers is the newest the entry states, by version.
    @Test func offersTheNewestTagTheEntryStates() throws {
        guard case .read(let libraries) = read(app()) else { return }

        #expect(libraries[0].newestTag == "v1.2.0")
        #expect(libraries[1].newestTag == nil)
    }

    @Test func narrowsByName() {
        let libraries = [
            IndexedLibrary(label: "acme", name: "Acme Platform", repository: "a"),
            IndexedLibrary(
                label: "beta",
                name: "Beta Tooling",
                description: "Kubernetes and its friends",
                repository: "b"
            )
        ]

        #expect(LibraryIndex.narrow(libraries, to: "acme").map(\.label) == ["acme"])
        #expect(LibraryIndex.narrow(libraries, to: "kubernetes").map(\.label) == ["beta"])
        #expect(LibraryIndex.narrow(libraries, to: "").count == 2)
        #expect(LibraryIndex.narrow(libraries, to: "nothing").isEmpty)
    }

    @Test func refusesAnIndexOfAVersionItDoesNotRead() {
        let app = app(with: "{ \"version\": 99, \"libraries\": [] }")

        guard case .cannotRead(let reason) = read(app) else {
            Issue.record("expected the index to be refused")
            return
        }
        #expect(reason.contains("version 99"))
    }

    @Test func refusesAFileThatIsNotAnIndex() {
        let app = app(with: "not json at all")

        guard case .cannotRead(let reason) = read(app) else {
            Issue.record("expected the index to be refused")
            return
        }
        #expect(reason.contains("is not an index"))
    }

    /// A machine with no network says what went wrong and leaves the sheet
    /// working.
    @Test func saysWhatWentWrongWithNoNetwork() {
        let app = TestDependencies()
        app.libraryIndex.refuse(
            .cannotRead(reason: "fatal: unable to access: Could not resolve host"),
            at: ProjectConvention.defaultLibraryIndex
        )

        guard case .cannotRead(let reason) = read(app) else {
            Issue.record("expected the read to fail")
            return
        }
        #expect(reason.contains("Could not resolve host"))
    }

    @Test func readsAnIndexAPersonNames() throws {
        let app = TestDependencies()
        app.libraryIndex.put(index, at: "https://example.internal/our-index")

        guard case .read(let libraries) = read(app, repository: "https://example.internal/our-index")
        else {
            Issue.record("expected the index to be read")
            return
        }
        #expect(libraries.isEmpty == false)
        #expect(app.libraryIndex.reads == ["https://example.internal/our-index"])
    }

    /// Nothing reads an index until a person asks.
    @Test func nothingReadsTheIndexOnItsOwn() {
        let app = app()

        _ = app.listLibraries().execute(ListLibrariesRequest(root: "/work"))

        #expect(app.libraryIndex.reads.isEmpty)
    }

    @Test func anEntryWithNoTagsIsStillListed() throws {
        guard case .read(let libraries) = read(app()) else { return }

        #expect(libraries[1].tags.isEmpty)
        #expect(libraries[1].label == "beta")
    }
}
