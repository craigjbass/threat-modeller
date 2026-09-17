import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// What the layout search publishes for a preview to draw.
///
/// The search holds geometry alone, so the use case that runs the search
/// states the subject: the names, the shapes and the flows a picture needs.
@Suite("The subject the layout search draws")
struct LayoutSubjectTests {
    private let architecture = """
        system "Payments" {
          zone "app" {
            kind = "private"

            component "api" {
              technology = "aws-ec2"
              name = "Orders API"
            }

            component "db" {
              technology = "aws-rds"
              name = "Orders store"
            }
          }

          flow api -> db
        }
        """

    @Test func importStatesTheSubjectBeforeTheFirstReport() {
        let app = TestDependencies()
        let progress = LayoutProgress()
        let heard = HeardSubjects()
        progress.listen { _ in heard.add(progress.subject) }

        _ = ImportArchitecture(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            sources: HclArchitectureSource(),
            attackTreeSources: HclAttackTreeSource(),
            layout: LayOutModel(progress: progress),
            progress: progress
        ).execute(ImportArchitectureRequest(text: architecture))

        let atTheFirstReport = heard.all().first ?? nil
        #expect(atTheFirstReport?.components.map(\.name) == ["Orders API", "Orders store"])
        #expect(atTheFirstReport?.connections.map(\.id) == ["api->db"])
        #expect(atTheFirstReport?.zones.map(\.id) == ["app"])
    }

    /// The preview draws icons, so the subject carries what an icon is
    /// chosen by. A subject built from a source alone could not.
    @Test func theSubjectCarriesTheProviderAndTheCategory() {
        let app = TestDependencies()
        let progress = LayoutProgress()
        progress.listen { _ in }

        _ = ImportArchitecture(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            sources: HclArchitectureSource(),
            attackTreeSources: HclAttackTreeSource(),
            layout: LayOutModel(progress: progress),
            progress: progress
        ).execute(ImportArchitectureRequest(text: architecture))

        let api = progress.subject?.components.first { $0.id == "api" }
        #expect(api?.providerId.isEmpty == false)
        #expect(api?.categoryId.isEmpty == false)
    }

    /// Lay Out on an open system draws the same preview as opening one.
    @Test func layingOutAgainStatesTheSubject() {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architecture))

        let progress = LayoutProgress()
        _ = ArrangeDiagram(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            layout: LayOutModel(progress: progress),
            progress: progress
        ).execute(ArrangeDiagramRequest())

        #expect(progress.subject?.components.map(\.name) == ["Orders API", "Orders store"])
    }

    /// One mapping draws the canvas and the preview, so a component cannot
    /// read one way in the picture and another on the canvas.
    @Test func theSubjectMatchesWhatTheCanvasDraws() {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architecture))

        let progress = LayoutProgress()
        _ = ArrangeDiagram(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            layout: LayOutModel(progress: progress),
            progress: progress
        ).execute(ArrangeDiagramRequest())
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())

        // The subject is stated before the search moves anything, so the
        // names, the shapes and the flows match and only the coordinates
        // differ.
        #expect(progress.subject?.components.map(\.shapeId) == canvas.components.map(\.shapeId))
        #expect(progress.subject?.connections == canvas.connections)
        #expect(progress.subject?.zones.map(\.name) == canvas.zones.map(\.name))
    }

    /// The compile path lays nothing out and draws nothing, so it states no
    /// subject and keeps the coordinates it always had.
    @Test func animportWithNoLayoutLeavesEveryComponentAtTheOrigin() {
        let app = TestDependencies()

        _ = ImportArchitecture(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            sources: HclArchitectureSource(),
            attackTreeSources: HclAttackTreeSource(),
            layout: nil
        ).execute(ImportArchitectureRequest(text: architecture))

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.components.allSatisfy { $0.x == 0 && $0.y == 0 })
        #expect(canvas.zones.allSatisfy { $0.width == 0 && $0.height == 0 })
    }
}

/// Collects what a listener read. The search may report from another thread,
/// so the list takes a lock.
private final class HeardSubjects: @unchecked Sendable {
    private let lock = NSLock()
    private var subjects: [LayoutSubject?] = []

    func add(_ subject: LayoutSubject?) {
        lock.lock()
        subjects.append(subject)
        lock.unlock()
    }

    func all() -> [LayoutSubject?] {
        lock.lock()
        defer { lock.unlock() }
        return subjects
    }
}
