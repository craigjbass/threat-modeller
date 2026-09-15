import AppKit
import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A pasteboard a test drives, so no test changes what the person running it
/// had copied.
@MainActor
final class FakeClipboard: Clipboard {
    private(set) var held: String?
    private(set) var png: Data?
    private(set) var pdf: Data?

    func put(text: String) {
        held = text
        png = nil
        pdf = nil
    }

    func text() -> String? { held }

    func put(png: Data, pdf: Data) {
        held = nil
        self.png = png
        self.pdf = pdf
    }
}

/// What every pasteboard does, whichever one it is.
@MainActor
@Suite("The clipboard")
struct ClipboardTests {
    /// The contract both pasteboards keep.
    private func contract(_ clipboard: some Clipboard) {
        clipboard.put(text: "a threat model")
        #expect(clipboard.text() == "a threat model")

        clipboard.put(text: "something else")
        #expect(clipboard.text() == "something else")

        clipboard.put(png: Data([0x89, 0x50]), pdf: Data([0x25, 0x50]))
        #expect(clipboard.text() == nil)
    }

    @Test func theFakeKeepsTheContract() {
        contract(FakeClipboard())
    }

    /// The machine's own pasteboard, kept and put back, so the suite leaves
    /// what the person had copied exactly as it was.
    @Test func theSystemPasteboardKeepsTheContract() {
        let held = NSPasteboard.general.string(forType: .string)
        defer {
            NSPasteboard.general.clearContents()
            if let held { NSPasteboard.general.setString(held, forType: .string) }
        }

        contract(SystemClipboard())
    }

    @Test func copyAsImageWritesBothFlavours() throws {
        let clipboard = FakeClipboard()
        let session = ThreatModelSession(useCases: TestDependencies(), clipboard: clipboard)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        #expect(session.copyDiagramAsImage())

        let png = try #require(clipboard.png)
        let pdf = try #require(clipboard.pdf)
        #expect(png.starts(with: [0x89, 0x50, 0x4E, 0x47]))
        #expect(pdf.starts(with: Array("%PDF".utf8)))
        #expect(clipboard.text() == nil)
    }

    @Test func copyAsImageCopiesNothingFromAnEmptyDiagram() {
        let clipboard = FakeClipboard()
        let session = ThreatModelSession(useCases: TestDependencies(), clipboard: clipboard)

        #expect(session.copyDiagramAsImage() == false)
        #expect(clipboard.png == nil)
    }

    /// A selection crops the picture to what is selected, with a margin.
    @Test func copyAsImageCropsToTheSelection() throws {
        let clipboard = FakeClipboard()
        let session = ThreatModelSession(useCases: TestDependencies(), clipboard: clipboard)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 2000, y: 1200)
        let ids = session.canvas.components.map(\.id)

        #expect(session.copyDiagramAsImage(componentIds: [ids[0]], zoneIds: []))
        let cropped = try #require(clipboard.png)

        #expect(session.copyDiagramAsImage())
        let whole = try #require(clipboard.png)

        #expect(cropped.count < whole.count)
    }

    @Test func theCropHoldsEveryElementAndTheMargin() {
        let rect = SelectionBounds.rect(
            components: [(x: 100, y: 100, width: 160, height: 72)],
            zones: [(x: 0, y: 0, width: 400, height: 300)]
        )

        #expect(
            rect == CGRect(
                x: -SelectionBounds.margin,
                y: -SelectionBounds.margin,
                width: 400 + SelectionBounds.margin * 2,
                height: 300 + SelectionBounds.margin * 2
            )
        )
    }

    @Test func nothingSelectedHasNoCrop() {
        #expect(SelectionBounds.rect(components: [], zones: []) == nil)
    }

    @Test func aCopyPutsTheModelOnTheClipboardAndNotOnTheMachines() throws {
        let clipboard = FakeClipboard()
        let session = ThreatModelSession(useCases: TestDependencies(), clipboard: clipboard)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let placed = try #require(session.canvas.components.first)

        session.copySelection(componentIds: [placed.id], zoneIds: [])

        #expect(clipboard.text()?.isEmpty == false)
    }
}
