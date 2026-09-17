import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A library's pathway mitigation states a description; the panel row now
/// draws it, where before the row named the mitigation and said nothing
/// about what it does.
@MainActor
@Suite("A pathway mitigation's description in the window")
struct PathwayMitigationDescriptionFlowTests {
    private func library(_ descriptionLine: String) -> String {
        """
        library "custom" {
          mitigation "custom-mitigation" {
            name           = "Custom Mitigation"
            mitigates      = ["credential-theft"]
            provided_by    = ["aws-waf"]
            reduces_risk_by = 50
        \(descriptionLine)
          }
        }
        """
    }

    private func aSession(_ descriptionLine: String) -> ThreatModelSession {
        let app = TestDependencies()
        app.project.put(library(descriptionLine), at: "/work/threatmodel/library/custom.lib")
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            return ThreatModelSession(useCases: app)
        }
        app.useLibraries(libraries)
        return ThreatModelSession(useCases: app)
    }

    /// The model carries the description already; the gap is the panel.
    @Test func theSessionCarriesTheDescription() {
        let session = aSession("    description = \"Blocks common attack payloads.\"")

        let mitigation = session.pathwayMitigations.mitigations.first { $0.id == "custom-custom-mitigation" }
        #expect(mitigation?.description == "Blocks common attack payloads.")
    }

    /// The row draws differently when the library states a description than
    /// when it states none, so the text reaches the picture.
    @Test func theRowDrawsTheDescription() throws {
        let stated = aSession("    description = \"Blocks common attack payloads.\"")
        let silent = aSession("")

        let withDescription = try #require(
            hostedDrawing(
                of: PathwayMitigationsPanel(session: stated, isExpanded: true),
                width: 300,
                height: 400
            )
        )
        let withoutDescription = try #require(
            hostedDrawing(
                of: PathwayMitigationsPanel(session: silent, isExpanded: true),
                width: 300,
                height: 400
            )
        )

        #expect(pixels(of: withDescription.image) != pixels(of: withoutDescription.image))
    }

    /// Every sampled pixel of a drawn image, so one picture is compared with
    /// another.
    private func pixels(of image: NSBitmapImageRep) -> [String] {
        var read: [String] = []
        for x in stride(from: 0, to: image.pixelsWide, by: 2) {
            for y in stride(from: 0, to: image.pixelsHigh, by: 2) {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                read.append(
                    String(format: "%.2f,%.2f,%.2f", colour.redComponent, colour.greenComponent, colour.blueComponent)
                )
            }
        }
        return read
    }
}
