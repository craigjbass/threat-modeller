import SwiftUI

@main
struct ThreatModellerApp: App {
    var body: some Scene {
        DocumentGroup(newDocument: ThreatModelDocument()) { file in
            ContentView(document: file.document)
        }
        .defaultSize(width: 1400, height: 900)
    }
}
