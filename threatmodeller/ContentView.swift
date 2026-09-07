import SwiftUI
import ThreatModelKit

struct ContentView: View {
    var body: some View {
        Text(threatModelKitIsWired ? "ThreatModelKit linked" : "not linked")
            .padding()
    }
}
