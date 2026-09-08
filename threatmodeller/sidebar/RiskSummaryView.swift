import SwiftUI
import ThreatModelKit

/// Counts over the whole model, above the cards they count.
struct RiskSummaryView: View {
    let summary: SummariseRiskResponse

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ForEach(summary.byLevel, id: \.levelId) { level in
                    VStack(spacing: 1) {
                        Text("\(level.count)")
                            .font(.title3.monospacedDigit())
                            .foregroundStyle(level.count == 0 ? Color.secondary : RiskPalette.colour(forLevelId: level.levelId))
                        Text(level.label)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                }
            }

            if summary.controlsOffered > 0 {
                ProgressView(
                    value: Double(summary.controlsRecorded),
                    total: Double(summary.controlsOffered)
                ) {
                    Text("\(summary.controlsRecorded) of \(summary.controlsOffered) controls in place")
                        .font(.caption)
                }
            }

            HStack(spacing: 6) {
                ForEach(summary.byStride, id: \.strideId) { category in
                    Text("\(Self.initial(category.label)) \(category.count)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(category.count == 0 ? .tertiary : .secondary)
                        .help("\(category.label): \(category.count)")
                }
            }
        }
        .padding(12)
        .accessibilityIdentifier("risk-summary")
    }

    /// STRIDE reads as six initials. The full label is on the tooltip.
    private static func initial(_ label: String) -> String {
        String(label.prefix(1))
    }
}
