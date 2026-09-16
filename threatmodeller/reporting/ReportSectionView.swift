import SwiftUI
import ThreatModelKit

/// One section of the report, drawn as native views.
///
/// Nothing here reads Markdown or HTML. A heading is a `Text`, a table is a
/// `Grid`, and a diagram is the text the team wrote.
struct ReportSectionView: View {
    let section: ReportStageSection

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Array(section.blocks.enumerated()), id: \.offset) { offset, block in
                ReportBlockView(block: block)
                    .accessibilityIdentifier("report-block-\(section.slot.rawValue)-\(offset)")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityIdentifier("report-section-\(section.slot.rawValue)")
    }
}

/// One piece of a section.
struct ReportBlockView: View {
    let block: ReportBlock

    var body: some View {
        switch block {
        case .heading(let text):
            Text(text)
                .font(.title2.bold())
                .padding(.top, 8)
        case .subheading(let text):
            Text(text)
                .font(.headline)
                .padding(.top, 4)
        case .lead(let text):
            Text(text)
                .font(.callout.weight(.semibold))
        case .paragraph(let text):
            Text(text)
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        case .bullets(let bullets):
            list(bullets, numbered: false)
        case .numbered(let bullets):
            list(bullets, numbered: true)
        case .table(let table):
            ReportTableView(table: table)
        case .fenced(let kind, let text):
            fenced(kind: kind, text: text)
        }
    }

    /// A list of the report, with the lines the report indents under a row
    /// indented here too.
    private func list(_ bullets: [ReportBullet], numbered: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(bullets.enumerated()), id: \.offset) { offset, bullet in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(numbered ? "\(offset + 1)." : "\u{2022}")
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(.secondary)
                        Text(bullet.text)
                            .font(.callout)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(Array(bullet.notes.enumerated()), id: \.offset) { _, note in
                        Text(note)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.leading, 18)
                    }
                }
            }
        }
    }

    /// A diagram a team wrote, in the language it wrote it in. The window
    /// draws no Mermaid renderer, so the text is what a reader reads.
    private func fenced(kind: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(kind)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(Color.secondary.opacity(0.1), in: .rect(cornerRadius: 6))
        }
    }
}

/// A table of the report, drawn as a grid.
struct ReportTableView: View {
    let table: ReportTable

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
            GridRow {
                ForEach(Array(table.columns.enumerated()), id: \.offset) { _, column in
                    Text(column)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            ForEach(Array(table.rows.enumerated()), id: \.offset) { _, row in
                GridRow {
                    ForEach(Array(row.enumerated()), id: \.offset) { _, cell in
                        Text(cell)
                            .font(.caption)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
