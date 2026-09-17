import SwiftUI
import ThreatModelKit

/// The Report stage: what the report says about the model as it stands.
///
/// It draws the sections the project's template names, in that order, from the
/// `Report` value the exporters render. It writes no file to draw, so an
/// answer given on the Controls stage shows here on the next draw.
///
/// The design is `docs/superpowers/specs/2026-09-16-report-stage-design.md`.
struct ReportStage: View {
    let project: ProjectSession
    let session: ThreatModelSession
    /// The stage the panel writes. The columns own it, so the stage takes the
    /// binding the columns hold.
    @Binding var stage: WorkStage

    /// The section the left sidebar has scrolled to, or nil.
    @State private var chosen: ReportTemplate.Slot?

    /// The report, read again on every draw. Reading it is arithmetic over the
    /// model in memory, and it touches no file.
    private var page: ReportStagePage {
        session.reportStagePage(history: project.sampledHistory)
    }

    var body: some View {
        let page = self.page

        NavigationSplitView {
            sections(of: page)
                .navigationSplitViewColumnWidth(min: 200, ideal: 240)
        } content: {
            reading(page)
        } detail: {
            controls(page)
                .navigationSplitViewColumnWidth(min: 260, ideal: 300, max: 360)
        }
    }

    /// The sections the template names, in order. A click scrolls the reading
    /// column to that section.
    private func sections(of page: ReportStagePage) -> some View {
        List(page.sections, selection: $chosen) { section in
            Text(section.title)
                .lineLimit(2)
                .tag(section.slot)
                .accessibilityIdentifier("report-contents-\(section.slot.rawValue)")
        }
        .navigationTitle("Sections")
        .accessibilityIdentifier("report-contents")
    }

    /// The sections themselves, one after another.
    private func reading(_ page: ReportStagePage) -> some View {
        ScrollViewReader { scroller in
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if page.fault.isEmpty == false {
                        fault(page.fault)
                    } else if page.sections.isEmpty {
                        Text("This template names no section of the report.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(page.sections) { section in
                            ReportSectionView(
                                section: section,
                                session: session,
                                sample: { Task { await project.sampleTheHistory() } }
                            )
                                .id(section.slot)
                        }
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .onChange(of: chosen) {
                guard let chosen else { return }
                withAnimation { scroller.scrollTo(chosen, anchor: .top) }
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                Color.clear.frame(
                    height: WorkflowPanel.reservedHeight + WorkflowPanel.bottomMargin
                )
            }
            .overlay(alignment: .bottom) {
                GeometryReader { geometry in
                    WorkflowPanel(
                        session: project,
                        stage: $stage,
                        columnWidth: geometry.size.width
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
                }
            }
            .navigationTitle("Report")
            .navigationSplitViewColumnWidth(min: ProjectColumns.minimumDiagramWidth, ideal: 700)
            .accessibilityIdentifier("report-reading")
        }
    }

    /// What stops the report. The stage shows the fault where the sections
    /// would be, because the export writes no file either.
    private func fault(_ lines: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("This report does not render", systemImage: "exclamationmark.octagon.fill")
                .font(.headline)
                .foregroundStyle(.red)
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.callout)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityIdentifier("report-fault")
    }

    /// The verb, the format, the template and the file the last write went to.
    private func controls(_ page: ReportStagePage) -> some View {
        Form {
            Section("Write a file") {
                Picker("Format", selection: format) {
                    ForEach(ProjectSession.ReportFormat.allCases) { choice in
                        Text(choice.label).tag(choice)
                    }
                }
                .accessibilityIdentifier("report-format")

                Button("Generate Report") {
                    Task { await project.generateReport() }
                }
                .disabled(project.chosenSystem == nil)
                .accessibilityIdentifier("report-generate")
            }

            Section("Template") {
                Text(page.templatePath ?? "The shape this application ships")
                    .font(.callout)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("report-template-path")
            }

            Section("Last report") {
                if let path = project.reportPath {
                    Text(path)
                        .font(.callout)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("report-last-path")

                    Button("Open") { project.openLastReport() }
                        .accessibilityIdentifier("report-open-last")
                    Button("Reveal in Finder") { project.revealLastReport() }
                        .accessibilityIdentifier("report-reveal-last")
                } else {
                    Text("This window has written none.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("report-last-path")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Report")
        .accessibilityIdentifier("report-controls")
    }

    private var format: Binding<ProjectSession.ReportFormat> {
        Binding(
            get: { project.reportFormat },
            set: { project.reportFormat = $0 }
        )
    }
}
