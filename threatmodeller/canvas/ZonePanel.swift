import SwiftUI
import ThreatModelKit

/// The editor in the right sidebar, shown while exactly one zone is selected.
///
/// Every control writes through `SetZoneProperties` and the threat list
/// rescores, so the user sees the effect of a reduction as they change it.
struct ZonePanel: View {
    let session: ThreatModelSession
    let zone: ViewedZone

    /// The drag in flight on the reduction slider, if there is one.
    @State private var reduction = DeferredEdit<Double>()

    private static let kinds = [("private", "Private"), ("public", "Public")]
    private static let boundaries = [("network", "Network"), ("privilege", "Privilege")]
    private static let networkTypes = [
        ("generic", "Generic Network"),
        ("vpc", "VPC"),
        ("subnet", "Subnet"),
        ("on-premises", "On-Premises"),
        ("dmz", "DMZ"),
        ("management", "Management Network"),
        ("data", "Data Network")
    ]

    var body: some View {
        SelectionEditor(title: "This zone", identifier: "zone-panel") {
            controls
        }
    }

    @ViewBuilder
    private var controls: some View {
        SelectionField("Name") {
            DeferredTextField(
                title: "Name",
                text: zone.customName ?? "",
                identifier: "zone-name",
                write: { write(name: $0) }
            )
        }

        SelectionField("Kind") {
            Picker("Kind", selection: kind) {
                ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityIdentifier("zone-kind")
        }

        SelectionField("Boundary") {
            Picker("Boundary", selection: boundary) {
                ForEach(Self.boundaries, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityIdentifier("zone-boundary")
        }

        if zone.boundaryId == "network" {
            SelectionField("Network") {
                Picker("Network", selection: networkType) {
                    ForEach(Self.networkTypes, id: \.0) { Text($0.1).tag($0.0) }
                }
                .labelsHidden()
                .accessibilityIdentifier("zone-network-type")
            }
        }

        SelectionField("Description") {
            DeferredTextField(
                title: "Description",
                text: zone.description,
                identifier: "zone-description",
                write: { commitDescription($0) }
            )
        }

        // The tags a zone is filed under, as one line. The canvas tag
        // filter draws the zone and the components inside it.
        SelectionField("Tags") {
            DeferredTextField(
                title: "Tags",
                text: tagsText,
                identifier: "zone-tags",
                write: { commitTags($0) }
            )
        }

        Divider()

        Toggle("Reduce risk", isOn: reductionEnabled)
            .toggleStyle(.switch)
            .accessibilityIdentifier("zone-reduction-enabled")

        if zone.riskReductionEnabled && zone.networkZoneId == "private" {
            SelectionField("Reduces risk by") {
                HStack(spacing: 6) {
                    // The slider writes when the drag ends, not at every
                    // step: a drag across the range is one change and one
                    // undo, and the number beside it follows the thumb.
                    Slider(
                        value: Binding(
                            get: { reduction.shown(Double(zone.riskReductionPercent)) },
                            set: { reduction.edit($0) }
                        ),
                        in: 0...100,
                        step: 5,
                        onEditingChanged: { editing in
                            guard editing == false else { return }
                            guard let picked = reduction.end(
                                from: Double(zone.riskReductionPercent)
                            ) else { return }
                            write(percent: Int(picked.rounded()))
                        }
                    )
                    .accessibilityIdentifier("zone-reduction-percent")
                    Text("\(Int(reduction.shown(Double(zone.riskReductionPercent)).rounded()))%")
                        .monospacedDigit()
                        .frame(width: 42, alignment: .trailing)
                }
            }
        }

        Divider()

        Button(role: .destructive) {
            session.removeZone(zone.id)
        } label: {
            Label("Remove zone", systemImage: "trash")
        }
        .accessibilityIdentifier("zone-remove")
    }

    /// The line the tag field shows: every tag the zone holds, separated by
    /// commas.
    var tagsText: String { TagFilter.text(from: zone.tags) }

    /// Writes what a person typed in the tag field. An empty line takes every
    /// tag off the zone.
    func commitTags(_ text: String) {
        write(tags: TagFilter.tags(from: text))
    }

    /// Writes what a person typed in the description field. An empty field
    /// takes the description off the zone.
    func commitDescription(_ text: String) {
        write(description: text)
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        kind newKind: String? = nil,
        networkType newNetworkType: String? = nil,
        enabled newEnabled: Bool? = nil,
        percent newPercent: Int? = nil,
        boundary newBoundary: String? = nil,
        description newDescription: String? = nil,
        tags newTags: [String]? = nil
    ) {
        session.setZoneProperties(
            zoneId: zone.id,
            name: newName ?? zone.customName,
            networkZoneId: newKind ?? zone.networkZoneId,
            networkTypeId: newNetworkType ?? zone.networkTypeId,
            riskReductionEnabled: newEnabled ?? zone.riskReductionEnabled,
            riskReductionPercent: newPercent ?? zone.riskReductionPercent,
            boundaryId: newBoundary ?? zone.boundaryId,
            description: newDescription,
            tags: newTags
        )
    }


    private var kind: Binding<String> {
        Binding(get: { zone.networkZoneId }, set: { write(kind: $0) })
    }

    private var boundary: Binding<String> {
        Binding(get: { zone.boundaryId }, set: { write(boundary: $0) })
    }

    private var networkType: Binding<String> {
        Binding(get: { zone.networkTypeId }, set: { write(networkType: $0) })
    }

    private var reductionEnabled: Binding<Bool> {
        Binding(get: { zone.riskReductionEnabled }, set: { write(enabled: $0) })
    }
}
