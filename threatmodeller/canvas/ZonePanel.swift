import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one zone is selected.
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
        // The controls scroll sideways, as the component bar's do. Their
        // widths are fixed and the canvas column can be 400 points, at which
        // the row reflowed and the bar grew to 176 points.
        ScrollView(.horizontal) {
            controls
        }
        .scrollIndicators(.automatic)
        .background(.bar)
    }

    private var controls: some View {
        HStack(alignment: .center, spacing: 16) {
            DeferredTextField(
                title: "Name",
                text: zone.customName ?? "",
                width: 180,
                identifier: "zone-name",
                commit: { write(name: $0) }
            )

            Picker("Kind", selection: kind) {
                ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 160)
            .accessibilityIdentifier("zone-kind")

            Picker("Boundary", selection: boundary) {
                ForEach(Self.boundaries, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 180)
            .accessibilityIdentifier("zone-boundary")

            if zone.boundaryId == "network" {
                Picker("Network", selection: networkType) {
                    ForEach(Self.networkTypes, id: \.0) { Text($0.1).tag($0.0) }
                }
                .labelsHidden()
                .frame(width: 200)
                .accessibilityIdentifier("zone-network-type")
            }

            Toggle("Reduce risk", isOn: reductionEnabled)
                .toggleStyle(.switch)
                .accessibilityIdentifier("zone-reduction-enabled")

            if zone.riskReductionEnabled && zone.networkZoneId == "private" {
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
                    .frame(width: 140)
                    .accessibilityIdentifier("zone-reduction-percent")
                    Text("\(Int(reduction.shown(Double(zone.riskReductionPercent)).rounded()))%")
                        .monospacedDigit()
                        .frame(width: 42, alignment: .trailing)
                }
            }

            Spacer(minLength: 0)

            Button(role: .destructive) {
                session.removeZone(zone.id)
            } label: {
                Label("Remove zone", systemImage: "trash")
            }
            .accessibilityIdentifier("zone-remove")
        }
        .padding(.horizontal, CanvasView.windowEdgeMargin)
        .padding(.vertical, 8)
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        kind newKind: String? = nil,
        networkType newNetworkType: String? = nil,
        enabled newEnabled: Bool? = nil,
        percent newPercent: Int? = nil,
        boundary newBoundary: String? = nil
    ) {
        session.setZoneProperties(
            zoneId: zone.id,
            name: newName ?? zone.customName,
            networkZoneId: newKind ?? zone.networkZoneId,
            networkTypeId: newNetworkType ?? zone.networkTypeId,
            riskReductionEnabled: newEnabled ?? zone.riskReductionEnabled,
            riskReductionPercent: newPercent ?? zone.riskReductionPercent,
            boundaryId: newBoundary ?? zone.boundaryId
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
