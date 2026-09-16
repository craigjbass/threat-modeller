import SwiftUI
import ThreatModelKit

/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this is a pure value computation with no shared state.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this is a pure value computation with no shared state.
nonisolated extension BoundaryCrossings.BoundaryRun {
    /// The bow this boundary draws, in the stretches no unrelated flow crosses.
    func path(avoiding unrelated: [[Point]]) -> Path {
        var built = Path()

        for stretch in BoundaryCrossings.stretches(of: self, avoiding: unrelated) {
            guard let first = stretch.first else { continue }
            built.move(to: CGPoint(first))
            for point in stretch.dropFirst() { built.addLine(to: CGPoint(point)) }
        }

        return built
    }
}

struct ConnectionsLayer: View {
    /// The model point this layer's own top-left corner sits at. Everything
    /// below draws in model coordinates, and a `Canvas` paints nothing outside
    /// its own frame, so the layer reaches back past the origin and shifts its
    /// drawing by the same amount.
    let origin: CGPoint
    let connections: [ViewedConnection]
    let boxes: [String: ComponentBox]
    /// Every component by id, so the layer can tell which zone each end of a
    /// link sits in.
    let componentsById: [String: ViewedComponent]
    /// In drawing order, so the containment rule matches the core's.
    let zones: [ViewedZone]
    /// The risk of every element, by source id. A link reads
    /// "connection:<id>".
    let risks: [String: ElementRisk]
    /// What guards every element, by source id. A crossing states these, so a
    /// reader sees what stands in the way of a flow across a boundary.
    let guards: [String: [EdgeGuard]]
    /// The components the user turned threats off for.
    let outOfScopeComponentIds: Set<String>
    let selectedConnectionIds: Set<String>
    /// Which components are selected. A mitigates mark both ends of which are
    /// selected is the one the bar under the canvas edits, so that mark is
    /// drawn in the accent colour.
    var selectedComponentIds: Set<String> = []
    /// What one component lowers on another. Each of these draws its own
    /// mark.
    var mitigations: [ViewedMitigation] = []
    let preview: (start: CGPoint, end: CGPoint)?

    var body: some View {
        let geometry = FlowGeometry.of(
            connections: connections,
            boxes: boxes,
            componentsById: componentsById,
            zones: zones,
            guards: guards,
            risks: risks,
            outOfScopeComponentIds: outOfScopeComponentIds
        )

        let protection = MitigatesGeometry.of(mitigations: mitigations, boxes: boxes)

        return Canvas { context, _ in
            context.translateBy(x: -origin.x, y: -origin.y)

            for connection in connections {
                guard let curve = geometry.curves[connection.id] else { continue }
                draw(connection, along: ConnectionPath(curve), in: &context)
            }

            for mark in protection.marks {
                draw(mark, in: &context)
            }

            for run in geometry.runs {
                let unrelated = geometry.samples
                    .filter { run.connectionIds.contains($0.key) == false }
                    .map(\.value)

                context.stroke(
                    run.path(avoiding: unrelated),
                    with: .color(tint(of: run)),
                    style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: [2, 5])
                )
            }

            // The chips go on last, so a link drawn later never covers one.
            for run in geometry.runs {
                writeGuards(of: run, in: &context)
            }

            // The labels go last, over everything, because a label a link
            // crosses is unreadable.
            for callout in geometry.callouts {
                guard let connection = connections.first(where: { $0.id == callout.connectionId })
                else { continue }
                draw(callout, colour: colour(of: connection), in: &context)
            }

            if let preview {
                stroke(
                    ConnectionPath(from: preview.start, to: preview.end),
                    in: &context,
                    colour: .accentColor,
                    width: 2.5,
                    dashed: true
                )
            }
        }
        .allowsHitTesting(false)
    }

    // MARK: what one mitigates edge looks like

    /// The colour of a mark. A mark both ends of which are selected is the
    /// edge the bar under the canvas edits.
    private func colour(of mark: MitigatesMark) -> Color {
        isSelected(mark) ? .accentColor : .teal
    }

    private func isSelected(_ mark: MitigatesMark) -> Bool {
        selectedComponentIds.contains(mark.sourceComponentId)
            && selectedComponentIds.contains(mark.targetComponentId)
    }

    /// A bowed curve with a shield on it and no arrowhead. A broken curve and
    /// a hollow shield state an assumed edge, which the team would run and
    /// does not run today.
    private func draw(_ mark: MitigatesMark, in context: inout GraphicsContext) {
        let colour = colour(of: mark)

        context.stroke(
            mark.drawnPath,
            with: .color(colour),
            style: StrokeStyle(
                lineWidth: isSelected(mark) ? 4 : 3,
                lineCap: .round,
                dash: mark.dash
            )
        )

        context.fill(
            mark.shieldPath,
            with: .color(mark.isShieldFilled ? colour : Color(nsColor: .textBackgroundColor))
        )
        context.stroke(
            mark.shieldPath,
            with: .color(colour),
            style: StrokeStyle(lineWidth: 1.5, dash: mark.isAssumed ? [3, 3] : [])
        )
    }

    private func tint(of run: BoundaryCrossings.BoundaryRun) -> Color {
        run.networkZoneId == "private" ? .green : .orange
    }

    // MARK: what one link looks like

    private func isOutOfScope(_ connection: ViewedConnection) -> Bool {
        FlowGeometry.isOutOfScope(connection, outOfScopeComponentIds)
    }

    private func risk(of connection: ViewedConnection) -> ElementRisk? {
        risks["connection:\(connection.id)"]
    }

    private func colour(of connection: ViewedConnection) -> Color {
        if isOutOfScope(connection) { return .secondary }
        if selectedConnectionIds.contains(connection.id) { return .accentColor }
        guard let levelId = risk(of: connection)?.highestLevelId else { return .secondary }
        return RiskPalette.colour(forLevelId: levelId)
    }

    /// The description when the user wrote one, else the flow kind, cut to
    /// what fits on the line. The panel shows the whole of it.
    func labelForTesting(_ connection: ViewedConnection) -> String {
        FlowGeometry.label(of: connection)
    }

    private func draw(
        _ connection: ViewedConnection,
        along path: ConnectionPath,
        in context: inout GraphicsContext
    ) {
        let selected = selectedConnectionIds.contains(connection.id)
        let colour = colour(of: connection)

        stroke(
            path,
            in: &context,
            colour: colour,
            width: selected ? 2.5 : 1.5,
            dashed: isOutOfScope(connection)
        )

        let head = path.arrowhead()
        var arrow = Path()
        arrow.move(to: head[0])
        arrow.addLine(to: head[1])
        arrow.addLine(to: head[2])
        arrow.closeSubpath()
        context.fill(arrow, with: .color(colour))
    }

    private func draw(
        _ callout: Callout,
        colour: Color,
        in context: inout GraphicsContext
    ) {
        let box = CGRect(callout.rect)
        let anchor = CGPoint(callout.anchor)

        // The leader leaves the edge of the box nearest the flow.
        var leader = Path()
        leader.move(to: CGPoint(x: box.midX, y: box.midY))
        leader.addLine(to: anchor)
        context.stroke(
            leader,
            with: .color(colour.opacity(0.5)),
            style: StrokeStyle(lineWidth: 1, dash: [3, 3])
        )

        context.fill(
            Path(roundedRect: box, cornerRadius: 5),
            with: .color(Color(nsColor: .textBackgroundColor))
        )
        context.stroke(
            Path(roundedRect: box, cornerRadius: 5),
            with: .color(colour.opacity(0.6)),
            style: StrokeStyle(lineWidth: 1)
        )
        context.fill(
            Path(ellipseIn: CGRect(x: anchor.x - 2.5, y: anchor.y - 2.5, width: 5, height: 5)),
            with: .color(colour)
        )

        // The lines are broken here rather than by the drawing, which clips a
        // resolved text to one line. The break is the one the core sized the
        // box with, so the text and the box always agree.
        let lines = Self.wrapped(callout.text, perLine: CalloutPlacement.charactersPerLine)
        for (index, line) in lines.enumerated() {
            context.draw(
                context.resolve(Text(line).font(.caption2).foregroundStyle(colour)),
                at: CGPoint(
                    x: box.minX + 6,
                    y: box.minY + CalloutPlacement.padding / 2
                        + (Double(index) + 0.5) * CalloutPlacement.lineHeight
                ),
                anchor: .leading
            )
        }
    }

    /// The text broken into lines of about `perLine` characters, on word
    /// boundaries. A word longer than a line keeps its own line.
    static func wrapped(_ text: String, perLine: Int) -> [String] {
        var lines: [String] = []
        var line = ""

        for word in text.split(separator: " ") {
            if line.isEmpty {
                line = String(word)
            } else if line.count + 1 + word.count <= perLine {
                line += " " + word
            } else {
                lines.append(line)
                line = String(word)
            }
        }
        if line.isEmpty == false { lines.append(line) }

        return lines
    }

    private func writeGuards(
        of run: BoundaryCrossings.BoundaryRun,
        in context: inout GraphicsContext
    ) {
        let tint = tint(of: run)
        let texts = FlowGeometry.chipTexts(of: run)
        let rects = BoundaryChips.rects(of: run, texts: texts, zoneHeaders: bandRects)
        let assumed = Array(run.guards.prefix(FlowGeometry.guardsShown)).map(\.isAssumed)

        for (index, text) in texts.enumerated() where index < rects.count {
            let colour: Color = run.guards.isEmpty ? .secondary : tint
            let box = CGRect(rects[index])

            context.fill(
                Path(roundedRect: box, cornerRadius: 4),
                with: .color(Color(nsColor: .textBackgroundColor))
            )
            context.stroke(
                Path(roundedRect: box, cornerRadius: 4),
                with: .color(colour),
                style: StrokeStyle(
                    lineWidth: 1,
                    dash: index < assumed.count && assumed[index] ? [3, 3] : []
                )
            )
            context.draw(
                context.resolve(Text(text).font(.caption2).foregroundStyle(colour)),
                at: CGPoint(x: box.midX, y: box.midY),
                anchor: .center
            )
        }
    }

    /// The name band of every zone. Nothing is drawn over one.
    private var bandRects: [Rect] {
        zones.map {
            Rect(x: $0.x, y: $0.y, width: $0.width, height: Double(ZoneBox.headerHeight))
        }
    }

    private func stroke(
        _ path: ConnectionPath,
        in context: inout GraphicsContext,
        colour: Color,
        width: CGFloat,
        dashed: Bool
    ) {
        context.stroke(
            path.drawnPath,
            with: .color(colour),
            style: StrokeStyle(lineWidth: width, dash: dashed ? [6, 4] : [])
        )
    }
}
