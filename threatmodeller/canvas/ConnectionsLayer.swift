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
    /// How many guards a crossing names before it counts the rest.
    static let guardsShown = 2
    /// How long a guard's name may be on a chip. A component's name carries
    /// its product and its kind, and the whole of it covers the diagram.
    static let guardLimit = 30

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
    let preview: (start: CGPoint, end: CGPoint)?

    var body: some View {
        Canvas { context, _ in
            var marked: [BoundaryCrossings.MarkedCrossing] = []
            var sampled: [String: [Point]] = [:]
            var toLabel: [(connectionId: String, text: String, curve: FlowCurve)] = []
            var chipRects: [Rect] = []

            for connection in connections {
                guard let source = boxes[connection.sourceComponentId],
                      let target = boxes[connection.targetComponentId] else { continue }

                let avoid = CanvasHitTest.zonesToAvoid(
                    connection,
                    components: componentsById,
                    zones: zones
                )
                let anchors = AnchorGeometry.nearestPair(
                    from: source.rect.modelRect,
                    to: target.rect.modelRect,
                    avoiding: avoid
                )
                let path = ConnectionPath(
                    from: CGPoint(AnchorGeometry.point(anchors.source, of: source.rect.modelRect)),
                    to: CGPoint(AnchorGeometry.point(anchors.target, of: target.rect.modelRect)),
                    avoiding: avoid
                )
                draw(connection, along: path, in: &context)
                toLabel.append((connection.id, label(of: connection), path.curve))

                guard isOutOfScope(connection) == false else { continue }
                sampled[connection.id] = CurveCrossing.samples(of: path.curve)
                marked += BoundaryCrossings.of(
                    connectionId: connection.id,
                    sourceZoneId: componentsById[connection.sourceComponentId]?.zoneId,
                    targetZoneId: componentsById[connection.targetComponentId]?.zoneId,
                    curve: path.curve,
                    zones: boundaryZones
                ).map {
                    BoundaryCrossings.MarkedCrossing(
                        connectionId: connection.id,
                        crossing: $0,
                        guards: guards(of: connection),
                        openCount: risk(of: connection)?.openCount ?? 0
                    )
                }
            }

            // One curve for each boundary, however many arrows pass through it.
            let runs = BoundaryCrossings.runs(marked)

            for run in runs {
                let unrelated = sampled
                    .filter { run.connectionIds.contains($0.key) == false }
                    .map(\.value)

                context.stroke(
                    run.path(avoiding: unrelated),
                    with: .color(tint(of: run)),
                    style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: [2, 5])
                )
            }

            // The chips go on last, so a link drawn later never covers one.
            for run in runs {
                writeGuards(of: run, in: &context)
            }
            chipRects = runs.flatMap {
                BoundaryChips.rects(of: $0, texts: chipTexts(of: $0), zoneHeaders: bandRects)
            }

            // The labels go last, over everything, because a label a link
            // crosses is unreadable.
            drawCallouts(
                toLabel,
                over: Array(sampled.values),
                clearOf: chipRects,
                in: &context
            )

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

    /// The zones as the core geometry reads them.
    private var boundaryZones: [BoundaryZone] {
        zones.map {
            BoundaryZone(
                id: $0.id,
                networkZoneId: $0.networkZoneId,
                rect: Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
            )
        }
    }

    private func tint(of run: BoundaryCrossings.BoundaryRun) -> Color {
        run.networkZoneId == "private" ? .green : .orange
    }

    /// What guards a flow at a boundary: the components that guard the far end
    /// of it, and any that guard the flow itself. A `mitigates` edge names a
    /// component, so what stands in the way of a crossing is what guards the
    /// component the crossing reaches.
    private func guards(of connection: ViewedConnection) -> [EdgeGuard] {
        EdgeGuards.merge(
            guards["connection:\(connection.id)"] ?? [],
            guards["component:\(connection.targetComponentId)"] ?? []
        )
    }

    // MARK: what one link looks like

    private func isOutOfScope(_ connection: ViewedConnection) -> Bool {
        outOfScopeComponentIds.contains(connection.sourceComponentId)
            || outOfScopeComponentIds.contains(connection.targetComponentId)
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
    func labelForTesting(_ connection: ViewedConnection) -> String { label(of: connection) }

    private func label(of connection: ViewedConnection) -> String {
        let described = connection.description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard described.isEmpty == false else {
            return FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId
        }
        // Whole: the callout is sized to the text rather than the text cut to
        // fit a line.
        return described
    }

    /// A component's name, without what follows it in brackets or after a
    /// comma. `opfilter System Extension (Endpoint Security)` reads
    /// `opfilter System Extension`, which is the name; cutting it to a
    /// character count read `opfilter System E…`, which is nothing.
    static func name(of label: String) -> String {
        var ends = label.endIndex
        for mark in [" (", ", ", " \u{2014} ", " - "] {
            if let found = label.range(of: mark), found.lowerBound < ends {
                ends = found.lowerBound
            }
        }
        return cut(String(label[label.startIndex ..< ends]), to: guardLimit)
    }

    /// The text, or as much of it as fits, with an ellipsis for the rest.
    static func cut(_ text: String, to limit: Int) -> String {
        guard text.count > limit else { return text }
        return text.prefix(limit - 1).trimmingCharacters(in: .whitespaces) + "\u{2026}"
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

    /// Every flow's label, in a box where the diagram is empty, joined to its
    /// flow by a leader.
    ///
    /// A description is prose. On the line it is cut or it covers the diagram;
    /// in a box it is whole.
    private func drawCallouts(
        _ labels: [(connectionId: String, text: String, curve: FlowCurve)],
        over flows: [[Point]],
        clearOf chips: [Rect],
        in context: inout GraphicsContext
    ) {
        let placed = CalloutPlacement.place(
            labels,
            nodes: boxes.values.map(\.drawnRect),
            zoneHeaders: bandRects,
            boundaryChips: chips,
            flows: flows
        )

        for callout in placed {
            guard let connection = connections.first(where: { $0.id == callout.connectionId })
            else { continue }
            draw(callout, colour: colour(of: connection), in: &context)
        }
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

    /// What this boundary writes: the components that guard it, or the words
    /// that say none does. An unguarded crossing carrying an open threat is
    /// what a reviewer looks for, so it is stated rather than left blank.
    private func chipTexts(of run: BoundaryCrossings.BoundaryRun) -> [String] {
        let shown = Array(run.guards.prefix(Self.guardsShown))
        let hidden = run.guards.count - shown.count

        guard run.guards.isEmpty == false else {
            return run.openCount > 0 ? ["no guard"] : []
        }

        var texts = shown.map { Self.name(of: $0.label) }
        if hidden > 0 { texts.append("+\(hidden)") }
        return texts
    }

    private func writeGuards(
        of run: BoundaryCrossings.BoundaryRun,
        in context: inout GraphicsContext
    ) {
        let tint = tint(of: run)
        let texts = chipTexts(of: run)
        let rects = BoundaryChips.rects(of: run, texts: texts, zoneHeaders: bandRects)
        let assumed = Array(run.guards.prefix(Self.guardsShown)).map(\.isAssumed)

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
