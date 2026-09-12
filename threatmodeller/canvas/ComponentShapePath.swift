import SwiftUI
import ThreatModelKit

/// The outline each data flow diagram shape draws.
///
/// An actor is a rectangle. A process is a circle. A store is two horizontal
/// lines with no side walls, so a store's path holds two subpaths and nothing
/// closes.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one holds no state at all.
nonisolated enum ComponentShapePath {
    /// The outline to stroke, in the view's own coordinates.
    static func path(for shape: DiagramShape, in rect: CGRect) -> Path {
        switch shape {
        case .actor: Path(roundedRect: rect, cornerRadius: 4)
        case .process: Path(ellipseIn: rect)
        case .store: store(in: rect)
        }
    }

    /// The area to fill. A store has none: it is two lines, and whatever sits
    /// behind it shows through.
    static func fill(for shape: DiagramShape, in rect: CGRect) -> Path? {
        switch shape {
        case .actor: Path(roundedRect: rect, cornerRadius: 4)
        case .process: Path(ellipseIn: rect)
        case .store: nil
        }
    }

    private static func store(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        path.move(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        return path
    }
}
