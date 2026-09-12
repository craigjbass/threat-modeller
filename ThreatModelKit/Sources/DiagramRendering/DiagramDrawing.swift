import Foundation
import ThreatModelKit

/// A colour, as the diagram states it. No platform type appears here: this
/// description is read by a writer that runs anywhere.
public struct DiagramColour: Equatable, Sendable {
    public let red: Double
    public let green: Double
    public let blue: Double
    public let alpha: Double

    public init(_ red: Double, _ green: Double, _ blue: Double, alpha: Double = 1) {
        self.red = red
        self.green = green
        self.blue = blue
        self.alpha = alpha
    }

    public func faded(to alpha: Double) -> DiagramColour {
        DiagramColour(red, green, blue, alpha: alpha)
    }

    public static let ink = DiagramColour(0.11, 0.11, 0.12)
    public static let quiet = DiagramColour(0.44, 0.44, 0.46)
    public static let paper = DiagramColour(1, 1, 1)
    public static let green = DiagramColour(0.20, 0.68, 0.33)
    public static let orange = DiagramColour(0.95, 0.55, 0.12)
    public static let yellow = DiagramColour(0.96, 0.78, 0.09)
    public static let red = DiagramColour(0.90, 0.22, 0.21)
    public static let purple = DiagramColour(0.50, 0.30, 0.75)

    /// One colour per risk level, the same names the application shows.
    public static func forLevel(_ levelId: String?) -> DiagramColour {
        switch levelId {
        case "critical": red
        case "high": orange
        case "medium": yellow
        case "low": green
        default: quiet
        }
    }
}

/// How a shape is painted.
public struct DiagramStyle: Equatable, Sendable {
    public let stroke: DiagramColour?
    public let fill: DiagramColour?
    public let width: Double
    /// The on and off lengths of a dash, or empty for a solid line.
    public let dash: [Double]

    public init(
        stroke: DiagramColour? = nil,
        fill: DiagramColour? = nil,
        width: Double = 1,
        dash: [Double] = []
    ) {
        self.stroke = stroke
        self.fill = fill
        self.width = width
        self.dash = dash
    }
}

/// Where a piece of text sits against its point.
public enum TextAnchor: Equatable, Sendable {
    case leading
    case centre
    case trailing
}

/// One step of a path.
public enum PathStep: Equatable, Sendable {
    case move(Point)
    case line(Point)
    case cubic(control1: Point, control2: Point, to: Point)
    case quadratic(control: Point, to: Point)
    case close
}

/// One thing the diagram draws.
public enum DrawnShape: Equatable, Sendable {
    case rectangle(Rect, cornerRadius: Double, DiagramStyle)
    case ellipse(Rect, DiagramStyle)
    case path([PathStep], DiagramStyle)
    case text(String, at: Point, anchor: TextAnchor, size: Double, bold: Bool, DiagramColour)
}

/// Everything a diagram draws, in the order it draws it, and nothing about how
/// a platform draws it.
///
/// The application draws with SwiftUI, which cannot go in this package: the
/// command line tool ships as a static Linux binary. One description with a
/// writer per output keeps the two pictures the same.
public struct DiagramDrawing: Equatable, Sendable {
    /// Where the picture starts, in model coordinates.
    public let origin: Point
    public let size: Size
    public let background: DiagramColour
    public let shapes: [DrawnShape]

    public init(
        origin: Point,
        size: Size,
        background: DiagramColour = .paper,
        shapes: [DrawnShape]
    ) {
        self.origin = origin
        self.size = size
        self.background = background
        self.shapes = shapes
    }
}
