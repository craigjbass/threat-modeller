import Foundation

/// Where the chips naming what guards a boundary sit.
///
/// The core places them because a callout has to keep away from them, and the
/// layout scores what the canvas draws. Both call this, so neither can
/// disagree.
public enum BoundaryChips {
    /// How far past the end of the boundary curve the first chip sits.
    public static let clearOfTheCurve = 14.0
    public static let height = 18.0
    public static let gap = 3.0
    /// About how wide a character is at the size a chip is written.
    public static let characterWidth = 5.6
    public static let padding = 12.0
    /// The blank a chip drops to when it lands on a zone's name band.
    public static let clearOfTheBand = 8.0

    public static func width(of text: String) -> Double {
        Double(text.count) * characterWidth + padding
    }

    /// The stack of chips this boundary writes, in the order given.
    ///
    /// A chip that lands on a zone's name band drops below it: a chip over the
    /// band hides which zone a reader is looking at.
    public static func rects(
        of run: BoundaryCrossings.BoundaryRun,
        texts: [String],
        zoneHeaders: [Rect] = []
    ) -> [Rect] {
        guard texts.isEmpty == false else { return [] }

        let reach = hypot(run.end.x - run.start.x, run.end.y - run.start.y)
        guard reach > 0 else { return [] }

        let step = Point(x: (run.end.x - run.start.x) / reach, y: (run.end.y - run.start.y) / reach)
        let x = run.end.x + clearOfTheCurve * step.x
        var y = run.end.y + clearOfTheCurve * step.y

        for band in zoneHeaders where band.contains(Point(x: x, y: y)) {
            // Past the band by the blank, measured from the chip's top edge
            // rather than its middle.
            y = band.maxY + clearOfTheBand + height / 2
        }

        var built: [Rect] = []

        for text in texts {
            let box = width(of: text)
            built.append(Rect(x: x - box / 2, y: y - height / 2, width: box, height: height))
            y += height + gap
        }

        return built
    }
}
