import CoreGraphics
import ThreatModelKit

/// The eight grips on a zone's outline.
nonisolated enum ZoneHandle: String, CaseIterable, Equatable {
    case topLeft
    case top
    case topRight
    case right
    case bottomRight
    case bottom
    case bottomLeft
    case left
}

/// A zone's rectangle on the canvas, its header band, and its resize grips.
///
/// The header height and the minimum size come from the core, so what the user
/// sees and what the core scores can never disagree.
nonisolated struct ZoneBox: Equatable {
    static let headerHeight = CGFloat(ZoneContainment.headerHeight)
    static let handleSize: CGFloat = 12
    static let minimumSize = CGSize(
        width: Zone.minimumSize.width,
        height: Zone.minimumSize.height
    )

    let rect: CGRect

    init(x: Double, y: Double, width: Double, height: Double) {
        rect = CGRect(x: x, y: y, width: width, height: height)
    }

    init(zone: ViewedZone) {
        self.init(x: zone.x, y: zone.y, width: zone.width, height: zone.height)
    }

    /// The band holding the zone's name. Dragging it moves the zone.
    var headerRect: CGRect {
        CGRect(
            x: rect.minX,
            y: rect.minY,
            width: rect.width,
            height: min(Self.headerHeight, rect.height)
        )
    }

    /// The area a component's centre must sit in to belong to the zone.
    var contentRect: CGRect {
        let removed = min(Self.headerHeight, rect.height)
        return CGRect(
            x: rect.minX,
            y: rect.minY + removed,
            width: rect.width,
            height: rect.height - removed
        )
    }

    func containsHeader(_ modelPoint: CGPoint) -> Bool { headerRect.contains(modelPoint) }

    func handleRect(_ handle: ZoneHandle) -> CGRect {
        let centre = handlePoint(handle)
        return CGRect(
            x: centre.x - Self.handleSize / 2,
            y: centre.y - Self.handleSize / 2,
            width: Self.handleSize,
            height: Self.handleSize
        )
    }

    func handle(at modelPoint: CGPoint) -> ZoneHandle? {
        ZoneHandle.allCases.first { handleRect($0).contains(modelPoint) }
    }

    /// The rectangle a drag from a grip produces.
    ///
    /// A corner grip moves two edges, an edge grip moves one. The rectangle
    /// never falls below the minimum: the dragged edge stops and the opposite
    /// edge stays put, so the zone cannot turn inside out.
    func resized(by translation: CGSize, from handle: ZoneHandle) -> CGRect {
        var minX = rect.minX
        var minY = rect.minY
        var maxX = rect.maxX
        var maxY = rect.maxY

        switch handle {
        case .topLeft:
            minX += translation.width
            minY += translation.height
        case .top:
            minY += translation.height
        case .topRight:
            maxX += translation.width
            minY += translation.height
        case .right:
            maxX += translation.width
        case .bottomRight:
            maxX += translation.width
            maxY += translation.height
        case .bottom:
            maxY += translation.height
        case .bottomLeft:
            minX += translation.width
            maxY += translation.height
        case .left:
            minX += translation.width
        }

        if maxX - minX < Self.minimumSize.width {
            if handle == .topLeft || handle == .left || handle == .bottomLeft {
                minX = maxX - Self.minimumSize.width
            } else {
                maxX = minX + Self.minimumSize.width
            }
        }
        if maxY - minY < Self.minimumSize.height {
            if handle == .topLeft || handle == .top || handle == .topRight {
                minY = maxY - Self.minimumSize.height
            } else {
                maxY = minY + Self.minimumSize.height
            }
        }

        return CGRect(x: minX, y: minY, width: maxX - minX, height: maxY - minY)
    }

    private func handlePoint(_ handle: ZoneHandle) -> CGPoint {
        switch handle {
        case .topLeft: CGPoint(x: rect.minX, y: rect.minY)
        case .top: CGPoint(x: rect.midX, y: rect.minY)
        case .topRight: CGPoint(x: rect.maxX, y: rect.minY)
        case .right: CGPoint(x: rect.maxX, y: rect.midY)
        case .bottomRight: CGPoint(x: rect.maxX, y: rect.maxY)
        case .bottom: CGPoint(x: rect.midX, y: rect.maxY)
        case .bottomLeft: CGPoint(x: rect.minX, y: rect.maxY)
        case .left: CGPoint(x: rect.minX, y: rect.midY)
        }
    }
}
