/// Which zone holds a component.
///
/// Spec section 5.2: the component's centre must lie inside the zone rectangle
/// with the header band removed, and a later zone wins over an earlier one, so
/// a zone drawn on top of another captures what it covers.
///
/// Nothing stores the answer. A component records a position and a zone records
/// a rectangle, so the two can never disagree.
public enum ZoneContainment {
    /// The band at the top of a zone that holds its name and its controls.
    /// A component whose centre sits in the band is not inside the zone.
    public static let headerHeight = 40.0

    public static func zone(holding centre: Point, in zones: [Zone]) -> Zone? {
        zones.last { $0.rect.insetFromTop(by: headerHeight).contains(centre) }
    }
}
