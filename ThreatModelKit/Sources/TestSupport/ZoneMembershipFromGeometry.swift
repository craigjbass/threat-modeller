import ThreatModelKit

extension ThreatModel {
    /// Fills in which zone holds each component, from the coordinates.
    ///
    /// A component carries the zone that holds it, and the use cases write
    /// that field: an import reads the nesting the file states, and a drag or
    /// a resize asks `ZoneContainment`. A test that builds a `ThreatModel` by
    /// hand states a picture and no membership, so this states the membership
    /// that picture means. It is the same rule `ThreatModelCodec` runs over a
    /// document written before format version 7.
    public func withZoneMembershipFromGeometry() -> ThreatModel {
        var model = self
        for index in model.components.indices {
            model.components[index].zoneId = ZoneContainment.zone(
                holding: model.components[index].centre,
                in: model.zones
            )?.id
        }
        return model
    }
}
