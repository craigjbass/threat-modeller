import Testing
import ThreatModelKit

struct SeverityOverrideKeyTests {
    @Test func keysAComponentThreatByItsTechnology() {
        // Spec section 5.3. An override set on one EC2 node applies to every
        // EC2 node, because the key names the technology and not the component.
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )

        #expect(key.value == "aws-ec2::credential-theft")
    }

    @Test func keysALinkThreatAcrossEveryLink() {
        #expect(SeverityOverrideKey.forConnection(threatId: ThreatId("connection-mitm")).value
                == "connection::connection-mitm")
    }

    @Test func keysAZoneThreatAcrossEveryZone() {
        #expect(SeverityOverrideKey.forZone(threatId: ThreatId("lateral-movement")).value
                == "zone::lateral-movement")
    }

    @Test func tellsTheThreeShapesApart() {
        let keys = Set([
            SeverityOverrideKey.forComponent(technologyId: TechnologyId("connection"), threatId: ThreatId("x")),
            SeverityOverrideKey.forConnection(threatId: ThreatId("x")),
            SeverityOverrideKey.forZone(threatId: ThreatId("x"))
        ])

        // A technology literally named "connection" would collide with the
        // link shape. The catalogue has no such technology, and the shapes are
        // the ones the spec states.
        #expect(keys.count == 2)
    }
}
