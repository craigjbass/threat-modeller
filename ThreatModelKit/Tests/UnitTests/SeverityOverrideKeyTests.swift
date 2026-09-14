import Testing
import ThreatModelKit

struct SeverityOverrideKeyTests {
    @Test func keysAComponentThreatByItsComponent() {
        // Spec section 5.3. An override set on one EC2 node stays on that
        // node, because the key names the component and not the technology.
        let key = SeverityOverrideKey.forComponent(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft")
        )

        #expect(key.value == "node:c1::credential-theft")
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
            SeverityOverrideKey.forComponent(componentId: ComponentId("c1"), threatId: ThreatId("x")),
            SeverityOverrideKey.forConnection(threatId: ThreatId("x")),
            SeverityOverrideKey.forZone(threatId: ThreatId("x"))
        ])

        #expect(keys.count == 3)
    }

    /// A component named after another kind cannot write a key that kind
    /// reads. The component shape carries `node:` and the other two carry no
    /// id, so the three sets of keys can never meet.
    @Test func aComponentNamedConnectionOrZoneCannotCollide() {
        let threatId = ThreatId("x")
        let named = [ComponentId("connection"), ComponentId("zone"), ComponentId("node")]

        let componentKeys = named.map {
            SeverityOverrideKey.forComponent(componentId: $0, threatId: threatId)
        }
        let otherKeys = [
            SeverityOverrideKey.forConnection(threatId: threatId),
            SeverityOverrideKey.forZone(threatId: threatId)
        ]

        #expect(Set(componentKeys).isDisjoint(with: Set(otherKeys)))
        #expect(Set(componentKeys).count == named.count)
    }

    /// A technology named after another kind cannot collide either: the key
    /// never names a technology.
    @Test func noKeyNamesATechnology() {
        let key = SeverityOverrideKey.forComponent(
            componentId: ComponentId("c1"),
            threatId: ThreatId("x")
        )

        #expect(key.value.contains("aws-ec2") == false)
        #expect(key.value == "node:c1::x")
    }
}

@Suite("Reading an override written before the element keying")
struct SeverityOverrideMigrationTests {
    private func component(_ id: String, technologyId: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technologyId),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    @Test func writesATechnologyKeyedOverrideOntoEveryComponentOfThatTechnology() {
        let migrated = SeverityOverrideMigration.migrated(
            [SeverityOverrideKey("aws-ec2::credential-theft"): "critical"],
            components: [
                component("c1", technologyId: "aws-ec2"),
                component("c2", technologyId: "aws-ec2"),
                component("c3", technologyId: "aws-rds")
            ]
        )

        #expect(migrated == [
            SeverityOverrideKey("node:c1::credential-theft"): "critical",
            SeverityOverrideKey("node:c2::credential-theft"): "critical"
        ])
    }

    @Test func keepsALinkOverrideAndAZoneOverrideAsTheyAre() {
        let overrides: [SeverityOverrideKey: String] = [
            SeverityOverrideKey("connection::connection-mitm"): "high",
            SeverityOverrideKey("zone::lateral-movement"): "low"
        ]

        #expect(SeverityOverrideMigration.migrated(overrides, components: []) == overrides)
    }

    @Test func readsAnOverrideItHasAlreadyMigratedUnchanged() {
        let overrides: [SeverityOverrideKey: String] = [
            SeverityOverrideKey("node:c1::credential-theft"): "critical"
        ]

        #expect(
            SeverityOverrideMigration.migrated(
                overrides,
                components: [component("c1", technologyId: "aws-ec2")]
            ) == overrides
        )
    }

    @Test func dropsATechnologyKeyedOverrideNoComponentUses() {
        #expect(
            SeverityOverrideMigration.migrated(
                [SeverityOverrideKey("aws-ec2::credential-theft"): "critical"],
                components: [component("c3", technologyId: "aws-rds")]
            ) == [:]
        )
    }

    @Test func theNewShapeWinsOverTheOldOneForTheSameElement() {
        let migrated = SeverityOverrideMigration.migrated(
            [
                SeverityOverrideKey("aws-ec2::credential-theft"): "low",
                SeverityOverrideKey("node:c1::credential-theft"): "critical"
            ],
            components: [component("c1", technologyId: "aws-ec2")]
        )

        #expect(migrated == [SeverityOverrideKey("node:c1::credential-theft"): "critical"])
    }
}
