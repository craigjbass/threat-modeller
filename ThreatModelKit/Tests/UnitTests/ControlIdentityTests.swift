import Testing
import ThreatModelKit

struct ControlIdentityTests {
    @Test func hashesADescriptionToEightHexDigits() {
        let fingerprint = ControlIdentity.fingerprint(of: "Rotate credentials regularly")

        #expect(fingerprint.count == 8)
        #expect(fingerprint.allSatisfy { $0.isHexDigit })
        #expect(fingerprint == fingerprint.lowercased())
    }

    @Test func givesTheSameDescriptionTheSameFingerprint() {
        #expect(ControlIdentity.fingerprint(of: "Apply rate limits")
                == ControlIdentity.fingerprint(of: "Apply rate limits"))
    }

    @Test func givesTwoDescriptionsDifferentFingerprints() {
        #expect(ControlIdentity.fingerprint(of: "Apply rate limits")
                != ControlIdentity.fingerprint(of: "Apply rate limiting"))
    }

    @Test func ignoresSurroundingAndRepeatedWhitespace() {
        let plain = ControlIdentity.fingerprint(of: "Rotate credentials regularly")

        #expect(ControlIdentity.fingerprint(of: "  Rotate credentials regularly  ") == plain)
        #expect(ControlIdentity.fingerprint(of: "Rotate   credentials\tregularly") == plain)
        #expect(ControlIdentity.fingerprint(of: "Rotate\ncredentials regularly") == plain)
    }

    @Test func matchesTheDjb2AlgorithmTheSpecStates() {
        // hash = 5381; hash = hash * 33 + byte, unsigned 32-bit.
        // "a" -> 5381 * 33 + 97 = 177670 = 0x0002b606
        #expect(ControlIdentity.fingerprint(of: "a") == "0002b606")
        // "" -> 5381 = 0x00001505
        #expect(ControlIdentity.fingerprint(of: "") == "00001505")
    }

    @Test func scopesAComponentsGenericControl() {
        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials regularly",
            isTechnologySpecific: false
        )

        #expect(key.value == "node:c1:credential-theft::\(ControlIdentity.fingerprint(of: "Rotate credentials regularly"))")
    }

    @Test func marksATechnologysOwnMitigationApart() {
        let generic = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2",
            isTechnologySpecific: false
        )
        let specific = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2",
            isTechnologySpecific: true
        )

        #expect(specific.value.contains(":tech::"))
        #expect(generic != specific)
    }

    @Test func consolidatesALinksControlAcrossEveryLink() {
        let key = ControlIdentity.connectionControl(
            threatId: ThreatId("connection-mitm"),
            description: "Enforce TLS on every hop"
        )

        #expect(key.value == "connection:connection-mitm::\(ControlIdentity.fingerprint(of: "Enforce TLS on every hop"))")
    }

    @Test func consolidatesAZonesControlAcrossEveryZone() {
        let key = ControlIdentity.zoneControl(
            threatId: ThreatId("lateral-movement"),
            description: "Segment the network"
        )

        #expect(key.value == "zone:lateral-movement::\(ControlIdentity.fingerprint(of: "Segment the network"))")
    }

    @Test func givesAComponentAPrefixItsKeysArePrunedBy() {
        let prefix = ControlIdentity.componentPrefix(ComponentId("c1"))
        let mine = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )
        let theirs = ControlIdentity.componentControl(
            componentId: ComponentId("c2"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )

        #expect(prefix == "node:c1:")
        #expect(mine.value.hasPrefix(prefix))
        #expect(theirs.value.hasPrefix(prefix) == false)
    }
}

@Suite("Reading a control key back")
struct ControlKeyReadingTests {
    @Test func readsAComponentKey() throws {
        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Use IAM roles",
            isTechnologySpecific: false
        )

        let read = try #require(ControlIdentity.read(key))
        #expect(read.threatId == ThreatId("credential-theft"))
        #expect(read.fingerprint == ControlIdentity.fingerprint(of: "Use IAM roles"))
    }

    @Test func readsATechnologySpecificComponentKey() throws {
        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2",
            isTechnologySpecific: true
        )

        #expect(try #require(ControlIdentity.read(key)).threatId == ThreatId("credential-theft"))
    }

    @Test func readsALinkKeyAndAZoneKey() throws {
        let link = ControlIdentity.connectionControl(
            threatId: ThreatId("connection-mitm"),
            description: "Use TLS"
        )
        let zone = ControlIdentity.zoneControl(
            threatId: ThreatId("lateral-movement"),
            description: "Segment the zone"
        )

        #expect(try #require(ControlIdentity.read(link)).threatId == ThreatId("connection-mitm"))
        #expect(try #require(ControlIdentity.read(zone)).threatId == ThreatId("lateral-movement"))
    }

    @Test func readsNothingFromAKeyOfNoKnownShape() {
        #expect(ControlIdentity.read(ControlKey("nonsense")) == nil)
        #expect(ControlIdentity.read(ControlKey("node:c1::0002b606")) == nil)
        #expect(ControlIdentity.read(ControlKey("thing:x::short")) == nil)
    }
}
