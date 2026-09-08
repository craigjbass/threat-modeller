import Testing
import ThreatModelKit
import TestSupport

struct AssessThreatModelTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func assess(_ model: ThreatModel) -> AssessThreatModelResponse {
        AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest())
    }

    private func ec2(
        id: String = "c1",
        sensitivity: DataSensitivity = .confidential,
        customName: String? = nil,
        threatsDisabled: Bool = false,
        position: Point = Point(x: 0, y: 0)
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: position,
            sensitivity: sensitivity,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
    }

    private func rds(
        id: String = "c2",
        sensitivity: DataSensitivity = .confidential,
        threatsDisabled: Bool = false,
        position: Point = Point(x: 0, y: 0)
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-rds"),
            position: position,
            sensitivity: sensitivity,
            threatsDisabled: threatsDisabled
        )
    }

    private func link(_ id: String, _ source: String, _ target: String) -> Connection {
        Connection(id: ConnectionId(id), source: ComponentId(source), target: ComponentId(target))
    }

    @Test func raisesNothingForAnEmptyModel() {
        #expect(assess(ThreatModel()).threats.isEmpty)
    }

    @Test func raisesEveryThreatTheTechnologyDeclares() {
        let response = assess(ThreatModel(components: [ec2()]))
        #expect(response.threats.map(\.threatId) == ["credential-theft", "misconfiguration", "dos-attack"])
    }

    @Test func scoresSeverityAgainstTheComponentsSensitivity() throws {
        let response = assess(ThreatModel(components: [ec2(sensitivity: .confidential)]))

        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(credentialTheft.riskScore == 12)
        #expect(credentialTheft.riskLevel == "critical")
        #expect(credentialTheft.severityId == "critical")
        #expect(credentialTheft.severityLabel == "Critical")
        #expect(credentialTheft.sensitivityId == "confidential")

        let misconfiguration = try #require(response.threats.first { $0.threatId == "misconfiguration" })
        #expect(misconfiguration.riskScore == 6)
        #expect(misconfiguration.riskLevel == "medium")

        let dos = try #require(response.threats.first { $0.threatId == "dos-attack" })
        #expect(dos.riskScore == 3)
        #expect(dos.riskLevel == "low")
    }

    @Test func ordersByScoreThenThreatIdThenSource() {
        let response = assess(
            ThreatModel(components: [ec2(id: "c2"), ec2(id: "c1", sensitivity: .publicData)])
        )
        let ordering = response.threats.map { "\($0.riskScore):\($0.threatId):\($0.source.id)" }
        #expect(ordering == [
            "12:credential-theft:component:c2",
            "6:misconfiguration:component:c2",
            "4:credential-theft:component:c1",
            "3:dos-attack:component:c2",
            "2:misconfiguration:component:c1",
            "1:dos-attack:component:c1"
        ])
    }

    @Test func namesTheSourceAfterTheTechnologyUnlessRenamed() throws {
        let plain = assess(ThreatModel(components: [ec2()]))
        #expect(try #require(plain.threats.first).source
                == .component(id: "c1", name: "EC2", providerId: "aws"))
        #expect(try #require(plain.threats.first).source.displayName == "EC2")

        let renamed = assess(ThreatModel(components: [ec2(customName: "Bastion host")]))
        #expect(try #require(renamed.threats.first).source.displayName == "Bastion host")
    }

    @Test func prefersTechnologySpecificMitigationsOverGenericControls() throws {
        let response = assess(ThreatModel(components: [ec2()]))

        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(credentialTheft.controls.allSatisfy { $0.isTechnologySpecific })
        #expect(credentialTheft.controls.map(\.description) == [
            "Enforce IMDSv2 to block SSRF-based credential theft",
            "Use IAM roles with minimal permissions"
        ])

        let misconfiguration = try #require(response.threats.first { $0.threatId == "misconfiguration" })
        #expect(misconfiguration.controls.contains(where: \.isTechnologySpecific) == false)
        #expect(misconfiguration.controls.map(\.description) == ["Scan configuration continuously"])
    }

    @Test func carriesTechnologySpecificContextWhenThereIsSome() throws {
        let response = assess(ThreatModel(components: [ec2()]))
        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        let dos = try #require(response.threats.first { $0.threatId == "dos-attack" })

        #expect(credentialTheft.context == "Instance Metadata Service credential theft")
        #expect(dos.context == nil)
    }

    @Test func carriesStrideAndMitreThrough() throws {
        let response = assess(ThreatModel(components: [ec2()]))
        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })

        #expect(credentialTheft.stride == ["spoofing"])
        #expect(credentialTheft.mitreTechniques == [
            AssessedMitreTechnique(id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access")
        ])
    }

    @Test func raisesNothingForAComponentWithThreatsDisabled() {
        let response = assess(ThreatModel(components: [ec2(threatsDisabled: true)]))
        #expect(response.threats.isEmpty)
    }

    @Test func ignoresAComponentWhoseTechnologyIsNotInTheCatalogue() {
        let orphan = Component(
            id: ComponentId("c9"),
            technologyId: TechnologyId("aws-nope"),
            position: Point(x: 0, y: 0),
            sensitivity: .restricted
        )
        #expect(assess(ThreatModel(components: [orphan])).threats.isEmpty)
    }

    @Test func raisesEveryConnectionThreatOnALink() {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), rds(sensitivity: .internalData)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let onTheLink = response.threats.filter {
            if case .connection = $0.source { return true } else { return false }
        }
        #expect(onTheLink.map(\.threatId) == ["connection-mitm", "connection-dos"])
        #expect(onTheLink.allSatisfy { $0.source.id == "connection:k1" })
        #expect(onTheLink.first?.source.displayName == "EC2 \u{2192} RDS")
    }

    @Test func scoresALinkAgainstTheHigherOfItsTwoEndSensitivities() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .publicData), rds(sensitivity: .restricted)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.sensitivityId == "restricted")
        #expect(mitm.riskScore == 8)
        #expect(mitm.riskLevel == "high")
    }

    @Test func alwaysUsesTheThreatsOwnControlsOnALink() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1"), rds()],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.controls.map(\.description) == ["Enforce TLS on every hop"])
        #expect(mitm.controls.contains(where: \.isTechnologySpecific) == false)
        #expect(mitm.context == nil)
    }

    @Test func flagsTlsMitigationWithoutChangingTheScore() throws {
        // RDS enforces encryption in the fixture; EC2 does not.
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), rds(sensitivity: .internalData)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        let flood = try #require(response.threats.first { $0.threatId == "connection-dos" })

        #expect(mitm.isTlsMitigated)
        #expect(mitm.riskScore == 4)
        #expect(flood.isTlsMitigated == false)
        #expect(flood.riskScore == 2)
    }

    @Test func neverFlagsTlsMitigationOnAComponentThreat() {
        let response = assess(ThreatModel(components: [ec2()]))
        #expect(response.threats.allSatisfy { $0.isTlsMitigated == false })
    }

    @Test func raisesNothingOnALinkTouchingAComponentWithThreatsDisabled() {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1"), rds(threatsDisabled: true)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        #expect(response.threats.allSatisfy {
            if case .connection = $0.source { return false } else { return true }
        })
    }

    @Test func raisesNothingOnALinkWhoseEndIsNotOnTheModel() {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], connections: [link("k1", "c1", "c9")])
        )

        #expect(response.threats.allSatisfy {
            if case .connection = $0.source { return false } else { return true }
        })
    }

    @Test func stillRaisesLinkThreatsWhenAnEndsTechnologyLeftTheCatalogue() throws {
        let orphan = Component(
            id: ComponentId("c2"),
            technologyId: TechnologyId("aws-nope"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), orphan],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.source.displayName == "EC2 \u{2192} aws-nope")
        #expect(mitm.isTlsMitigated == false)
    }

    @Test func raisesLinkThreatsOncePerLink() {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1"), rds(), ec2(id: "c3")],
                connections: [link("k1", "c1", "c2"), link("k2", "c1", "c3")]
            )
        )

        let mitm = response.threats.filter { $0.threatId == "connection-mitm" }
        #expect(mitm.map(\.source.id).sorted() == ["connection:k1", "connection:k2"])
    }

    @Test func raisesADuplicateThreatAndSourcePairOnlyOnce() {
        // A technology that declares the same threat twice must not produce two
        // rows. Spec section 5.3. No vendored technology does this today.
        let doubled = Technology(
            id: TechnologyId("aws-doubled"),
            name: "Doubled",
            provider: ProviderId("aws"),
            category: CategoryId("compute"),
            description: "Declares one threat twice",
            threatIds: [ThreatId("misconfiguration"), ThreatId("misconfiguration")]
        )
        let catalogue = InMemoryTechnologyCatalogue(
            technologies: [doubled],
            threats: CatalogueFixture.ec2Threats() + CatalogueFixture.connectionThreats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )
        let model = ThreatModel(components: [
            Component(
                id: ComponentId("c1"),
                technologyId: TechnologyId("aws-doubled"),
                position: Point(x: 0, y: 0),
                sensitivity: .internalData
            )
        ])

        let response = AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest())

        #expect(response.threats.map(\.threatId) == ["misconfiguration"])
    }

    /// A zone that captures a component left at the origin. Its top edge sits
    /// above the origin, because containment ignores the top 40 points and a
    /// component at 0,0 has its centre at 80,36.
    private func privateZone(
        _ id: String = "z1",
        x: Double = -100,
        y: Double = -100,
        reduction: Int = 20,
        enabled: Bool = true,
        kind: NetworkZone = .privateZone
    ) -> Zone {
        Zone(
            id: ZoneId(id),
            rect: Rect(x: x, y: y, width: 800, height: 700),
            networkZone: kind,
            riskReductionEnabled: enabled,
            riskReductionPercent: reduction
        )
    }

    private func zoneThreats(_ response: AssessThreatModelResponse) -> [AssessedThreat] {
        response.threats.filter {
            if case .zone = $0.source { return true } else { return false }
        }
    }

    @Test func reducesAComponentThreatInsideAPrivateZone() throws {
        // Credential theft is critical (4) against confidential data (3), so 12
        // before the zone. A 20 per cent reduction leaves 9.6, which rounds to
        // 10 and drops the level from critical to high.
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone()])
        )

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.riskScore == 10)
        #expect(theft.riskLevel == "high")
    }

    @Test func leavesAComponentThreatAloneOutsideEveryZone() throws {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1", position: Point(x: 2000, y: 2000))],
                        zones: [privateZone()])
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 12)
    }

    @Test func leavesAComponentThreatAloneInAPublicZone() throws {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone(kind: .publicZone)])
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 12)
    }

    @Test func leavesAComponentThreatAloneWhenReductionIsOff() throws {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone(reduction: 90, enabled: false)])
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 12)
    }

    @Test func dropsAComponentThreatTheZoneReducesToNothing() {
        // Denial of service is low (1) against confidential data (3), so 3.
        // A 90 per cent reduction leaves 0.3, which rounds to 0 and is filtered.
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone(reduction: 90)])
        )

        #expect(response.threats.contains {
            $0.threatId == "dos-attack" && $0.source.id == "component:c1"
        } == false)
    }

    @Test func usesTheLaterOfTwoOverlappingZones() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1")],
                zones: [privateZone("z1", reduction: 0), privateZone("z2", reduction: 50)]
            )
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 6)
    }

    @Test func reducesALinkOnlyWhenBothEndsAreInPrivateZones() throws {
        // Man-in-the-middle is medium (2) against internal data (2), so 4.
        let bothInside = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData)
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [privateZone(reduction: 50)]
            )
        )
        #expect(try #require(bothInside.threats.first { $0.threatId == "connection-mitm" }).riskScore == 2)

        let oneOutside = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData, position: Point(x: 3000, y: 3000))
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [privateZone(reduction: 50)]
            )
        )
        #expect(try #require(oneOutside.threats.first { $0.threatId == "connection-mitm" }).riskScore == 4)
    }

    @Test func givesALinkTheLowerOfTheTwoZoneReductions() throws {
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData, position: Point(x: 1000, y: 100))
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [
                    privateZone("z1", x: 0, y: 0, reduction: 25),
                    privateZone("z2", x: 900, y: 0, reduction: 75)
                ]
            )
        )

        // 25 per cent is the lower reduction, so 4 becomes 3.
        #expect(try #require(response.threats.first { $0.threatId == "connection-mitm" }).riskScore == 3)
    }

    @Test func givesALinkNoReductionWhenOneEndsZoneHasReductionOff() throws {
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData, position: Point(x: 1000, y: 100))
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [
                    privateZone("z1", x: 0, y: 0, reduction: 90, enabled: false),
                    privateZone("z2", x: 900, y: 0, reduction: 75)
                ]
            )
        )

        #expect(try #require(response.threats.first { $0.threatId == "connection-mitm" }).riskScore == 4)
    }

    @Test func raisesEveryZoneThreatOncePerPrivateZone() {
        let response = assess(ThreatModel(zones: [privateZone("z1"), privateZone("z2", x: 2000)]))

        let raised = zoneThreats(response)
        #expect(Set(raised.map(\.threatId)) == ["misconfiguration", "lateral-movement"])
        #expect(Set(raised.map(\.source.id)) == ["zone:z1", "zone:z2"])
        #expect(raised.count == 4)
    }

    @Test func raisesNoZoneThreatsForAPublicZone() {
        let response = assess(ThreatModel(zones: [privateZone(kind: .publicZone)]))

        #expect(zoneThreats(response).isEmpty)
    }

    @Test func scoresAZoneThreatAgainstInternalDataAndTheZonesOwnReduction() throws {
        // Lateral movement is high (3) against internal data (2), so 6.
        // A 20 per cent reduction leaves 4.8, which rounds to 5.
        let response = assess(ThreatModel(zones: [privateZone(reduction: 20)]))

        let lateral = try #require(zoneThreats(response).first { $0.threatId == "lateral-movement" })
        #expect(lateral.sensitivityId == "internal")
        #expect(lateral.riskScore == 5)
        #expect(lateral.riskLevel == "medium")

        let unreduced = assess(ThreatModel(zones: [privateZone(enabled: false)]))
        #expect(try #require(zoneThreats(unreduced).first { $0.threatId == "lateral-movement" }).riskScore == 6)
    }

    @Test func showsTheZonesDisplayNameAndTheThreatsZoneWording() throws {
        let named = Zone(
            id: ZoneId("z1"),
            rect: Rect(x: 0, y: 0, width: 600, height: 500),
            name: "Payments"
        )
        let response = assess(ThreatModel(zones: [named]))

        let lateral = try #require(zoneThreats(response).first { $0.threatId == "lateral-movement" })
        #expect(lateral.source == .zone(id: "z1", name: "Payments"))
        #expect(lateral.source.displayName == "Payments")
        #expect(lateral.context == "Pivoting between resources inside the network zone")
        #expect(lateral.isTlsMitigated == false)
    }

    @Test func alwaysUsesTheThreatsOwnControlsOnAZone() throws {
        let response = assess(ThreatModel(zones: [privateZone()]))

        let misconfiguration = try #require(
            zoneThreats(response).first { $0.threatId == "misconfiguration" }
        )
        #expect(misconfiguration.controls.map(\.description) == ["Scan configuration continuously"])
        #expect(misconfiguration.controls.contains(where: \.isTechnologySpecific) == false)
    }

    @Test func tellsAComponentThreatApartFromTheSameThreatOnItsZone() {
        // EC2 declares misconfiguration and the zone raises it too. Two rows,
        // two sources, and the deduplication rule leaves both alone.
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone("z1")])
        )

        let rows = response.threats.filter { $0.threatId == "misconfiguration" }
        #expect(rows.map(\.source.id).sorted() == ["component:c1", "zone:z1"])
    }
}
