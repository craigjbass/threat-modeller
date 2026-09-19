import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The Open Threat Model export: what it writes for a component and a flow
/// beyond the tags it synthesises.
@Suite("The Open Threat Model export")
struct ExportModelAsOtmTests {
    private let catalogue = CatalogueFixture.catalogue()

    /// GAP: the OTM `tags` fields are synthesised from technology,
    /// sensitivity, privilege, status and flow kind, never from the model's
    /// own tags.
    @Test func writesTheModelSOwnTagsSeparatelyFromTheSynthesisedOnes() throws {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    tags: ["billing", "tier-1"]
                ),
                Component(
                    id: ComponentId("c2"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 300, y: 0),
                    sensitivity: .confidential
                )
            ],
            connections: [
                Connection(
                    id: ConnectionId("f1"),
                    source: ComponentId("c1"),
                    target: ComponentId("c2"),
                    tags: ["pci"]
                )
            ]
        )

        let json = ExportModelAsOtm(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model),
                catalogue: catalogue
            )
        ).execute(ExportModelAsOtmRequest()).json

        let document = try #require(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        let components = try #require(document["components"] as? [[String: Any]])
        let component = try #require(components.first { $0["id"] as? String == "c1" })
        let modelTags = try #require(component["modelTags"] as? [String])
        let syntheticTags = try #require(component["tags"] as? [String])

        #expect(modelTags == ["billing", "tier-1"])
        #expect(syntheticTags.contains("aws-ec2"))
        #expect(syntheticTags.contains("billing") == false)

        let dataflows = try #require(document["dataflows"] as? [[String: Any]])
        let flow = try #require(dataflows.first)
        #expect(flow["modelTags"] as? [String] == ["pci"])
    }

    /// GAP: a flow may name a user, and a user is not a component, so the
    /// file pointed a dataflow at an id it declared nowhere.
    @Test func everyElementADataflowNamesIsDeclared() throws {
        let model = ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("api"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                ),
                Component(
                    id: ComponentId("alice"),
                    technologyId: Component.userTechnologyId,
                    position: Point(x: -300, y: 0),
                    sensitivity: .internalData,
                    customName: "Alice",
                    user: UserFacts(role: "Operator")
                )
            ],
            connections: [
                Connection(
                    id: ConnectionId("f1"),
                    source: ComponentId("alice"),
                    target: ComponentId("api")
                )
            ]
        )

        let json = ExportModelAsOtm(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model),
                catalogue: catalogue
            )
        ).execute(ExportModelAsOtmRequest()).json

        let document = try #require(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        let declared = Set(
            try #require(document["components"] as? [[String: Any]])
                .compactMap { $0["id"] as? String }
        )
        let dataflows = try #require(document["dataflows"] as? [[String: Any]])
        #expect(dataflows.isEmpty == false)
        for flow in dataflows {
            let source = try #require(flow["source"] as? String)
            let destination = try #require(flow["destination"] as? String)
            #expect(declared.contains(source), "no component declares \(source)")
            #expect(declared.contains(destination), "no component declares \(destination)")
        }
        #expect(declared.contains("Alice"))
    }
}
