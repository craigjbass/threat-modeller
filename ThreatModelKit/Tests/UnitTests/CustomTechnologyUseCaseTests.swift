import Testing
import ThreatModelKit
import TestSupport

@Suite("Defining a technology the catalogue does not hold")
struct CustomTechnologyUseCaseTests {
    private func dependencies() -> TestDependencies { TestDependencies() }

    private func request(
        name: String = "Our Billing Service",
        categoryId: String = "compute",
        description: String = "Charges the customer",
        threatIds: [String] = [],
        enforcesEncryption: Bool = false
    ) -> CreateCustomTechnologyRequest {
        CreateCustomTechnologyRequest(
            name: name,
            categoryId: categoryId,
            description: description,
            threatIds: threatIds,
            enforcesEncryption: enforcesEncryption
        )
    }

    @Test func namesTheTechnologyItCreates() throws {
        let dependencies = dependencies()

        let response = dependencies.createCustomTechnology().execute(request())

        guard case .created(let technologyId) = response else {
            Issue.record("expected .created, got \(response)")
            return
        }
        let listed = dependencies.listTechnologies().execute(ListTechnologiesRequest())
        let ours = listed.providers
            .flatMap(\.categories)
            .flatMap(\.technologies)
            .first { $0.id == technologyId }
        #expect(try #require(ours).name == "Our Billing Service")
    }

    @Test func refusesATechnologyWithNoName() {
        let response = dependencies().createCustomTechnology().execute(request(name: "   "))

        #expect(response == .emptyName)
    }

    @Test func refusesACategoryTheTaxonomyDoesNotHold() {
        let response = dependencies().createCustomTechnology().execute(request(categoryId: "nonsense"))

        #expect(response == .unknownCategory)
    }

    @Test func placesTheTechnologyItCreatedUnderItsCategory() throws {
        let dependencies = dependencies()
        _ = dependencies.createCustomTechnology().execute(request(categoryId: "database"))

        let listed = dependencies.listTechnologies().execute(ListTechnologiesRequest())
        let database = listed.providers
            .flatMap(\.categories)
            .filter { $0.id == "database" }
            .flatMap(\.technologies)
        #expect(database.contains { $0.name == "Our Billing Service" })
    }

    @Test func raisesTheThreatsTheUserChose() throws {
        let dependencies = dependencies()
        let threatId = try #require(
            dependencies.listThreatChoices().execute(ListThreatChoicesRequest()).threats.first?.id
        )
        guard case .created(let technologyId) = dependencies.createCustomTechnology()
            .execute(request(threatIds: [threatId])) else {
            Issue.record("the technology was not created")
            return
        }
        _ = dependencies.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 100, y: 100, sensitivity: "internal")
        )

        let assessment = dependencies.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessment.threats.contains { $0.threatId == threatId })
    }

    @Test func changesEveryPropertyAtOnce() throws {
        let dependencies = dependencies()
        guard case .created(let technologyId) = dependencies.createCustomTechnology()
            .execute(request()) else {
            Issue.record("the technology was not created")
            return
        }

        let response = dependencies.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: technologyId,
                name: "Our Ledger",
                categoryId: "database",
                description: "Keeps the balances",
                threatIds: [],
                enforcesEncryption: true
            )
        )

        #expect(response == .updated)
        let listed = dependencies.listTechnologies().execute(ListTechnologiesRequest())
        let database = listed.providers
            .flatMap(\.categories)
            .filter { $0.id == "database" }
            .flatMap(\.technologies)
        #expect(database.contains { $0.id == technologyId && $0.name == "Our Ledger" })
    }

    @Test func leavesTheTechnologyAloneWhenOneValueIsBad() throws {
        let dependencies = dependencies()
        guard case .created(let technologyId) = dependencies.createCustomTechnology()
            .execute(request()) else {
            Issue.record("the technology was not created")
            return
        }

        let response = dependencies.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: technologyId,
                name: "Our Ledger",
                categoryId: "nonsense",
                description: "Keeps the balances",
                threatIds: [],
                enforcesEncryption: true
            )
        )

        #expect(response == .unknownCategory)
        let listed = dependencies.listTechnologies().execute(ListTechnologiesRequest())
        let ours = listed.providers
            .flatMap(\.categories)
            .flatMap(\.technologies)
            .first { $0.id == technologyId }
        #expect(try #require(ours).name == "Our Billing Service")
    }

    @Test func refusesToEditATechnologyTheModelDoesNotDefine() {
        let response = dependencies().editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: "aws-ec2",
                name: "Our EC2",
                categoryId: "compute",
                description: "",
                threatIds: [],
                enforcesEncryption: false
            )
        )

        #expect(response == .unknownTechnology)
    }

    @Test func deletesTheComponentsThatUsedTheTechnology() throws {
        let dependencies = dependencies()
        guard case .created(let technologyId) = dependencies.createCustomTechnology()
            .execute(request()) else {
            Issue.record("the technology was not created")
            return
        }
        guard case .added(let componentId) = dependencies.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 100, y: 100, sensitivity: "internal")
        ) else {
            Issue.record("the component was not added")
            return
        }

        let response = dependencies.deleteCustomTechnology().execute(
            DeleteCustomTechnologyRequest(technologyId: technologyId)
        )

        #expect(response == .deleted(removedComponentIds: [componentId], removedConnectionIds: []))
        let view = dependencies.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.isEmpty)
    }

    @Test func deletesTheConnectionsThoseComponentsCarried() throws {
        let dependencies = dependencies()
        guard case .created(let technologyId) = dependencies.createCustomTechnology()
            .execute(request()) else {
            Issue.record("the technology was not created")
            return
        }
        guard case .added(let ours) = dependencies.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 100, y: 100, sensitivity: "internal")
        ), case .added(let theirs) = dependencies.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 400, y: 100, sensitivity: "internal")
        ) else {
            Issue.record("the components were not added")
            return
        }
        guard case .connected(let connectionId) = dependencies.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: ours, targetComponentId: theirs)
        ) else {
            Issue.record("the components were not connected")
            return
        }

        let response = dependencies.deleteCustomTechnology().execute(
            DeleteCustomTechnologyRequest(technologyId: technologyId)
        )

        #expect(response == .deleted(removedComponentIds: [ours], removedConnectionIds: [connectionId]))
        let view = dependencies.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.connections.isEmpty)
        #expect(view.components.map(\.id) == [theirs])
    }

    @Test func refusesToDeleteATechnologyTheModelDoesNotDefine() {
        let response = dependencies().deleteCustomTechnology().execute(
            DeleteCustomTechnologyRequest(technologyId: "aws-ec2")
        )

        #expect(response == .unknownTechnology)
    }

    @Test func offersTheWorstThreatsFirst() {
        let threats = dependencies().listThreatChoices().execute(ListThreatChoicesRequest()).threats

        #expect(threats.isEmpty == false)
        #expect(threats.first?.severityLabel == "Critical")
        #expect(threats.contains { $0.strideLabels.isEmpty == false })
    }

    @Test func offersEachThreatOnce() {
        let threats = dependencies().listThreatChoices().execute(ListThreatChoicesRequest()).threats

        #expect(Set(threats.map(\.id)).count == threats.count)
    }
}
