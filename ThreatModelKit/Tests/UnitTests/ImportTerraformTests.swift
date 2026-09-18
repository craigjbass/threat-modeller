import ArchitectureDSL
import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("Drawing what a Terraform state holds")
struct ImportTerraformTests {
    private let architecture = HclArchitectureSource()

    private func importing() -> ImportTerraform {
        ImportTerraform(sources: HclArchitectureSource())
    }

    private static func state(_ name: String) throws -> String {
        try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Goldens")
                .appendingPathComponent(name),
            encoding: .utf8
        )
    }

    private func imported(
        _ stateName: String,
        into architectureText: String? = nil
    ) throws -> (text: String, added: [String], removed: [String], unmapped: [(type: String, count: Int)]) {
        try importedText(Self.state(stateName), into: architectureText)
    }

    private func importedText(
        _ stateText: String,
        into architectureText: String? = nil
    ) -> (text: String, added: [String], removed: [String], unmapped: [(type: String, count: Int)]) {
        let response = importing().execute(
            ImportTerraformRequest(
                stateText: stateText,
                architectureText: architectureText,
                systemName: "Payments"
            )
        )
        guard case .imported(let text, let added, let removed, _, _, _, let unmapped) = response
        else {
            Issue.record("the state did not import: \(response)")
            return ("", [], [], [])
        }
        return (text, added, removed, unmapped)
    }

    /// A small `terraform show -json` document, under `values.root_module`
    /// or `planned_values.root_module`, holding a zone, two components and
    /// an ingress rule that states a flow between them.
    private static func terraformDocument(topLevelKey: String) -> String {
        """
        {
          "\(topLevelKey)": {
            "root_module": {
              "resources": [
                {
                  "address": "aws_vpc.main",
                  "mode": "managed",
                  "type": "aws_vpc",
                  "name": "main",
                  "values": { "id": "vpc-01", "name": "main" }
                },
                {
                  "address": "aws_subnet.app",
                  "mode": "managed",
                  "type": "aws_subnet",
                  "name": "app",
                  "values": {
                    "id": "subnet-app",
                    "vpc_id": "vpc-01",
                    "map_public_ip_on_launch": true,
                    "name": "app"
                  }
                },
                {
                  "address": "aws_instance.api",
                  "mode": "managed",
                  "type": "aws_instance",
                  "name": "api",
                  "values": {
                    "id": "i-01",
                    "subnet_id": "subnet-app",
                    "vpc_security_group_ids": ["sg-api"],
                    "name": "api"
                  }
                },
                {
                  "address": "aws_db_instance.ledger",
                  "mode": "managed",
                  "type": "aws_db_instance",
                  "name": "ledger",
                  "values": {
                    "id": "db-01",
                    "subnet_id": "subnet-app",
                    "vpc_security_group_ids": ["sg-db"],
                    "name": "ledger"
                  }
                },
                {
                  "address": "aws_security_group_rule.db_from_api",
                  "mode": "managed",
                  "type": "aws_security_group_rule",
                  "name": "db_from_api",
                  "values": {
                    "id": "sgr-01",
                    "type": "ingress",
                    "security_group_id": "sg-db",
                    "source_security_group_id": "sg-api"
                  }
                }
              ]
            }
          }
        }
        """
    }

    // MARK: AWS

    @Test func drawsEachResourceAsTheTechnologyItIs() throws {
        let written = try imported("terraform-aws-state.json").text

        #expect(written.contains("component \"aws-instance-api\" {"))
        #expect(written.contains("technology = \"aws-ec2\""))
        #expect(written.contains("component \"aws-db-instance-ledger\" {"))
        #expect(written.contains("technology = \"aws-rds\""))
        #expect(written.contains("component \"aws-s3-bucket-receipts\" {"))
        #expect(written.contains("technology = \"aws-s3\""))
    }

    /// A module's resources are read the way the root module's are.
    @Test func readsTheResourcesOfEveryModule() throws {
        #expect(
            try imported("terraform-aws-state.json").text
                .contains("component \"module-workers-aws-lambda-function-settle\" {")
        )
    }

    @Test func drawsEachNetworkAsAZone() throws {
        let written = try imported("terraform-aws-state.json").text

        #expect(written.contains("zone \"aws-vpc-main\" {"))
        #expect(written.contains("zone \"aws-subnet-public\" {"))
        #expect(written.contains("kind    = \"public\""))
        #expect(written.contains("zone \"aws-subnet-private\" {"))
    }

    @Test func putsEachComponentInTheZoneItNames() throws {
        let source = try #require(architecture.read(try imported("terraform-aws-state.json").text).source)
        let publicZone = try #require(source.zones.first { $0.id == "aws-subnet-public" })
        let privateZone = try #require(source.zones.first { $0.id == "aws-subnet-private" })

        #expect(publicZone.components.map(\.id) == ["aws-instance-api"])
        #expect(privateZone.components.map(\.id) == ["aws-db-instance-ledger"])
        #expect(source.components.map(\.id).contains("aws-s3-bucket-receipts"))
    }

    /// An ingress rule naming a group on each side states a flow.
    @Test func drawsAFlowFromASecurityGroupRule() throws {
        let source = try #require(architecture.read(try imported("terraform-aws-state.json").text).source)

        #expect(
            source.flows.contains {
                $0.sourceId == "aws-instance-api" && $0.targetId == "aws-db-instance-ledger"
            }
        )
    }

    @Test func marksEveryImportedElement() throws {
        let written = try imported("terraform-aws-state.json").text

        #expect(written.contains("= \"terraform\""))
        let source = try #require(architecture.read(written).source)
        #expect(source.everyComponent.allSatisfy { $0.source == "terraform" })
        #expect(source.zones.allSatisfy { $0.source == "terraform" })
    }

    /// A resource type with no mapping is counted and named once, and the
    /// import still writes what it could.
    @Test func saysWhatItCouldNotMap() throws {
        let imported = try self.imported("terraform-aws-state.json")

        #expect(imported.unmapped.map(\.type) == ["aws_cloudwatch_metric_alarm"])
        #expect(imported.unmapped.first?.count == 1)
        #expect(imported.text.isEmpty == false)
    }

    /// A data source is a read, not a thing this system runs.
    @Test func readsNoDataSource() throws {
        #expect(
            try imported("terraform-aws-state.json").text.contains("aws-caller-identity") == false
        )
    }

    // MARK: Google Cloud

    @Test func drawsAGoogleCloudState() throws {
        let imported = try self.imported("terraform-gcp-state.json")
        let source = try #require(architecture.read(imported.text).source)

        #expect(source.zones.map(\.id).contains("google-compute-network-main"))
        #expect(source.zones.map(\.id).contains("google-compute-subnetwork-app"))
        let zone = try #require(source.zones.first { $0.id == "google-compute-subnetwork-app" })
        #expect(zone.components.map(\.id) == ["google-compute-instance-api"])
        #expect(imported.text.contains("technology = \"gcp-cloud-sql\""))
        #expect(imported.text.contains("technology = \"gcp-cloud-storage\""))
        #expect(imported.unmapped.map(\.type) == ["google_container_registry"])
    }

    // MARK: importing again

    /// A second import over the same state changes nothing.
    @Test func aSecondImportWritesTheSameBytes() throws {
        let first = try imported("terraform-aws-state.json")
        let second = try imported("terraform-aws-state.json", into: first.text)

        #expect(second.text == first.text)
        #expect(second.added.isEmpty)
        #expect(second.removed.isEmpty)
    }

    /// A resource gone from the state removes the element it made.
    @Test func aResourceGoneFromTheStateGoesFromTheFile() throws {
        let first = try imported("terraform-aws-state.json")
        let smaller = try Self.state("terraform-aws-state.json")
            .replacingOccurrences(of: "\"aws_s3_bucket\"", with: "\"aws_s3_bucket_gone\"")

        let response = importing().execute(
            ImportTerraformRequest(
                stateText: smaller,
                architectureText: first.text,
                systemName: "Payments"
            )
        )
        guard case .imported(let text, _, let removed, _, _, _, _) = response else {
            Issue.record("the state did not import: \(response)")
            return
        }

        #expect(removed == ["aws-s3-bucket-receipts"])
        #expect(text.contains("aws-s3-bucket-receipts") == false)
    }

    /// An element a person added by hand is never removed.
    @Test func anElementAPersonWroteStays() throws {
        let first = try imported("terraform-aws-state.json")
        let byHand = first.text.replacingOccurrences(
            of: "}\n",
            with: """
              component "the-card-network" {
                technology = "generic-host"
                data       = "restricted"
              }
            }

            """,
            options: [.backwards],
            range: first.text.range(of: "}\n", options: .backwards)
        )

        let second = try imported("terraform-aws-state.json", into: byHand)

        #expect(second.text.contains("component \"the-card-network\" {"))
        #expect(second.removed.isEmpty)
        #expect(second.text.contains("data       = \"restricted\""))
    }

    /// What a person wrote on an imported element stays; the technology and
    /// the zone take the state's word.
    @Test func whatAPersonWroteOnAnImportedElementStays() throws {
        let first = try imported("terraform-aws-state.json")
        let answered = first.text.replacingOccurrences(
            of: "    technology = \"aws-s3\"",
            with: "    technology = \"aws-s3\"\n    data       = \"restricted\""
        )

        let second = try imported("terraform-aws-state.json", into: answered)

        #expect(second.text.contains("data       = \"restricted\""))
    }

    // MARK: a plan file

    /// A plan file states `planned_values.root_module`, not
    /// `values.root_module`, and imports the same components, zones and
    /// flows a state file with the same resources imports.
    @Test func aPlanFileImportsTheSameElementsAsAStateFile() {
        let fromAPlan = importedText(Self.terraformDocument(topLevelKey: "planned_values"))
        let fromAState = importedText(Self.terraformDocument(topLevelKey: "values"))

        #expect(fromAPlan.text == fromAState.text)
        #expect(fromAPlan.text.contains("zone \"aws-vpc-main\" {"))
        #expect(fromAPlan.text.contains("component \"aws-instance-api\" {"))
        #expect(fromAPlan.text.contains("component \"aws-db-instance-ledger\" {"))
    }

    /// A document holding both keys reads `values`, not `planned_values`:
    /// `TerraformState.read` tries `values` first.
    @Test func aDocumentHoldingBothKeysReadsValues() {
        let bothKeys = """
        {
          "values": { "root_module": { "resources": [
            { "address": "aws_vpc.from_values", "mode": "managed", "type": "aws_vpc",
              "name": "from_values", "values": { "id": "v1", "name": "from-values" } }
          ] } },
          "planned_values": { "root_module": { "resources": [
            { "address": "aws_vpc.from_planned", "mode": "managed", "type": "aws_vpc",
              "name": "from_planned", "values": { "id": "v2", "name": "from-planned" } }
          ] } }
        }
        """
        let written = importedText(bothKeys).text

        #expect(written.contains("zone \"aws-vpc-from-values\" {"))
        #expect(written.contains("zone \"aws-vpc-from-planned\" {") == false)
    }

    /// A document holding neither key reads as no resources, and
    /// `ImportTerraform` answers `.nothingToImport`.
    @Test func aDocumentHoldingNeitherKeyReadsAsNoResources() {
        let neitherKey = "{\"format_version\": \"1.0\"}"

        #expect(TerraformState.read(neitherKey)?.resources.isEmpty == true)

        let response = importing().execute(
            ImportTerraformRequest(stateText: neitherKey, systemName: "Payments")
        )
        #expect(response == .nothingToImport(unmapped: []))
    }

    // MARK: what it refuses

    @Test func refusesAStateItCannotRead() {
        let response = importing().execute(
            ImportTerraformRequest(stateText: "not json", systemName: "Payments")
        )

        #expect(response == .unreadableState)
    }

    @Test func saysWhenTheStateHoldsNothingItDraws() {
        let response = importing().execute(
            ImportTerraformRequest(
                stateText: """
                {"values":{"root_module":{"resources":[
                  {"address":"aws_cloudwatch_metric_alarm.cpu","mode":"managed",
                   "type":"aws_cloudwatch_metric_alarm","name":"cpu","values":{"id":"a"}}
                ]}}}
                """,
                systemName: "Payments"
            )
        )

        guard case .nothingToImport(let unmapped) = response else {
            Issue.record("the state drew something: \(response)")
            return
        }
        #expect(unmapped.map(\.type) == ["aws_cloudwatch_metric_alarm"])
    }

    /// Writing over a file that does not parse would take a person's work
    /// away.
    @Test func refusesToWriteOverAFileThatDoesNotParse() throws {
        let response = importing().execute(
            ImportTerraformRequest(
                stateText: try Self.state("terraform-aws-state.json"),
                architectureText: "system \"Payments\" {\n  zone \"z\" { kind = \"secret\" }\n}\n",
                systemName: "Payments"
            )
        )

        guard case .refused(let diagnostics) = response else {
            Issue.record("the file was written over: \(response)")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }

    // MARK: the verb

    @Test func theVerbWritesTheFileAndSaysWhatItDrew() throws {
        let project = InMemoryProject(root: "/work")
        project.put("system \"Payments\" {\n}\n", at: "/work/threatmodel/payments.arch")
        var lines: [String] = []
        let state = try Self.state("terraform-aws-state.json")

        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() },
            standardInput: { state }
        )
        .run(arguments: ["threatmodeller", "import", "terraform", "/work"], output: { lines.append($0) })

        #expect(code == 0)
        #expect(lines.contains { $0.hasPrefix("added aws-instance-api") })
        #expect(lines.contains { $0.contains("aws_cloudwatch_metric_alarm (1)") })
        #expect(lines.contains { $0.contains("imported 4 components, 3 zones and 1 flows") })

        let written = try #require(project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("technology = \"aws-ec2\""))
    }

    @Test func theVerbSaysWhenNoStateArrives() {
        let project = InMemoryProject(root: "/work")
        var lines: [String] = []

        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() },
            standardInput: { "" }
        )
        .run(arguments: ["threatmodeller", "import", "terraform", "/work"], output: { lines.append($0) })

        #expect(code != 0)
        #expect(lines.contains { $0.contains("no state arrived on standard input") })
    }

    @Test func theVerbTakesOnlyTerraform() {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: InMemoryProject(root: "/work"),
            catalogue: { CatalogueFixture.catalogue() },
            standardInput: { "" }
        )
        .run(arguments: ["threatmodeller", "import", "cloudformation"], output: { lines.append($0) })

        #expect(code != 0)
        #expect(lines.contains { $0.contains("import takes terraform") })
    }

    // MARK: the window's own use case

    /// A window holds a root and a system's name, not a path, so it runs
    /// `ImportTerraformIntoSystem` rather than the verb. The two write the
    /// same bytes for the same input.
    @Test func theWindowsUseCaseWritesTheSameFileTheVerbWrites() throws {
        let state = try Self.state("terraform-aws-state.json")
        let header = "system \"Payments\" {\n}\n"

        // The verb, over its own project.
        let verbProject = InMemoryProject(root: "/work")
        verbProject.put(header, at: "/work/threatmodel/payments.arch")
        let code = CommandLineApplication(
            projects: verbProject,
            catalogue: { CatalogueFixture.catalogue() },
            standardInput: { state }
        )
        .run(arguments: ["threatmodeller", "import", "terraform", "/work"], output: { _ in })
        #expect(code == 0)
        let fromTheVerb = try #require(verbProject.text(at: "/work/threatmodel/payments.arch"))

        // The window's use case, over an identically seeded project.
        let windowProject = InMemoryProject(root: "/work")
        windowProject.put(header, at: "/work/threatmodel/payments.arch")
        let response = ImportTerraformIntoSystem(
            projects: windowProject,
            sources: HclArchitectureSource()
        ).execute(
            ImportTerraformIntoSystemRequest(
                root: "/work",
                systemName: "payments",
                stateText: state
            )
        )
        guard case .imported(let path, .imported) = response else {
            Issue.record("the system did not import: \(response)")
            return
        }
        let fromTheWindow = try #require(windowProject.text(at: path))

        #expect(fromTheWindow == fromTheVerb)
    }

    /// A second import over the same state, run through the window's use
    /// case, writes the file it already holds and changes nothing in it.
    @Test func aSecondImportThroughTheWindowsUseCaseChangesNothing() throws {
        let project = InMemoryProject(root: "/work")
        project.put("system \"Payments\" {\n}\n", at: "/work/threatmodel/payments.arch")
        let state = try Self.state("terraform-aws-state.json")
        let importer = ImportTerraformIntoSystem(projects: project, sources: HclArchitectureSource())
        let request = ImportTerraformIntoSystemRequest(
            root: "/work", systemName: "payments", stateText: state
        )

        _ = importer.execute(request)
        let firstWrite = try #require(project.text(at: "/work/threatmodel/payments.arch"))

        let response = importer.execute(request)
        let secondWrite = try #require(project.text(at: "/work/threatmodel/payments.arch"))

        #expect(secondWrite == firstWrite)
        guard case .imported(_, .imported(_, let added, let removed, _, _, _, _)) = response else {
            Issue.record("the state did not import: \(response)")
            return
        }
        #expect(added.isEmpty)
        #expect(removed.isEmpty)
    }

    @Test func theWindowsUseCaseSaysWhenTheProjectHoldsNoSuchSystem() throws {
        let project = InMemoryProject(root: "/work")
        project.put("system \"Payments\" {\n}\n", at: "/work/threatmodel/payments.arch")

        let response = ImportTerraformIntoSystem(
            projects: project,
            sources: HclArchitectureSource()
        ).execute(
            ImportTerraformIntoSystemRequest(
                root: "/work", systemName: "reporting", stateText: "{}"
            )
        )

        #expect(response == .noSuchSystem)
    }

    /// `importLines` states the words `threatmodeller import terraform`
    /// prints, so a window that shows them says what the verb says.
    @Test func importLinesStatesTheWordsTheVerbPrints() throws {
        let project = InMemoryProject(root: "/work")
        project.put("system \"Payments\" {\n}\n", at: "/work/threatmodel/payments.arch")
        var verbLines: [String] = []
        let state = try Self.state("terraform-aws-state.json")

        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() },
            standardInput: { state }
        )
        .run(
            arguments: ["threatmodeller", "import", "terraform", "/work"],
            output: { verbLines.append($0) }
        )
        #expect(code == 0)

        let response = importing().execute(
            ImportTerraformRequest(stateText: state, systemName: "Payments")
        )
        let windowLines = response.importLines(path: "/work/threatmodel/payments.arch")

        for line in windowLines {
            #expect(verbLines.contains(line), "the verb did not print \"\(line)\"")
        }
        #expect(windowLines.contains { $0.hasPrefix("added aws-instance-api") })
        #expect(windowLines.contains { $0.contains("aws_cloudwatch_metric_alarm (1)") })
        #expect(windowLines.contains { $0.contains("imported 4 components, 3 zones and 1 flows") })
    }

    // MARK: the golden files

    @Test func theImportMatchesTheGoldenFile() throws {
        for state in ["aws", "gcp"] {
            let written = try imported("terraform-\(state)-state.json").text
            let golden = try Self.state("terraform-\(state)-import.arch")

            #expect(written == golden, "the \(state) import changed")
        }
    }

    @Test func writesTheGoldenFilesWhenAskedTo() throws {
        guard ProcessInfo.processInfo.environment["THREATMODELLER_WRITE_GOLDENS"] == "1" else {
            return
        }
        for state in ["aws", "gcp"] {
            try imported("terraform-\(state)-state.json").text.write(
                to: URL(fileURLWithPath: #filePath)
                    .deletingLastPathComponent()
                    .deletingLastPathComponent()
                    .appendingPathComponent("Goldens")
                    .appendingPathComponent("terraform-\(state)-import.arch"),
                atomically: true,
                encoding: .utf8
            )
        }
    }
}
