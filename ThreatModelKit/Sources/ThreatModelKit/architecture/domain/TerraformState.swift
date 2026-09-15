import Foundation

/// What a Terraform state says, as this application reads it.
///
/// `terraform show -json` writes `values.root_module`, which holds
/// `resources` and `child_modules`. A module's resources are read the way the
/// root module's are, so a system split across modules imports whole.
public struct TerraformState: Equatable, Sendable {
    /// One resource of the state.
    public struct Resource: Equatable, Sendable {
        /// `module.web.aws_instance.api`. It is the element's identity, and
        /// it holds across imports.
        public let address: String
        public let type: String
        public let name: String
        /// What the state states about the resource, as text. A value that is
        /// not text is left out: this reads ids, names and words, not trees.
        public let values: [String: String]
        /// A list value the state holds, such as `vpc_security_group_ids`.
        public let lists: [String: [String]]

        public init(
            address: String,
            type: String,
            name: String,
            values: [String: String] = [:],
            lists: [String: [String]] = [:]
        ) {
            self.address = address
            self.type = type
            self.name = name
            self.values = values
            self.lists = lists
        }

        /// The id the state gave the resource, which another resource names.
        public var id: String? { values["id"] }
    }

    public let resources: [Resource]

    public init(resources: [Resource]) {
        self.resources = resources
    }

    /// Reads the JSON `terraform show -json` writes. A file this cannot read
    /// is nil, and the caller says so.
    public static func read(_ text: String) -> TerraformState? {
        guard let data = text.data(using: .utf8),
              let top = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        // A plan file states `planned_values`; a state file states `values`.
        let values = (top["values"] ?? top["planned_values"]) as? [String: Any]
        guard let root = values?["root_module"] as? [String: Any] else {
            return TerraformState(resources: [])
        }
        return TerraformState(resources: read(module: root))
    }

    private static func read(module: [String: Any]) -> [Resource] {
        var found: [Resource] = []
        for raw in (module["resources"] as? [[String: Any]]) ?? [] {
            guard let address = raw["address"] as? String,
                  let type = raw["type"] as? String,
                  let name = raw["name"] as? String else { continue }
            // A data source is a read, not a thing this system runs.
            guard (raw["mode"] as? String) != "data" else { continue }

            var values: [String: String] = [:]
            var lists: [String: [String]] = [:]
            for (key, value) in (raw["values"] as? [String: Any]) ?? [:] {
                if let text = value as? String {
                    values[key] = text
                } else if let flag = value as? Bool {
                    values[key] = flag ? "true" : "false"
                } else if let number = value as? Int {
                    values[key] = String(number)
                } else if let array = value as? [Any] {
                    let texts = array.compactMap { $0 as? String }
                    if texts.isEmpty == false { lists[key] = texts }
                }
            }
            found.append(
                Resource(address: address, type: type, name: name, values: values, lists: lists)
            )
        }
        for child in (module["child_modules"] as? [[String: Any]]) ?? [] {
            found += read(module: child)
        }
        return found
    }
}

/// What a resource type becomes in this model.
///
/// The tables are the ones
/// `docs/superpowers/specs/2026-09-15-terraform-import-design.md` decides. A
/// type the tables do not hold is counted and named once, and the import
/// still writes everything it could map.
public enum TerraformMapping {
    /// The technology a resource type becomes, or nil for a type this
    /// application does not map.
    public static func technology(of type: String) -> String? {
        byType[type]
    }

    /// True when the type is a network this model draws as a zone.
    public static func isZone(_ type: String) -> Bool {
        zoneKinds.keys.contains(type)
    }

    /// What kind of zone a network resource becomes.
    public static func zoneKind(of resource: TerraformState.Resource) -> String {
        guard let stated = zoneKinds[resource.type] else { return "private" }
        guard stated == "subnet" else { return stated }
        // A subnet that hands out public addresses, or that a person named
        // public, is a public zone. Everything else is private.
        if resource.values["map_public_ip_on_launch"] == "true" { return "public" }
        let name = (resource.values["name"] ?? resource.name).lowercased()
        return name.contains("public") ? "public" : "private"
    }

    /// What kind of network a zone this state holds is: a VPC is a `vpc`, and
    /// a subnet is a `subnet`.
    public static func network(of type: String) -> String {
        zoneKinds[type] == "subnet" ? "subnet" : "vpc"
    }

    /// The types that state a flow rather than an element, so a count of what
    /// this application does not map leaves them out.
    public static let flowTypes: Set<String> = [
        "aws_security_group_rule",
        "aws_security_group",
        "google_compute_firewall"
    ]

    /// The keys a component states to name the network that holds it, worst
    /// first: a subnet is more exact than a network.
    public static let zoneKeys = ["subnet_id", "subnetwork", "subnetwork_id", "network", "vpc_id"]

    /// The keys a component states to name the security groups it holds.
    public static let securityGroupKeys = ["vpc_security_group_ids", "security_groups"]

    private static let zoneKinds: [String: String] = [
        "aws_vpc": "private",
        "google_compute_network": "private",
        "aws_subnet": "subnet",
        "google_compute_subnetwork": "subnet"
    ]

    private static let byType: [String: String] = [
        // AWS
        "aws_instance": "aws-ec2",
        "aws_lambda_function": "aws-lambda",
        "aws_db_instance": "aws-rds",
        "aws_db_cluster_snapshot": "aws-rds",
        "aws_rds_cluster": "aws-aurora",
        "aws_dynamodb_table": "aws-dynamodb",
        "aws_s3_bucket": "aws-s3",
        "aws_efs_file_system": "aws-efs",
        "aws_elasticache_cluster": "aws-elasticache",
        "aws_elasticache_replication_group": "aws-elasticache",
        "aws_opensearch_domain": "aws-opensearch",
        "aws_elasticsearch_domain": "aws-opensearch",
        "aws_redshift_cluster": "aws-redshift",
        "aws_eks_cluster": "aws-eks",
        "aws_ecs_cluster": "aws-ecs",
        "aws_ecs_service": "aws-ecs",
        "aws_ecr_repository": "aws-ecr",
        "aws_apprunner_service": "aws-app-runner",
        "aws_secretsmanager_secret": "aws-secrets-manager",
        "aws_kms_key": "aws-kms",
        "aws_iam_role": "aws-iam",
        "aws_iam_user": "aws-iam",
        "aws_cognito_user_pool": "aws-cognito",
        "aws_api_gateway_rest_api": "aws-api-gateway",
        "aws_apigatewayv2_api": "aws-api-gateway",
        "aws_cloudfront_distribution": "aws-cloudfront",
        "aws_route53_zone": "aws-route53",
        "aws_lb": "aws-elb",
        "aws_alb": "aws-elb",
        "aws_elb": "aws-elb",
        "aws_wafv2_web_acl": "aws-waf",
        "aws_sqs_queue": "aws-sqs",
        "aws_sns_topic": "aws-sns",
        "aws_cloudwatch_log_group": "aws-cloudwatch",
        "aws_cloudtrail": "aws-cloudtrail",
        "aws_kinesis_stream": "aws-kinesis",
        "aws_sfn_state_machine": "aws-step-functions",
        "aws_msk_cluster": "aws-msk",
        "aws_glue_job": "aws-glue",
        "aws_batch_job_definition": "aws-batch",
        "aws_networkfirewall_firewall": "aws-network-firewall",
        "aws_neptune_cluster": "aws-neptune",
        "aws_docdb_cluster": "aws-documentdb",
        // Google Cloud
        "google_compute_instance": "gcp-compute-engine",
        "google_cloudfunctions_function": "gcp-cloud-functions",
        "google_cloudfunctions2_function": "gcp-cloud-functions",
        "google_cloud_run_service": "gcp-cloud-run",
        "google_cloud_run_v2_service": "gcp-cloud-run",
        "google_sql_database_instance": "gcp-cloud-sql",
        "google_firestore_database": "gcp-firestore",
        "google_bigquery_dataset": "gcp-bigquery",
        "google_bigquery_table": "gcp-bigquery",
        "google_spanner_instance": "gcp-spanner",
        "google_bigtable_instance": "gcp-bigtable",
        "google_redis_instance": "gcp-memorystore",
        "google_storage_bucket": "gcp-cloud-storage",
        "google_filestore_instance": "gcp-filestore",
        "google_container_cluster": "gcp-gke",
        "google_artifact_registry_repository": "gcp-artifact-registry",
        "google_cloudbuild_trigger": "gcp-cloud-build",
        "google_secret_manager_secret": "gcp-secret-manager",
        "google_kms_crypto_key": "gcp-kms",
        "google_service_account": "gcp-iam",
        "google_project_iam_member": "gcp-iam",
        "google_compute_url_map": "gcp-cloud-load-balancing",
        "google_compute_backend_service": "gcp-cloud-load-balancing",
        "google_compute_security_policy": "gcp-cloud-armor",
        "google_dns_managed_zone": "gcp-cloud-dns",
        "google_pubsub_topic": "gcp-pub-sub",
        "google_pubsub_subscription": "gcp-pub-sub",
        "google_cloud_scheduler_job": "gcp-cloud-scheduler",
        "google_logging_project_sink": "gcp-cloud-logging",
        "google_dataflow_job": "gcp-dataflow"
    ]

    /// An identifier the language accepts, from a Terraform address.
    public static func identifier(_ address: String) -> String {
        var built = ""
        var lastWasDash = false
        for character in address.lowercased() {
            if character.isLetter || character.isNumber {
                built.append(character)
                lastWasDash = false
            } else if lastWasDash == false {
                built.append("-")
                lastWasDash = true
            }
        }
        while built.hasPrefix("-") { built.removeFirst() }
        while built.hasSuffix("-") { built.removeLast() }
        return built.isEmpty ? "unnamed" : built
    }
}
