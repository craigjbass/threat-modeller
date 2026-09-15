# Importing an architecture from Terraform state

**Status:** decided, 15 September 2026.

## The problem

An `.arch` file is written by hand from what a person knows. A team whose
infrastructure is Terraform already holds the components, the networks and the
data stores as state, draws them a second time by hand, and the drawing drifts
from the state on the next apply.

## The decision

`threatmodeller import terraform [<root>]` reads the JSON of
`terraform show -json` on standard input and writes or updates one `.arch`
file. Every element it writes states `source = "terraform"`, so a later import
knows what it owns and what a person wrote.

## What is read

`terraform show -json` writes a state file holding `values.root_module`, which
holds `resources` and `child_modules`. Each resource states `address`, `type`,
`name` and `values`. This reads the whole tree, so a module's resources are
imported the way the root module's are.

A resource's **address** is its identity: `module.web.aws_instance.api` is one
element, and it keeps that identity across imports. The component's id is the
address with every character outside a letter, a digit or a dash turned into a
dash.

## The mapping

### AWS

| Resource type | Technology |
| --- | --- |
| `aws_instance` | `aws-ec2` |
| `aws_lambda_function` | `aws-lambda` |
| `aws_db_instance`, `aws_db_cluster_snapshot` | `aws-rds` |
| `aws_rds_cluster` | `aws-aurora` |
| `aws_dynamodb_table` | `aws-dynamodb` |
| `aws_s3_bucket` | `aws-s3` |
| `aws_efs_file_system` | `aws-efs` |
| `aws_elasticache_cluster`, `aws_elasticache_replication_group` | `aws-elasticache` |
| `aws_opensearch_domain`, `aws_elasticsearch_domain` | `aws-opensearch` |
| `aws_redshift_cluster` | `aws-redshift` |
| `aws_eks_cluster` | `aws-eks` |
| `aws_ecs_cluster`, `aws_ecs_service` | `aws-ecs` |
| `aws_ecr_repository` | `aws-ecr` |
| `aws_apprunner_service` | `aws-app-runner` |
| `aws_secretsmanager_secret` | `aws-secrets-manager` |
| `aws_kms_key` | `aws-kms` |
| `aws_iam_role`, `aws_iam_user` | `aws-iam` |
| `aws_cognito_user_pool` | `aws-cognito` |
| `aws_api_gateway_rest_api`, `aws_apigatewayv2_api` | `aws-api-gateway` |
| `aws_cloudfront_distribution` | `aws-cloudfront` |
| `aws_route53_zone` | `aws-route53` |
| `aws_lb`, `aws_alb`, `aws_elb` | `aws-elb` |
| `aws_wafv2_web_acl` | `aws-waf` |
| `aws_sqs_queue` | `aws-sqs` |
| `aws_sns_topic` | `aws-sns` |
| `aws_cloudwatch_log_group` | `aws-cloudwatch` |
| `aws_cloudtrail` | `aws-cloudtrail` |
| `aws_kinesis_stream` | `aws-kinesis` |
| `aws_sfn_state_machine` | `aws-step-functions` |
| `aws_msk_cluster` | `aws-msk` |
| `aws_glue_job` | `aws-glue` |
| `aws_batch_job_definition` | `aws-batch` |
| `aws_networkfirewall_firewall` | `aws-network-firewall` |
| `aws_neptune_cluster` | `aws-neptune` |
| `aws_docdb_cluster` | `aws-documentdb` |

### Google Cloud

| Resource type | Technology |
| --- | --- |
| `google_compute_instance` | `gcp-compute-engine` |
| `google_cloudfunctions_function`, `google_cloudfunctions2_function` | `gcp-cloud-functions` |
| `google_cloud_run_service`, `google_cloud_run_v2_service` | `gcp-cloud-run` |
| `google_sql_database_instance` | `gcp-cloud-sql` |
| `google_firestore_database` | `gcp-firestore` |
| `google_bigquery_dataset`, `google_bigquery_table` | `gcp-bigquery` |
| `google_spanner_instance` | `gcp-spanner` |
| `google_bigtable_instance` | `gcp-bigtable` |
| `google_redis_instance` | `gcp-memorystore` |
| `google_storage_bucket` | `gcp-cloud-storage` |
| `google_filestore_instance` | `gcp-filestore` |
| `google_container_cluster` | `gcp-gke` |
| `google_artifact_registry_repository` | `gcp-artifact-registry` |
| `google_cloudbuild_trigger` | `gcp-cloud-build` |
| `google_secret_manager_secret` | `gcp-secret-manager` |
| `google_kms_crypto_key` | `gcp-kms` |
| `google_service_account`, `google_project_iam_member` | `gcp-iam` |
| `google_compute_url_map`, `google_compute_backend_service` | `gcp-cloud-load-balancing` |
| `google_compute_security_policy` | `gcp-cloud-armor` |
| `google_dns_managed_zone` | `gcp-cloud-dns` |
| `google_pubsub_topic`, `google_pubsub_subscription` | `gcp-pub-sub` |
| `google_cloud_scheduler_job` | `gcp-cloud-scheduler` |
| `google_logging_project_sink` | `gcp-cloud-logging` |
| `google_dataflow_job` | `gcp-dataflow` |

### Zones

| Resource type | What it becomes |
| --- | --- |
| `aws_vpc`, `google_compute_network` | one zone, `kind = "private"`, `network = "cloud"` |
| `aws_subnet`, `google_compute_subnetwork` | one zone. A subnet whose `map_public_ip_on_launch` is true, or whose name holds `public`, takes `kind = "public"`; every other subnet takes `kind = "private"` |

A component sits in the zone its `subnet_id`, `subnetwork` or `vpc_id` names,
by the address of the resource that holds that id. A component naming none
sits outside every zone.

### Flows

A `aws_security_group_rule` of type `ingress`, and an `ingress` block inside an
`aws_security_group`, states a flow **into** every component whose
`vpc_security_group_ids` or `security_groups` name that group, from every
component whose security group is named in `source_security_group_id`. A rule
naming a CIDR rather than a group states no flow: an address range is not an
element of this model.

`google_compute_firewall` reads the same way through `source_tags` and
`target_tags`.

The flow's kind is `network`.

## What is not derivable

These are stated by a person, and an import never writes them:

- **What data a component holds.** Terraform states a bucket, not what is in
  it. Every imported component takes `data = "internal"`, and a person raises
  it.
- **Who owns the system**, the use cases, the exclusions and the assumptions.
- **Named assets.** A bucket's contents have no name in the state.
- **Third parties.** A SaaS the team pays for is not in its own Terraform.
- **Trust boundaries beyond the network.** A privilege boundary is a decision.
- **Flows a security group does not state**: a queue read, a call through the
  internet, a batch job reading a bucket. Terraform states the wiring it
  controls and no more.
- **`runs_as`.** Terraform states no privilege level.

## Writing the file again

The import reads the `.arch` file when one is there, and writes it again:

1. An element the state holds and the file does not is **added**, with
   `source = "terraform"`.
2. An element both hold is **updated**: its technology and its zone take the
   state's word; its `data`, its name, its assets and everything else a person
   wrote stay.
3. An element the file marks `source = "terraform"` and the state no longer
   holds is **removed**, and the import says which.
4. An element the file holds with no `source` was written by a person and is
   **never** removed or changed.

A second import over the same state therefore writes the same bytes.

## What the import says

One line per change, then a summary:

```
added component "aws-instance-api" (aws-ec2)
removed component "aws-s3-bucket-old", which the state no longer holds
2 resources have no mapping: aws_cloudwatch_metric_alarm (2)
imported 7 components, 2 zones and 3 flows into threatmodel/payments.arch
```

A resource type with no mapping is counted and named once, and the import
still writes everything it could map. A state holding nothing this application
maps writes no file and says so.

## The `source` attribute

`component` and `zone` take `source = "<word>"`. The language reads any word;
`terraform` is the one this import writes. `format` writes it back, and the
report states it in the model inventory, so a reader knows which elements a
person drew.
