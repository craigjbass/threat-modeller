import ThreatModelKit

/// A small catalogue shaped like the real one, used by fast tests.
///
/// The EC2 entry mirrors the vendored `aws-ec2` service closely enough that the
/// acceptance tests read like the real thing, while staying hand-written so a
/// catalogue update never silently changes an expected value.
public enum CatalogueFixture {
    public static let low = ThreatSeverity(id: "low", label: "Low", rank: 1)
    public static let medium = ThreatSeverity(id: "medium", label: "Medium", rank: 2)
    public static let high = ThreatSeverity(id: "high", label: "High", rank: 3)
    public static let critical = ThreatSeverity(id: "critical", label: "Critical", rank: 4)

    public static func taxonomy() -> Taxonomy {
        Taxonomy(
            stride: [
                StrideCategory(id: StrideId("spoofing"), label: "Spoofing"),
                StrideCategory(id: StrideId("tampering"), label: "Tampering"),
                StrideCategory(id: StrideId("repudiation"), label: "Repudiation"),
                StrideCategory(id: StrideId("information-disclosure"), label: "Information Disclosure"),
                StrideCategory(id: StrideId("denial-of-service"), label: "Denial of Service"),
                StrideCategory(id: StrideId("elevation-of-privilege"), label: "Elevation of Privilege")
            ],
            severities: [low, medium, high, critical],
            categories: [
                ServiceCategory(
                    id: CategoryId("compute"),
                    label: "Compute",
                    presetThreatIds: [ThreatId("misconfiguration")]
                ),
                ServiceCategory(
                    id: CategoryId("database"),
                    label: "Database",
                    presetThreatIds: [ThreatId("data-exfiltration")]
                )
            ]
        )
    }

    public static func providers() -> [Provider] {
        [
            Provider(id: ProviderId("aws"), displayName: "Amazon Web Services"),
            Provider(id: ProviderId("gcp"), displayName: "Google Cloud Platform")
        ]
    }

    public static func ec2() -> Technology {
        Technology(
            id: TechnologyId("aws-ec2"),
            name: "EC2",
            provider: ProviderId("aws"),
            category: CategoryId("compute"),
            description: "Virtual servers in the cloud",
            threatIds: [
                ThreatId("credential-theft"),
                ThreatId("misconfiguration"),
                ThreatId("dos-attack")
            ],
            threatContext: [
                ThreatId("credential-theft"): "Instance Metadata Service credential theft"
            ],
            threatMitigations: [
                ThreatId("credential-theft"): [
                    "Enforce IMDSv2 to block SSRF-based credential theft",
                    "Use IAM roles with minimal permissions"
                ]
            ]
        )
    }

    public static func rds() -> Technology {
        Technology(
            id: TechnologyId("aws-rds"),
            name: "RDS",
            provider: ProviderId("aws"),
            category: CategoryId("database"),
            description: "Managed relational database",
            threatIds: [ThreatId("misconfiguration")],
            enforcesEncryption: true
        )
    }

    public static func bigQuery() -> Technology {
        Technology(
            id: TechnologyId("gcp-bigquery"),
            name: "BigQuery",
            provider: ProviderId("gcp"),
            category: CategoryId("database"),
            description: "Serverless data warehouse",
            threatIds: []
        )
    }

    public static func ec2Threats() -> [Threat] {
        [
            Threat(
                id: ThreatId("credential-theft"),
                name: "Credential Theft",
                description: "Attacker steals credentials to impersonate a principal",
                severity: critical,
                stride: [StrideId("spoofing")],
                mitreTechniques: [
                    MitreTechnique(id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access")
                ],
                controls: [
                    Control(id: "ctrl-cred-1", description: "Rotate credentials regularly"),
                    Control(id: "ctrl-cred-2", description: "Store secrets in a managed vault")
                ],
                isPathwayThreat: true
            ),
            Threat(
                id: ThreatId("misconfiguration"),
                name: "Misconfiguration",
                description: "Insecure defaults or drift leave the service exposed",
                severity: medium,
                stride: [StrideId("tampering")],
                controls: [Control(id: "ctrl-misc-1", description: "Scan configuration continuously")]
            ),
            Threat(
                id: ThreatId("dos-attack"),
                name: "Denial of Service",
                description: "Attacker exhausts capacity to deny availability",
                severity: low,
                stride: [StrideId("denial-of-service")],
                controls: [Control(id: "ctrl-dos-1", description: "Apply rate limits")],
                isPathwayThreat: true
            )
        ]
    }

    public static func catalogue() -> InMemoryTechnologyCatalogue {
        InMemoryTechnologyCatalogue(
            technologies: [ec2(), rds(), bigQuery()],
            threats: ec2Threats(),
            taxonomy: taxonomy(),
            providers: providers()
        )
    }
}
