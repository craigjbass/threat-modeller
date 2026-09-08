// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ThreatModelKit",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "ThreatModelKit", targets: ["ThreatModelKit", "CatalogueGateways"]),
        // Published so the Xcode app test target can build the same fakes and
        // the same composition root the package's own tests use.
        .library(name: "TestSupport", targets: ["TestSupport"]),
        .library(name: "FileGateways", targets: ["FileGateways"]),
        .library(name: "ArchitectureDSL", targets: ["ArchitectureDSL"])
    ],
    targets: [
        .target(name: "ThreatModelKit"),
        .target(
            name: "CatalogueGateways",
            dependencies: ["ThreatModelKit"],
            resources: [.copy("Resources/Library"), .copy("Resources/Actors")]
        ),
        .target(
            name: "FileGateways",
            dependencies: ["ThreatModelKit"],
            resources: [.copy("Resources/Samples")]
        ),
        .target(name: "ArchitectureDSL", dependencies: ["ThreatModelKit"]),
        .target(
            name: "TestSupport",
            dependencies: ["ThreatModelKit", "FileGateways", "ArchitectureDSL"]
        ),
        .testTarget(
            name: "UnitTests",
            dependencies: ["ThreatModelKit", "ArchitectureDSL", "TestSupport"]
        ),
        .testTarget(name: "AcceptanceTests", dependencies: ["ThreatModelKit", "TestSupport"]),
        .testTarget(
            name: "GatewayContractTests",
            dependencies: [
                "ThreatModelKit", "CatalogueGateways", "FileGateways",
                "ArchitectureDSL", "TestSupport"
            ]
        ),
        .testTarget(
            name: "GatewayIntegrationTests",
            dependencies: ["ThreatModelKit", "CatalogueGateways", "FileGateways"]
        )
    ]
)
