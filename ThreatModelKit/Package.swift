// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ThreatModelKit",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "ThreatModelKit", targets: ["ThreatModelKit", "CatalogueGateways"])
    ],
    targets: [
        .target(name: "ThreatModelKit"),
        .target(
            name: "CatalogueGateways",
            dependencies: ["ThreatModelKit"],
            resources: [.copy("Resources/Library")]
        ),
        .target(name: "TestSupport", dependencies: ["ThreatModelKit"]),
        .testTarget(name: "UnitTests", dependencies: ["ThreatModelKit", "TestSupport"]),
        .testTarget(name: "AcceptanceTests", dependencies: ["ThreatModelKit", "TestSupport"]),
        .testTarget(
            name: "GatewayContractTests",
            dependencies: ["ThreatModelKit", "CatalogueGateways", "TestSupport"]
        ),
        .testTarget(
            name: "GatewayIntegrationTests",
            dependencies: ["ThreatModelKit", "CatalogueGateways"]
        )
    ]
)
