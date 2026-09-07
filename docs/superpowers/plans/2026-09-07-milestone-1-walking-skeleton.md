# Milestone 1: Walking Skeleton — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A native macOS app that lists the real technology catalogue, lets the user add a technology to a model, and shows the resulting threats with correct risk scores — built on a Clean Architecture core with an acceptance-tested use case boundary.

**Architecture:** A local Swift package `ThreatModelKit` holds the hexagon: domain objects, use cases with a one-method `execute` boundary, and gateway protocols. A second package target `CatalogueGateways` adapts the vendored catalogue JSON. The Xcode app target is a thin delivery mechanism that translates clicks into use case calls. Every gateway has a fake and a real implementation held to one shared contract.

**Tech Stack:** Swift 6.3 (Swift 6 language mode in the package), Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Read Task 10 before starting Task 4.** Task 10 is the acceptance test — the outer loop. Swift cannot compile a test that references types which do not yet exist, so it is written last rather than first, but Tasks 4–9 exist solely to make it pass. Read it first so you know what you are building towards.

## Global Constraints

- Minimum deployment target: macOS 26. The package declares `platforms: [.macOS(.v26)]`.
- Package manifest uses `// swift-tools-version: 6.2`, which selects Swift 6 language mode.
- `ThreatModelKit` (the core target) must not `import SwiftUI`, `import AppKit`, or read from disk. It may `import Foundation` for value types only.
- Domain objects never cross a use case boundary. Every `Request` and `Response` type contains only `String`, `Int`, `Double`, `Bool`, arrays and other Response structs.
- Use cases take collaborators in `init` and the request in `execute`. One use case per file. Protocol named `<Name>UseCase`, concrete type named `<Name>`.
- Gateways accept and return Domain objects. The only non-Domain values crossing a gateway boundary are identifiers used to locate data.
- Catalogue pinned at `jib1337/threat-model-library` tag **v1.0.1**.
- Severity ranks come from the order of `taxonomy.json` `severities`: low=1, medium=2, high=3, critical=4.
- Data sensitivity ranks are application-owned: public=1, internal=2, confidential=3, restricted=4.
- Risk score = severity rank × sensitivity rank. Risk level: `>= 12` critical, `>= 8` high, `>= 4` medium, otherwise low.
- Bundle identifier stays `uk.craigbass.threatmodeller`.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Connections, zones, pathway mitigations, severity overrides, implemented controls, undo/redo, documents, custom technologies, actors, exports, samples, and the canvas. They arrive in Milestones 2–9. Do not add gateway methods or Response fields for them — later milestones extend the ports.

## File Structure

**Created in this milestone:**

| Path | Responsibility |
|---|---|
| `ThreatModelKit/Package.swift` | Package manifest: targets, resources, test targets |
| `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Identifiers.swift` | `TechnologyId`, `ThreatId`, `ProviderId`, `CategoryId`, `StrideId` |
| `.../catalogue/domain/Taxonomy.swift` | `StrideCategory`, `ThreatSeverity`, `ServiceCategory`, `Taxonomy` |
| `.../catalogue/domain/Provider.swift` | `Provider` |
| `.../catalogue/domain/Threat.swift` | `Threat`, `Control`, `MitreTechnique` |
| `.../catalogue/domain/Technology.swift` | `Technology` |
| `.../catalogue/gateway/TechnologyCatalogue.swift` | The catalogue port |
| `.../catalogue/usecase/ListTechnologies.swift` | `ListTechnologies` use case and its Request/Response |
| `.../modelling/domain/Point.swift` | `Point` |
| `.../modelling/domain/DataSensitivity.swift` | `DataSensitivity` |
| `.../modelling/domain/Component.swift` | `ComponentId`, `Component` |
| `.../modelling/domain/ThreatModel.swift` | `ThreatModel` aggregate |
| `.../modelling/gateway/ThreatModelGateway.swift` | The model port plus `InMemoryThreatModelGateway` |
| `.../modelling/gateway/IdentityGenerator.swift` | The id port plus `UUIDIdentityGenerator` |
| `.../modelling/usecase/AddComponent.swift` | `AddComponent` use case and its Request/Response |
| `.../assessment/domain/RiskScore.swift` | `RiskLevel`, `RiskScore` |
| `.../assessment/usecase/AssessThreatModel.swift` | `AssessThreatModel` use case and its Request/Response |
| `ThreatModelKit/Sources/CatalogueGateways/Resources/Library/` | Vendored catalogue JSON plus `library.lock.json` |
| `.../CatalogueGateways/CatalogueJSON.swift` | `Codable` DTOs mirroring the vendored JSON |
| `.../CatalogueGateways/BundledTechnologyCatalogue.swift` | Real `TechnologyCatalogue` over `Bundle.module` |
| `ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift` | Fake catalogue |
| `.../TestSupport/CatalogueFixture.swift` | Hand-built taxonomy and EC2-shaped fixtures |
| `.../TestSupport/SequentialIdentityGenerator.swift` | Deterministic id fake |
| `.../TestSupport/TechnologyCatalogueContract.swift` | The shared gateway contract |
| `.../TestSupport/TestDependencies.swift` | Use-case factory wired to fakes |
| `ThreatModelKit/Tests/UnitTests/` | Per-use-case and per-domain-object tests |
| `ThreatModelKit/Tests/AcceptanceTests/` | Use case boundary only |
| `ThreatModelKit/Tests/GatewayContractTests/` | Contract run against fake and real |
| `ThreatModelKit/Tests/GatewayIntegrationTests/` | Real vendored JSON |
| `scripts/update-catalogue.sh` | Vendoring and checksum verification |
| `threatmodeller/Dependencies.swift` | Composition root for the app |
| `threatmodeller/ThreatModelSession.swift` | The one observable object per window |
| `NOTICE` | Catalogue and MITRE ATT&CK attribution |

**Modified:**

- `threatmodeller.xcodeproj/project.pbxproj` — link the local package to the app and app-test targets
- `threatmodeller/threatmodellerApp.swift` — drop SwiftData, rename the App type
- `threatmodeller/ContentView.swift` — replace the template with the palette and threat list
- `threatmodellerTests/threatmodellerTests.swift` — replace the template test
- `.gitignore` — ignore build products

**Deleted:**

- `threatmodeller/Item.swift` — the SwiftData template model

---

### Task 1: Package skeleton wired into Xcode

**Files:**
- Create: `ThreatModelKit/Package.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/Placeholder.swift`
- Create: `ThreatModelKit/Tests/UnitTests/PackageBuildsTests.swift`
- Modify: `threatmodeller.xcodeproj/project.pbxproj`
- Modify: `threatmodeller/threatmodellerApp.swift`
- Modify: `threatmodeller/ContentView.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`
- Modify: `.gitignore`
- Delete: `threatmodeller/Item.swift`

**Interfaces:**
- Consumes: nothing
- Produces: a `ThreatModelKit` package product importable from `threatmodeller` and `threatmodellerTests`; `swift test` runs from `ThreatModelKit/`

- [ ] **Step 1: Create the package manifest**

Create `ThreatModelKit/Package.swift`:

```swift
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
```

`TestSupport` is a `Sources` target but deliberately absent from the `products` list, so fakes never ship in the application.

- [ ] **Step 2: Create the minimum files each target needs to compile**

```bash
cd /Users/craigjbass/Projects/threat-modeller
mkdir -p ThreatModelKit/Sources/ThreatModelKit
mkdir -p ThreatModelKit/Sources/CatalogueGateways/Resources/Library
mkdir -p ThreatModelKit/Sources/TestSupport
mkdir -p ThreatModelKit/Tests/UnitTests
mkdir -p ThreatModelKit/Tests/AcceptanceTests
mkdir -p ThreatModelKit/Tests/GatewayContractTests
mkdir -p ThreatModelKit/Tests/GatewayIntegrationTests
```

Create `ThreatModelKit/Sources/ThreatModelKit/Placeholder.swift`:

```swift
/// Removed in Task 3, once the catalogue domain gives this target real content.
public let threatModelKitIsWired = true
```

Create `ThreatModelKit/Sources/CatalogueGateways/Placeholder.swift`:

```swift
/// Removed in Task 3.
let catalogueGatewaysIsWired = true
```

Create `ThreatModelKit/Sources/TestSupport/Placeholder.swift`:

```swift
/// Removed in Task 5.
public let testSupportIsWired = true
```

The three empty test directories each need a file. Create
`ThreatModelKit/Tests/AcceptanceTests/Placeholder.swift`,
`ThreatModelKit/Tests/GatewayContractTests/Placeholder.swift` and
`ThreatModelKit/Tests/GatewayIntegrationTests/Placeholder.swift`, each containing:

```swift
// Replaced by real tests later in this plan.
```

- [ ] **Step 3: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/PackageBuildsTests.swift`:

```swift
import Testing
@testable import ThreatModelKit

struct PackageBuildsTests {
    @Test func theCoreTargetIsImportable() {
        #expect(threatModelKitIsWired)
    }
}
```

- [ ] **Step 4: Run the package suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test
```

Expected: `Build complete`, one test passes. If the build fails on a missing `Resources/Library` directory, confirm Step 2 created it — SPM requires the copied resource path to exist.

- [ ] **Step 5: Link the package into the Xcode project**

This edits `project.pbxproj`, which is `objectVersion = 77`. Run this script exactly; it has been verified against this project.

```bash
cd /Users/craigjbass/Projects/threat-modeller
python3 - threatmodeller.xcodeproj/project.pbxproj <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()

APP_BUILDFILE  = "A0000000000000000000001"
APP_PRODUCT    = "A0000000000000000000002"
PKG_REFERENCE  = "A0000000000000000000003"
TEST_BUILDFILE = "A0000000000000000000004"
TEST_PRODUCT   = "A0000000000000000000005"

s = s.replace("""	objects = {

/* Begin PBXContainerItemProxy section */""",
"""	objects = {

/* Begin PBXBuildFile section */
\t\t%s /* ThreatModelKit in Frameworks */ = {isa = PBXBuildFile; productRef = %s /* ThreatModelKit */; };
\t\t%s /* ThreatModelKit in Frameworks */ = {isa = PBXBuildFile; productRef = %s /* ThreatModelKit */; };
/* End PBXBuildFile section */

/* Begin PBXContainerItemProxy section */""" % (APP_BUILDFILE, APP_PRODUCT, TEST_BUILDFILE, TEST_PRODUCT), 1)

# App target's Frameworks build phase
s = s.replace("""		46EEEDC3304F3231000F014D /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);""",
"""		46EEEDC3304F3231000F014D /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
\t\t\t\t%s /* ThreatModelKit in Frameworks */,
			);""" % APP_BUILDFILE, 1)

# Unit test target's Frameworks build phase
s = s.replace("""		46EEEDD2304F3232000F014D /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);""",
"""		46EEEDD2304F3232000F014D /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
\t\t\t\t%s /* ThreatModelKit in Frameworks */,
			);""" % TEST_BUILDFILE, 1)

s = s.replace("""			name = threatmodeller;
			packageProductDependencies = (
			);""",
"""			name = threatmodeller;
			packageProductDependencies = (
\t\t\t\t%s /* ThreatModelKit */,
			);""" % APP_PRODUCT, 1)

s = s.replace("""			name = threatmodellerTests;
			packageProductDependencies = (
			);""",
"""			name = threatmodellerTests;
			packageProductDependencies = (
\t\t\t\t%s /* ThreatModelKit */,
			);""" % TEST_PRODUCT, 1)

s = s.replace("""			minimizedProjectReferenceProxies = 1;
			preferredProjectObjectVersion = 77;""",
"""			minimizedProjectReferenceProxies = 1;
			packageReferences = (
\t\t\t\t%s /* XCLocalSwiftPackageReference "ThreatModelKit" */,
			);
			preferredProjectObjectVersion = 77;""" % PKG_REFERENCE, 1)

s = s.replace("""/* End XCConfigurationList section */""",
"""/* End XCConfigurationList section */

/* Begin XCLocalSwiftPackageReference section */
\t\t%s /* XCLocalSwiftPackageReference "ThreatModelKit" */ = {
\t\t\tisa = XCLocalSwiftPackageReference;
\t\t\trelativePath = ThreatModelKit;
\t\t};
/* End XCLocalSwiftPackageReference section */

/* Begin XCSwiftPackageProductDependency section */
\t\t%s /* ThreatModelKit */ = {
\t\t\tisa = XCSwiftPackageProductDependency;
\t\t\tproductName = ThreatModelKit;
\t\t};
\t\t%s /* ThreatModelKit */ = {
\t\t\tisa = XCSwiftPackageProductDependency;
\t\t\tproductName = ThreatModelKit;
\t\t};
/* End XCSwiftPackageProductDependency section */""" % (PKG_REFERENCE, APP_PRODUCT, TEST_PRODUCT), 1)

open(p, 'w').write(s)
print("pbxproj edited")
PY
plutil -lint threatmodeller.xcodeproj/project.pbxproj
```

Expected: `pbxproj edited` then `project.pbxproj: OK`.

- [ ] **Step 6: Remove the SwiftData template and prove the app sees the package**

```bash
cd /Users/craigjbass/Projects/threat-modeller
rm threatmodeller/Item.swift
```

The app target uses `PBXFileSystemSynchronizedRootGroup`, so deleting and adding files under `threatmodeller/` needs no further project edit.

Replace `threatmodeller/threatmodellerApp.swift` entirely:

```swift
import SwiftUI

@main
struct ThreatModellerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
```

Replace `threatmodeller/ContentView.swift` entirely:

```swift
import SwiftUI
import ThreatModelKit

struct ContentView: View {
    var body: some View {
        Text(threatModelKitIsWired ? "ThreatModelKit linked" : "not linked")
            .padding()
    }
}
```

Replace `threatmodellerTests/threatmodellerTests.swift` entirely:

```swift
import Testing
import ThreatModelKit
@testable import threatmodeller

struct WiringTests {
    @Test func theTestTargetCanSeeThePackage() {
        #expect(threatModelKitIsWired)
    }
}
```

- [ ] **Step 7: Build and test the app target**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: `WiringTests/theTestTargetCanSeeThePackage()` passes and the run ends with `TEST SUCCEEDED`.

- [ ] **Step 8: Ignore build products**

Replace `.gitignore`:

```
.DS_Store
.superpowers/
.build/
DerivedData/
xcuserdata/
*.xcuserdatad
```

- [ ] **Step 9: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git rm --cached -r --ignore-unmatch threatmodeller.xcodeproj/xcuserdata threatmodeller.xcodeproj/project.xcworkspace/xcuserdata
git add -A
git commit -m "feat: add ThreatModelKit package and wire it into the app"
```

---

### Task 2: Vendor the catalogue

**Files:**
- Create: `scripts/update-catalogue.sh`
- Create: `ThreatModelKit/Sources/CatalogueGateways/Resources/Library/*` (downloaded)
- Create: `ThreatModelKit/Sources/CatalogueGateways/LibraryResources.swift`
- Create: `ThreatModelKit/Tests/GatewayIntegrationTests/LibraryResourcesTests.swift`
- Create: `NOTICE`
- Delete: `ThreatModelKit/Tests/GatewayIntegrationTests/Placeholder.swift`

**Interfaces:**
- Consumes: the package from Task 1
- Produces: `LibraryResources.data(named: String) throws -> Data`, loading a file from the vendored `Library` directory by relative path (for example `"taxonomy.json"`, `"technologies/aws.json"`)

- [ ] **Step 1: Write the vendoring script**

Create `scripts/update-catalogue.sh`:

```bash
#!/usr/bin/env bash
#
# Vendors the threat-model-library catalogue into the repository.
#
#   scripts/update-catalogue.sh update v1.0.1   download a tag and rewrite the lock file
#   scripts/update-catalogue.sh verify          re-check the vendored files against the lock file
#
set -euo pipefail

REPO="jib1337/threat-model-library"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/ThreatModelKit/Sources/CatalogueGateways/Resources/Library"
LOCK="$DEST/library.lock.json"

FILES=(
  "taxonomy.json"
  "technologies/aws.json"
  "technologies/azure.json"
  "technologies/gcp.json"
  "technologies/saas.json"
  "technologies/self-hosted.json"
  "threats/common-threats.json"
  "mitigations/pathway-mitigations.json"
)

WORKDIR=""
cleanup() { if [ -n "$WORKDIR" ]; then rm -rf "$WORKDIR"; fi; }
trap cleanup EXIT

checksum() { shasum -a 256 "$1" | awk '{print $1}'; }

write_lock() {
  local tag="$1"
  {
    printf '{\n'
    printf '  "repository": "%s",\n' "$REPO"
    printf '  "tag": "%s",\n' "$tag"
    printf '  "files": {\n'
    local i=0
    for f in "${FILES[@]}"; do
      i=$((i + 1))
      local sep=","
      [ "$i" -eq "${#FILES[@]}" ] && sep=""
      printf '    "%s": "%s"%s\n' "$f" "$(checksum "$DEST/$f")" "$sep"
    done
    printf '  }\n'
    printf '}\n'
  } > "$LOCK"
}

cmd_update() {
  local tag="${1:?usage: update-catalogue.sh update <tag>}"
  WORKDIR="$(mktemp -d)"
  local tmp="$WORKDIR"

  echo "Downloading $REPO@$tag"
  curl -fsSL "https://github.com/$REPO/archive/refs/tags/$tag.tar.gz" -o "$tmp/library.tar.gz"
  tar -xzf "$tmp/library.tar.gz" -C "$tmp"

  local src
  src="$(find "$tmp" -maxdepth 1 -type d -name 'threat-model-library-*' | head -1)/data"
  [ -d "$src" ] || { echo "No data/ directory in the downloaded tag" >&2; exit 1; }

  mkdir -p "$DEST/technologies" "$DEST/threats" "$DEST/mitigations"
  for f in "${FILES[@]}"; do
    [ -f "$src/$f" ] || { echo "Missing $f in the downloaded tag" >&2; exit 1; }
    cp "$src/$f" "$DEST/$f"
  done

  write_lock "$tag"
  echo "Vendored ${#FILES[@]} files at $tag"
}

cmd_verify() {
  [ -f "$LOCK" ] || { echo "No lock file at $LOCK" >&2; exit 1; }
  local failed=0
  for f in "${FILES[@]}"; do
    if [ ! -f "$DEST/$f" ]; then
      echo "MISSING $f" >&2
      failed=1
      continue
    fi
    local expected actual
    expected="$(grep "\"$f\"" "$LOCK" | sed 's/.*: "//; s/".*//')"
    actual="$(checksum "$DEST/$f")"
    if [ "$expected" != "$actual" ]; then
      echo "MISMATCH $f" >&2
      failed=1
    fi
  done
  if [ "$failed" -eq 0 ]; then
    echo "All ${#FILES[@]} vendored files match the lock file"
  fi
  exit "$failed"
}

case "${1:-}" in
  update) shift; cmd_update "$@" ;;
  verify) cmd_verify ;;
  *) echo "usage: update-catalogue.sh {update <tag>|verify}" >&2; exit 1 ;;
esac
```

- [ ] **Step 2: Run it and verify it**

```bash
cd /Users/craigjbass/Projects/threat-modeller
chmod +x scripts/update-catalogue.sh
scripts/update-catalogue.sh update v1.0.1
scripts/update-catalogue.sh verify
```

Expected: `Vendored 8 files at v1.0.1` then `All 8 vendored files match the lock file`.

- [ ] **Step 3: Write the failing test**

Delete `ThreatModelKit/Tests/GatewayIntegrationTests/Placeholder.swift` and create
`ThreatModelKit/Tests/GatewayIntegrationTests/LibraryResourcesTests.swift`:

```swift
import Foundation
import Testing
@testable import CatalogueGateways

struct LibraryResourcesTests {
    @Test func loadsTheVendoredTaxonomy() throws {
        let data = try LibraryResources.data(named: "taxonomy.json")
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains("\"spoofing\""))
    }

    @Test func loadsAVendoredProviderFile() throws {
        let data = try LibraryResources.data(named: "technologies/aws.json")
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains("\"aws-ec2\""))
    }

    @Test func reportsAMissingResource() {
        #expect(throws: LibraryResourceError.self) {
            try LibraryResources.data(named: "does-not-exist.json")
        }
    }
}
```

- [ ] **Step 4: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter LibraryResourcesTests
```

Expected: FAIL — `cannot find 'LibraryResources' in scope`.

- [ ] **Step 5: Write the minimal implementation**

Create `ThreatModelKit/Sources/CatalogueGateways/LibraryResources.swift`:

```swift
import Foundation

public enum LibraryResourceError: Error, Equatable {
    case notFound(String)
}

/// Reads the catalogue files vendored into this target's resource bundle.
public enum LibraryResources {
    public static func data(named name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: "Library/\(name)", withExtension: nil) else {
            throw LibraryResourceError.notFound(name)
        }
        return try Data(contentsOf: url)
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter LibraryResourcesTests
```

Expected: 3 tests pass.

- [ ] **Step 7: Write the attribution notice**

Create `NOTICE` at the repository root:

```
threatmodeller
Copyright (c) 2026 Craig J. Bass
Licensed under the MIT License.

This application embeds the Threat Model Library catalogue
(https://github.com/jib1337/threat-model-library), vendored at tag v1.0.1 under
ThreatModelKit/Sources/CatalogueGateways/Resources/Library/.

The catalogue is Copyright (c) 2026 Jack Nelson and is licensed under the
Creative Commons Attribution 4.0 International Licence (CC BY 4.0).
https://creativecommons.org/licenses/by/4.0/

The catalogue includes MITRE ATT&CK(R) content, reproduced with the permission
of The MITRE Corporation. ATT&CK(R) is a registered trademark of
The MITRE Corporation.
```

- [ ] **Step 8: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add scripts/update-catalogue.sh NOTICE ThreatModelKit
git commit -m "feat: vendor the threat catalogue at v1.0.1"
```

---

### Task 3: Catalogue domain and the catalogue port

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Identifiers.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Taxonomy.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Provider.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Threat.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Technology.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/gateway/TechnologyCatalogue.swift`
- Create: `ThreatModelKit/Tests/UnitTests/TaxonomyTests.swift`
- Delete: `ThreatModelKit/Sources/ThreatModelKit/Placeholder.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/PackageBuildsTests.swift` (delete it)
- Modify: `threatmodeller/ContentView.swift`, `threatmodellerTests/threatmodellerTests.swift` (stop using the placeholder)

**Interfaces:**
- Consumes: the package from Task 1
- Produces:
  - `TechnologyId(_ value: String)`, `ThreatId`, `ProviderId`, `CategoryId`, `StrideId` — each with `.value: String`
  - `ThreatSeverity(id: String, label: String, rank: Int)`
  - `StrideCategory(id: StrideId, label: String)`
  - `ServiceCategory(id: CategoryId, label: String, presetThreatIds: [ThreatId])`
  - `Taxonomy(stride:severities:categories:)` with `severity(id: String) -> ThreatSeverity?`, `category(id: CategoryId) -> ServiceCategory?`, `strideCategory(id: StrideId) -> StrideCategory?`
  - `Provider(id: ProviderId, displayName: String)`
  - `Control(id: String, description: String)`, `MitreTechnique(id: String, name: String, tactic: String)`
  - `Threat(id:name:description:severity:stride:mitreTechniques:controls:isConnectionThreat:isZoneThreat:isPathwayThreat:zoneContext:)`
  - `Technology(id:name:provider:category:description:threatIds:enforcesEncryption:internalOnly:threatContext:threatMitigations:)`
  - `protocol TechnologyCatalogue` with `all()`, `findById(_:)`, `threatsFor(technologyId:)`, `taxonomy()`, `providers()`

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/TaxonomyTests.swift`:

```swift
import Testing
import ThreatModelKit

struct TaxonomyTests {
    private let taxonomy = Taxonomy(
        stride: [
            StrideCategory(id: StrideId("spoofing"), label: "Spoofing"),
            StrideCategory(id: StrideId("tampering"), label: "Tampering")
        ],
        severities: [
            ThreatSeverity(id: "low", label: "Low", rank: 1),
            ThreatSeverity(id: "medium", label: "Medium", rank: 2),
            ThreatSeverity(id: "high", label: "High", rank: 3),
            ThreatSeverity(id: "critical", label: "Critical", rank: 4)
        ],
        categories: [
            ServiceCategory(
                id: CategoryId("compute"),
                label: "Compute",
                presetThreatIds: [ThreatId("misconfiguration")]
            )
        ]
    )

    @Test func findsASeverityByItsId() {
        #expect(taxonomy.severity(id: "critical")?.rank == 4)
        #expect(taxonomy.severity(id: "low")?.label == "Low")
    }

    @Test func returnsNilForAnUnknownSeverity() {
        #expect(taxonomy.severity(id: "catastrophic") == nil)
    }

    @Test func findsACategoryByItsId() {
        #expect(taxonomy.category(id: CategoryId("compute"))?.label == "Compute")
        #expect(taxonomy.category(id: CategoryId("nope")) == nil)
    }

    @Test func findsAStrideCategoryByItsId() {
        #expect(taxonomy.strideCategory(id: StrideId("tampering"))?.label == "Tampering")
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TaxonomyTests
```

Expected: FAIL — `cannot find 'Taxonomy' in scope`.

- [ ] **Step 3: Write the domain identifiers**

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Identifiers.swift`:

```swift
public struct TechnologyId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct ThreatId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct ProviderId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct CategoryId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct StrideId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}
```

- [ ] **Step 4: Write the taxonomy**

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Taxonomy.swift`:

```swift
public struct StrideCategory: Equatable, Sendable {
    public let id: StrideId
    public let label: String

    public init(id: StrideId, label: String) {
        self.id = id
        self.label = label
    }
}

public struct ThreatSeverity: Equatable, Sendable {
    public let id: String
    public let label: String
    /// 1-based position in the taxonomy's severity order. Drives risk scoring.
    public let rank: Int

    public init(id: String, label: String, rank: Int) {
        self.id = id
        self.label = label
        self.rank = rank
    }
}

public struct ServiceCategory: Equatable, Sendable {
    public let id: CategoryId
    public let label: String
    public let presetThreatIds: [ThreatId]

    public init(id: CategoryId, label: String, presetThreatIds: [ThreatId]) {
        self.id = id
        self.label = label
        self.presetThreatIds = presetThreatIds
    }
}

public struct Taxonomy: Equatable, Sendable {
    public let stride: [StrideCategory]
    public let severities: [ThreatSeverity]
    public let categories: [ServiceCategory]

    public init(stride: [StrideCategory], severities: [ThreatSeverity], categories: [ServiceCategory]) {
        self.stride = stride
        self.severities = severities
        self.categories = categories
    }

    public func severity(id: String) -> ThreatSeverity? {
        severities.first { $0.id == id }
    }

    public func category(id: CategoryId) -> ServiceCategory? {
        categories.first { $0.id == id }
    }

    public func strideCategory(id: StrideId) -> StrideCategory? {
        stride.first { $0.id == id }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TaxonomyTests
```

Expected: 4 tests pass.

- [ ] **Step 6: Write the remaining catalogue domain objects**

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Provider.swift`:

```swift
public struct Provider: Equatable, Sendable {
    public let id: ProviderId
    public let displayName: String

    public init(id: ProviderId, displayName: String) {
        self.id = id
        self.displayName = displayName
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Threat.swift`:

```swift
public struct Control: Equatable, Sendable {
    public let id: String
    public let description: String

    public init(id: String, description: String) {
        self.id = id
        self.description = description
    }
}

public struct MitreTechnique: Equatable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

public struct Threat: Equatable, Sendable {
    public let id: ThreatId
    public let name: String
    public let description: String
    public let severity: ThreatSeverity
    public let stride: [StrideId]
    public let mitreTechniques: [MitreTechnique]
    public let controls: [Control]
    public let isConnectionThreat: Bool
    public let isZoneThreat: Bool
    public let isPathwayThreat: Bool
    public let zoneContext: String?

    public init(
        id: ThreatId,
        name: String,
        description: String,
        severity: ThreatSeverity,
        stride: [StrideId] = [],
        mitreTechniques: [MitreTechnique] = [],
        controls: [Control] = [],
        isConnectionThreat: Bool = false,
        isZoneThreat: Bool = false,
        isPathwayThreat: Bool = false,
        zoneContext: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.stride = stride
        self.mitreTechniques = mitreTechniques
        self.controls = controls
        self.isConnectionThreat = isConnectionThreat
        self.isZoneThreat = isZoneThreat
        self.isPathwayThreat = isPathwayThreat
        self.zoneContext = zoneContext
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Technology.swift`:

```swift
public struct Technology: Equatable, Sendable {
    public let id: TechnologyId
    public let name: String
    public let provider: ProviderId
    public let category: CategoryId
    public let description: String
    public let threatIds: [ThreatId]
    public let enforcesEncryption: Bool
    public let internalOnly: Bool
    /// Technology-specific wording for a threat, keyed by threat id. Sparse.
    public let threatContext: [ThreatId: String]
    /// Technology-specific controls that supersede a threat's generic controls. Sparse.
    public let threatMitigations: [ThreatId: [String]]

    public init(
        id: TechnologyId,
        name: String,
        provider: ProviderId,
        category: CategoryId,
        description: String,
        threatIds: [ThreatId] = [],
        enforcesEncryption: Bool = false,
        internalOnly: Bool = false,
        threatContext: [ThreatId: String] = [:],
        threatMitigations: [ThreatId: [String]] = [:]
    ) {
        self.id = id
        self.name = name
        self.provider = provider
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
        self.internalOnly = internalOnly
        self.threatContext = threatContext
        self.threatMitigations = threatMitigations
    }
}
```

- [ ] **Step 7: Write the catalogue port**

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/gateway/TechnologyCatalogue.swift`:

```swift
/// Reads the technology and threat catalogue.
///
/// Later milestones extend this port with `connectionThreats()`, `zoneThreats()`
/// and `pathwayMitigations()`. Do not add them before the milestone that needs them.
public protocol TechnologyCatalogue {
    func all() -> [Technology]
    func findById(_ id: TechnologyId) -> Technology?
    /// The technology's threats, in the order the technology declares them.
    /// Empty for an unknown technology.
    func threatsFor(technologyId: TechnologyId) -> [Threat]
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
}
```

- [ ] **Step 8: Remove the placeholders**

```bash
cd /Users/craigjbass/Projects/threat-modeller
rm ThreatModelKit/Sources/ThreatModelKit/Placeholder.swift
rm ThreatModelKit/Tests/UnitTests/PackageBuildsTests.swift
```

Replace `threatmodeller/ContentView.swift`:

```swift
import SwiftUI

struct ContentView: View {
    var body: some View {
        Text("Threat Modeller")
            .padding()
    }
}
```

Replace `threatmodellerTests/threatmodellerTests.swift`:

```swift
import Testing
import ThreatModelKit
@testable import threatmodeller

struct WiringTests {
    @Test func theTestTargetCanSeeThePackage() {
        let severity = ThreatSeverity(id: "high", label: "High", rank: 3)
        #expect(severity.rank == 3)
    }
}
```

- [ ] **Step 9: Run everything**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | tail -3
```

Expected: package tests pass; `** BUILD SUCCEEDED **`.

- [ ] **Step 10: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: add catalogue domain objects and the catalogue port"
```

---

### Task 4: The bundled catalogue gateway

**Files:**
- Create: `ThreatModelKit/Sources/CatalogueGateways/CatalogueJSON.swift`
- Create: `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift`
- Create: `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`
- Delete: `ThreatModelKit/Sources/CatalogueGateways/Placeholder.swift`

**Interfaces:**
- Consumes: `LibraryResources.data(named:)` from Task 2; every domain type and the `TechnologyCatalogue` protocol from Task 3
- Produces: `BundledTechnologyCatalogue()` — a `TechnologyCatalogue` whose `init` throws `CatalogueLoadError`

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`:

```swift
import Testing
import ThreatModelKit
@testable import CatalogueGateways

struct BundledTechnologyCatalogueTests {
    private let catalogue: BundledTechnologyCatalogue

    init() throws {
        catalogue = try BundledTechnologyCatalogue()
    }

    @Test func loadsEveryVendoredTechnology() {
        #expect(catalogue.all().count == 277)
    }

    @Test func listsProvidersByIdAscending() {
        #expect(catalogue.providers().map(\.id.value) == ["aws", "azure", "gcp", "saas", "self-hosted"])
        #expect(catalogue.providers().first?.displayName == "Amazon Web Services")
    }

    @Test func ranksSeveritiesInTaxonomyOrder() {
        let severities = catalogue.taxonomy().severities
        #expect(severities.map(\.id) == ["low", "medium", "high", "critical"])
        #expect(severities.map(\.rank) == [1, 2, 3, 4])
    }

    @Test func loadsTheRestOfTheTaxonomy() {
        #expect(catalogue.taxonomy().stride.count == 6)
        #expect(catalogue.taxonomy().categories.count == 14)
        #expect(catalogue.taxonomy().category(id: CategoryId("compute"))?.label == "Compute")
    }

    @Test func findsATechnologyById() throws {
        let ec2 = try #require(catalogue.findById(TechnologyId("aws-ec2")))
        #expect(ec2.name == "EC2")
        #expect(ec2.provider == ProviderId("aws"))
        #expect(ec2.category == CategoryId("compute"))
        #expect(ec2.description == "Virtual servers in the cloud")
        #expect(ec2.enforcesEncryption == false)
        #expect(ec2.threatIds.count == 10)
    }

    @Test func carriesTechnologySpecificContextAndMitigations() throws {
        let ec2 = try #require(catalogue.findById(TechnologyId("aws-ec2")))
        #expect(ec2.threatContext[ThreatId("credential-theft")]?.contains("169.254.169.254") == true)
        #expect(ec2.threatMitigations[ThreatId("credential-theft")]?.count == 3)
        #expect(ec2.threatMitigations[ThreatId("misconfiguration")]?.count == 4)
    }

    @Test func returnsNilForAnUnknownTechnology() {
        #expect(catalogue.findById(TechnologyId("aws-nope")) == nil)
    }

    @Test func resolvesThreatsInTheOrderTheTechnologyDeclaresThem() {
        let threats = catalogue.threatsFor(technologyId: TechnologyId("aws-ec2"))
        #expect(threats.map(\.id.value) == [
            "unauthorized-access",
            "misconfiguration",
            "malware-infection",
            "data-exfiltration",
            "privilege-escalation",
            "dos-attack",
            "credential-theft",
            "lateral-movement",
            "unpatched-vulnerabilities",
            "ssrf-attack"
        ])
    }

    @Test func resolvesSeverityFromTheTaxonomy() throws {
        let threats = catalogue.threatsFor(technologyId: TechnologyId("aws-ec2"))
        let credentialTheft = try #require(threats.first { $0.id == ThreatId("credential-theft") })
        #expect(credentialTheft.severity.id == "critical")
        #expect(credentialTheft.severity.rank == 4)
        #expect(credentialTheft.isPathwayThreat)
        #expect(credentialTheft.controls.count == 5)
        #expect(credentialTheft.mitreTechniques.isEmpty == false)
    }

    @Test func flagsConnectionAndZoneThreats() throws {
        let threats = catalogue.threatsFor(technologyId: TechnologyId("aws-ec2"))
        let unauthorised = try #require(threats.first { $0.id == ThreatId("unauthorized-access") })
        #expect(unauthorised.isZoneThreat)
        #expect(unauthorised.isConnectionThreat == false)
    }

    @Test func returnsNoThreatsForAnUnknownTechnology() {
        #expect(catalogue.threatsFor(technologyId: TechnologyId("aws-nope")).isEmpty)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter BundledTechnologyCatalogueTests
```

Expected: FAIL — `cannot find 'BundledTechnologyCatalogue' in scope`.

- [ ] **Step 3: Write the JSON data transfer objects**

Create `ThreatModelKit/Sources/CatalogueGateways/CatalogueJSON.swift`:

```swift
import Foundation

// Mirrors the vendored JSON exactly. These types exist only so the gateway can
// build Domain objects; nothing outside this target sees them.

struct TaxonomyJSON: Decodable {
    struct Labelled: Decodable {
        let id: String
        let label: String
    }

    struct Category: Decodable {
        let id: String
        let label: String
        let presetThreatIds: [String]
    }

    let stride: [Labelled]
    let severities: [Labelled]
    let categories: [Category]
}

struct ProviderFileJSON: Decodable {
    let provider: String
    let displayName: String
    let services: [ServiceJSON]
}

struct ServiceJSON: Decodable {
    struct ConnectionSecurity: Decodable {
        let enforcesEncryption: Bool?
        let internalOnly: Bool?
    }

    let id: String
    let name: String
    let provider: String
    let category: String
    let description: String
    let threatIds: [String]
    let connectionSecurity: ConnectionSecurity?
    let threatContext: [String: String]?
    let threatMitigations: [String: [String]]?
}

struct ThreatsFileJSON: Decodable {
    let threats: [ThreatJSON]
}

struct ThreatJSON: Decodable {
    struct Mitre: Decodable {
        let id: String
        let name: String
        let tactic: String
    }

    struct ControlEntry: Decodable {
        let id: String
        let description: String
    }

    let id: String
    let name: String
    let description: String
    let severity: String
    let stride: [String]
    let mitreTechniques: [Mitre]
    let controls: [ControlEntry]
    let isConnectionThreat: Bool?
    let isZoneThreat: Bool?
    let isPathwayThreat: Bool?
    let zoneContext: String?
}
```

- [ ] **Step 4: Write the gateway**

Create `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift`:

```swift
import Foundation
import ThreatModelKit

public enum CatalogueLoadError: Error, Equatable {
    case unknownSeverity(threatId: String, severity: String)
}

/// Reads the catalogue vendored into this target's resource bundle.
public final class BundledTechnologyCatalogue: TechnologyCatalogue {
    private static let providerFiles = [
        "aws", "azure", "gcp", "saas", "self-hosted"
    ]

    private let taxonomyValue: Taxonomy
    private let providersValue: [Provider]
    private let technologies: [Technology]
    private let technologiesById: [TechnologyId: Technology]
    private let threatsById: [ThreatId: Threat]

    public init() throws {
        let decoder = JSONDecoder()

        let taxonomyJSON = try decoder.decode(
            TaxonomyJSON.self,
            from: try LibraryResources.data(named: "taxonomy.json")
        )
        taxonomyValue = Taxonomy(
            stride: taxonomyJSON.stride.map {
                StrideCategory(id: StrideId($0.id), label: $0.label)
            },
            severities: taxonomyJSON.severities.enumerated().map { index, entry in
                ThreatSeverity(id: entry.id, label: entry.label, rank: index + 1)
            },
            categories: taxonomyJSON.categories.map {
                ServiceCategory(
                    id: CategoryId($0.id),
                    label: $0.label,
                    presetThreatIds: $0.presetThreatIds.map(ThreatId.init)
                )
            }
        )

        let threatsJSON = try decoder.decode(
            ThreatsFileJSON.self,
            from: try LibraryResources.data(named: "threats/common-threats.json")
        )
        var threats: [ThreatId: Threat] = [:]
        for entry in threatsJSON.threats {
            guard let severity = taxonomyValue.severity(id: entry.severity) else {
                throw CatalogueLoadError.unknownSeverity(threatId: entry.id, severity: entry.severity)
            }
            threats[ThreatId(entry.id)] = Threat(
                id: ThreatId(entry.id),
                name: entry.name,
                description: entry.description,
                severity: severity,
                stride: entry.stride.map(StrideId.init),
                mitreTechniques: entry.mitreTechniques.map {
                    MitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                },
                controls: entry.controls.map {
                    Control(id: $0.id, description: $0.description)
                },
                isConnectionThreat: entry.isConnectionThreat ?? false,
                isZoneThreat: entry.isZoneThreat ?? false,
                isPathwayThreat: entry.isPathwayThreat ?? false,
                zoneContext: entry.zoneContext
            )
        }
        threatsById = threats

        var providers: [Provider] = []
        var loaded: [Technology] = []
        for file in Self.providerFiles.sorted() {
            let providerJSON = try decoder.decode(
                ProviderFileJSON.self,
                from: try LibraryResources.data(named: "technologies/\(file).json")
            )
            providers.append(
                Provider(id: ProviderId(providerJSON.provider), displayName: providerJSON.displayName)
            )
            loaded.append(contentsOf: providerJSON.services.map(Self.technology(from:)))
        }
        providersValue = providers
        technologies = loaded
        technologiesById = Dictionary(uniqueKeysWithValues: loaded.map { ($0.id, $0) })
    }

    private static func technology(from service: ServiceJSON) -> Technology {
        Technology(
            id: TechnologyId(service.id),
            name: service.name,
            provider: ProviderId(service.provider),
            category: CategoryId(service.category),
            description: service.description,
            threatIds: service.threatIds.map(ThreatId.init),
            enforcesEncryption: service.connectionSecurity?.enforcesEncryption ?? false,
            internalOnly: service.connectionSecurity?.internalOnly ?? false,
            threatContext: Dictionary(
                uniqueKeysWithValues: (service.threatContext ?? [:]).map { (ThreatId($0.key), $0.value) }
            ),
            threatMitigations: Dictionary(
                uniqueKeysWithValues: (service.threatMitigations ?? [:]).map { (ThreatId($0.key), $0.value) }
            )
        )
    }

    public func all() -> [Technology] { technologies }

    public func findById(_ id: TechnologyId) -> Technology? { technologiesById[id] }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let technology = technologiesById[technologyId] else { return [] }
        return technology.threatIds.compactMap { threatsById[$0] }
    }

    public func taxonomy() -> Taxonomy { taxonomyValue }

    public func providers() -> [Provider] { providersValue }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
rm ThreatModelKit/Sources/CatalogueGateways/Placeholder.swift
cd ThreatModelKit && swift test --filter BundledTechnologyCatalogueTests
```

Expected: 11 tests pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: read the vendored catalogue through a real gateway"
```

---

### Task 5: The fake catalogue and the shared gateway contract

**Files:**
- Create: `ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift`
- Create: `ThreatModelKit/Sources/TestSupport/CatalogueFixture.swift`
- Create: `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift`
- Create: `ThreatModelKit/Tests/GatewayContractTests/TechnologyCatalogueContractTests.swift`
- Delete: `ThreatModelKit/Sources/TestSupport/Placeholder.swift`
- Delete: `ThreatModelKit/Tests/GatewayContractTests/Placeholder.swift`

**Interfaces:**
- Consumes: `TechnologyCatalogue` and the domain from Task 3; `BundledTechnologyCatalogue` from Task 4
- Produces:
  - `InMemoryTechnologyCatalogue(technologies:threats:taxonomy:providers:)` implementing `TechnologyCatalogue`
  - `CatalogueFixture.taxonomy() -> Taxonomy`, `CatalogueFixture.ec2() -> Technology`, `CatalogueFixture.ec2Threats() -> [Threat]`, `CatalogueFixture.catalogue() -> InMemoryTechnologyCatalogue`
  - `verifyTechnologyCatalogueContract(_ subject: TechnologyCatalogue, knownTechnologyId: TechnologyId) throws`

- [ ] **Step 1: Write the failing test**

Delete `ThreatModelKit/Tests/GatewayContractTests/Placeholder.swift` and create
`ThreatModelKit/Tests/GatewayContractTests/TechnologyCatalogueContractTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport
import CatalogueGateways

struct TechnologyCatalogueContractTests {
    @Test func theFakeHonoursTheContract() throws {
        try verifyTechnologyCatalogueContract(
            CatalogueFixture.catalogue(),
            knownTechnologyId: TechnologyId("aws-ec2")
        )
    }

    @Test func theBundledCatalogueHonoursTheContract() throws {
        try verifyTechnologyCatalogueContract(
            try BundledTechnologyCatalogue(),
            knownTechnologyId: TechnologyId("aws-ec2")
        )
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyCatalogueContractTests
```

Expected: FAIL — `cannot find 'verifyTechnologyCatalogueContract' in scope`.

- [ ] **Step 3: Write the fake**

Delete `ThreatModelKit/Sources/TestSupport/Placeholder.swift` and create
`ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift`:

```swift
import ThreatModelKit

/// A working catalogue backed by arrays. Honours the same contract as the real one.
public final class InMemoryTechnologyCatalogue: TechnologyCatalogue {
    private let technologies: [Technology]
    private let threats: [ThreatId: Threat]
    private let taxonomyValue: Taxonomy
    private let providersValue: [Provider]

    public init(
        technologies: [Technology],
        threats: [Threat],
        taxonomy: Taxonomy,
        providers: [Provider]
    ) {
        self.technologies = technologies
        self.threats = Dictionary(uniqueKeysWithValues: threats.map { ($0.id, $0) })
        self.taxonomyValue = taxonomy
        self.providersValue = providers
    }

    public func all() -> [Technology] { technologies }

    public func findById(_ id: TechnologyId) -> Technology? {
        technologies.first { $0.id == id }
    }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let technology = findById(technologyId) else { return [] }
        return technology.threatIds.compactMap { threats[$0] }
    }

    public func taxonomy() -> Taxonomy { taxonomyValue }

    public func providers() -> [Provider] { providersValue }
}
```

- [ ] **Step 4: Write the fixtures**

Create `ThreatModelKit/Sources/TestSupport/CatalogueFixture.swift`:

```swift
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
```

- [ ] **Step 5: Write the contract**

`TestSupport` is a library target, not a test target, and it imports `Testing`.
That is deliberate and it builds: the contract has to be callable from more than
one test target. Because `TestSupport` is absent from the package's `products`,
`Testing` never links into the application.

Create `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift`:

```swift
import Testing
import ThreatModelKit

/// The behaviour every `TechnologyCatalogue` must exhibit, expressed entirely in
/// Domain objects. Run it against the fake and the real gateway alike.
public func verifyTechnologyCatalogueContract(
    _ subject: TechnologyCatalogue,
    knownTechnologyId: TechnologyId
) throws {
    let unknownId = TechnologyId("no-such-technology")

    #expect(subject.all().isEmpty == false)

    let known = try #require(subject.findById(knownTechnologyId))
    #expect(known.id == knownTechnologyId)
    #expect(subject.findById(unknownId) == nil)

    let threats = subject.threatsFor(technologyId: knownTechnologyId)
    #expect(threats.map(\.id) == known.threatIds)
    #expect(subject.threatsFor(technologyId: unknownId).isEmpty)

    let taxonomy = subject.taxonomy()
    #expect(taxonomy.severities.map(\.rank) == Array(1...taxonomy.severities.count))
    #expect(Set(taxonomy.severities.map(\.id)).count == taxonomy.severities.count)

    let providerIds = Set(subject.providers().map(\.id))
    let categoryIds = Set(taxonomy.categories.map(\.id))
    for technology in subject.all() {
        #expect(providerIds.contains(technology.provider))
        #expect(categoryIds.contains(technology.category))
    }

    for threat in threats {
        #expect(taxonomy.severity(id: threat.severity.id) == threat.severity)
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyCatalogueContractTests
```

Expected: 2 tests pass. If the fake fails on the provider or category check, the fixture's taxonomy is missing a category the fixture technologies use — add it to `CatalogueFixture.taxonomy()`, do not weaken the contract.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "test: hold the fake and real catalogue to one contract"
```

---

### Task 6: ListTechnologies

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/usecase/ListTechnologies.swift`
- Create: `ThreatModelKit/Tests/UnitTests/ListTechnologiesTests.swift`

**Interfaces:**
- Consumes: `TechnologyCatalogue`; `CatalogueFixture.catalogue()`
- Produces:
  - `protocol ListTechnologiesUseCase { func execute(_ request: ListTechnologiesRequest) -> ListTechnologiesResponse }`
  - `ListTechnologiesRequest()`
  - `ListTechnologiesResponse(providers: [ListedProvider])`
  - `ListedProvider(id: String, displayName: String, categories: [ListedCategory])`
  - `ListedCategory(id: String, label: String, technologies: [ListedTechnology])`
  - `ListedTechnology(id: String, name: String, description: String)`
  - `ListTechnologies(catalogue: TechnologyCatalogue)`

Ordering, which the tests pin: providers in the order the catalogue returns them; within a provider, categories in taxonomy order, omitting categories with no technologies; within a category, technologies by name ascending, case-insensitively.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ListTechnologiesTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ListTechnologiesTests {
    private let useCase = ListTechnologies(catalogue: CatalogueFixture.catalogue())

    @Test func groupsTechnologiesUnderTheirProvider() {
        let response = useCase.execute(ListTechnologiesRequest())
        #expect(response.providers.map(\.id) == ["aws", "gcp"])
        #expect(response.providers.first?.displayName == "Amazon Web Services")
    }

    @Test func groupsTechnologiesUnderTheirCategoryInTaxonomyOrder() throws {
        let response = useCase.execute(ListTechnologiesRequest())
        let aws = try #require(response.providers.first { $0.id == "aws" })
        #expect(aws.categories.map(\.id) == ["compute", "database"])
        #expect(aws.categories.first?.label == "Compute")
    }

    @Test func omitsCategoriesWithNoTechnologies() throws {
        let response = useCase.execute(ListTechnologiesRequest())
        let gcp = try #require(response.providers.first { $0.id == "gcp" })
        #expect(gcp.categories.map(\.id) == ["database"])
    }

    @Test func listsTechnologiesByName() throws {
        let catalogue = InMemoryTechnologyCatalogue(
            technologies: [
                Technology(
                    id: TechnologyId("aws-zeta"),
                    name: "Zeta",
                    provider: ProviderId("aws"),
                    category: CategoryId("compute"),
                    description: "Last"
                ),
                Technology(
                    id: TechnologyId("aws-alpha"),
                    name: "alpha",
                    provider: ProviderId("aws"),
                    category: CategoryId("compute"),
                    description: "First"
                )
            ],
            threats: [],
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )

        let response = ListTechnologies(catalogue: catalogue).execute(ListTechnologiesRequest())
        let compute = try #require(response.providers.first?.categories.first)
        #expect(compute.technologies.map(\.name) == ["alpha", "Zeta"])
        #expect(compute.technologies.first?.id == "aws-alpha")
        #expect(compute.technologies.first?.description == "First")
    }

    @Test func omitsProvidersWithNoTechnologies() {
        let catalogue = InMemoryTechnologyCatalogue(
            technologies: [],
            threats: [],
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )
        let response = ListTechnologies(catalogue: catalogue).execute(ListTechnologiesRequest())
        #expect(response.providers.isEmpty)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ListTechnologiesTests
```

Expected: FAIL — `cannot find 'ListTechnologies' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/catalogue/usecase/ListTechnologies.swift`:

```swift
public protocol ListTechnologiesUseCase {
    func execute(_ request: ListTechnologiesRequest) -> ListTechnologiesResponse
}

public struct ListTechnologiesRequest: Equatable, Sendable {
    public init() {}
}

public struct ListTechnologiesResponse: Equatable, Sendable {
    public let providers: [ListedProvider]

    public init(providers: [ListedProvider]) {
        self.providers = providers
    }
}

public struct ListedProvider: Equatable, Sendable {
    public let id: String
    public let displayName: String
    public let categories: [ListedCategory]

    public init(id: String, displayName: String, categories: [ListedCategory]) {
        self.id = id
        self.displayName = displayName
        self.categories = categories
    }
}

public struct ListedCategory: Equatable, Sendable {
    public let id: String
    public let label: String
    public let technologies: [ListedTechnology]

    public init(id: String, label: String, technologies: [ListedTechnology]) {
        self.id = id
        self.label = label
        self.technologies = technologies
    }
}

public struct ListedTechnology: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String

    public init(id: String, name: String, description: String) {
        self.id = id
        self.name = name
        self.description = description
    }
}

public struct ListTechnologies: ListTechnologiesUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ListTechnologiesRequest) -> ListTechnologiesResponse {
        let taxonomy = catalogue.taxonomy()
        let byProvider = Dictionary(grouping: catalogue.all(), by: \.provider)

        let providers = catalogue.providers().compactMap { provider -> ListedProvider? in
            let technologies = byProvider[provider.id] ?? []
            guard technologies.isEmpty == false else { return nil }

            let byCategory = Dictionary(grouping: technologies, by: \.category)
            let categories = taxonomy.categories.compactMap { category -> ListedCategory? in
                guard let members = byCategory[category.id], members.isEmpty == false else { return nil }
                return ListedCategory(
                    id: category.id.value,
                    label: category.label,
                    technologies: members
                        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                        .map {
                            ListedTechnology(id: $0.id.value, name: $0.name, description: $0.description)
                        }
                )
            }

            return ListedProvider(
                id: provider.id.value,
                displayName: provider.displayName,
                categories: categories
            )
        }

        return ListTechnologiesResponse(providers: providers)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ListTechnologiesTests
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: add the ListTechnologies use case"
```

---

### Task 7: Modelling domain, its gateways, and AddComponent

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Point.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DataSensitivity.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/gateway/ThreatModelGateway.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/gateway/IdentityGenerator.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/AddComponent.swift`
- Create: `ThreatModelKit/Sources/TestSupport/SequentialIdentityGenerator.swift`
- Create: `ThreatModelKit/Tests/UnitTests/AddComponentTests.swift`

**Interfaces:**
- Consumes: `TechnologyCatalogue`, `TechnologyId`, `CatalogueFixture`
- Produces:
  - `Point(x: Double, y: Double)`
  - `DataSensitivity` — `.publicData`, `.internalData`, `.confidential`, `.restricted`, raw values `"public"`, `"internal"`, `"confidential"`, `"restricted"`, with `.rank: Int` and `.label: String`
  - `ComponentId(_ value: String)`
  - `Component(id:technologyId:position:sensitivity:customName:threatsDisabled:)`
  - `ThreatModel(name:components:)` with `var components: [Component]`
  - `protocol ThreatModelGateway: AnyObject { func current() -> ThreatModel; func save(_ model: ThreatModel) }` plus `InMemoryThreatModelGateway(_ model: ThreatModel = ThreatModel())`
  - `protocol IdentityGenerator { func next() -> String }` plus `UUIDIdentityGenerator()`
  - `protocol AddComponentUseCase`, `AddComponentRequest(technologyId:x:y:sensitivity:)`, `AddComponentResponse` (`.added(componentId: String)`, `.unknownTechnology`, `.unknownSensitivity`), `AddComponent(models:catalogue:ids:)`
  - `SequentialIdentityGenerator()` yielding `"id-1"`, `"id-2"`, …

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/AddComponentTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct AddComponentTests {
    private let models = InMemoryThreatModelGateway()
    private let ids = SequentialIdentityGenerator()

    private func useCase() -> AddComponent {
        AddComponent(models: models, catalogue: CatalogueFixture.catalogue(), ids: ids)
    }

    @Test func addsTheTechnologyToTheModel() {
        let response = useCase().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 120, y: 240, sensitivity: "confidential")
        )

        #expect(response == .added(componentId: "id-1"))
        #expect(models.current().components.count == 1)

        let component = models.current().components[0]
        #expect(component.technologyId == TechnologyId("aws-ec2"))
        #expect(component.position == Point(x: 120, y: 240))
        #expect(component.sensitivity == .confidential)
        #expect(component.customName == nil)
        #expect(component.threatsDisabled == false)
    }

    @Test func keepsEarlierComponents() {
        _ = useCase().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        let second = useCase().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 10, y: 10, sensitivity: "restricted")
        )

        #expect(second == .added(componentId: "id-2"))
        #expect(models.current().components.map(\.technologyId.value) == ["aws-ec2", "aws-rds"])
    }

    @Test func rejectsATechnologyTheCatalogueDoesNotHave() {
        let response = useCase().execute(
            AddComponentRequest(technologyId: "aws-nope", x: 0, y: 0, sensitivity: "internal")
        )

        #expect(response == .unknownTechnology)
        #expect(models.current().components.isEmpty)
    }

    @Test func rejectsAnUnknownSensitivity() {
        let response = useCase().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "top-secret")
        )

        #expect(response == .unknownSensitivity)
        #expect(models.current().components.isEmpty)
    }

    @Test func ranksSensitivities() {
        #expect(DataSensitivity.publicData.rank == 1)
        #expect(DataSensitivity.internalData.rank == 2)
        #expect(DataSensitivity.confidential.rank == 3)
        #expect(DataSensitivity.restricted.rank == 4)
        #expect(DataSensitivity.internalData.label == "Internal")
        #expect(DataSensitivity(rawValue: "public") == .publicData)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AddComponentTests
```

Expected: FAIL — `cannot find 'InMemoryThreatModelGateway' in scope`.

- [ ] **Step 3: Write the modelling domain**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Point.swift`:

```swift
public struct Point: Equatable, Sendable {
    public let x: Double
    public let y: Double

    public init(x: Double, y: Double) {
        self.x = x
        self.y = y
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DataSensitivity.swift`:

```swift
/// How sensitive the data handled by a component is. Application-owned: the
/// catalogue has no opinion on it. The rank multiplies threat severity to give
/// a risk score.
public enum DataSensitivity: String, CaseIterable, Equatable, Sendable {
    case publicData = "public"
    case internalData = "internal"
    case confidential = "confidential"
    case restricted = "restricted"

    public var rank: Int {
        switch self {
        case .publicData: 1
        case .internalData: 2
        case .confidential: 3
        case .restricted: 4
        }
    }

    public var label: String {
        switch self {
        case .publicData: "Public"
        case .internalData: "Internal"
        case .confidential: "Confidential"
        case .restricted: "Restricted"
        }
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`:

```swift
public struct ComponentId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct Component: Equatable, Sendable {
    public let id: ComponentId
    public let technologyId: TechnologyId
    public var position: Point
    public var sensitivity: DataSensitivity
    public var customName: String?
    /// When true the component raises no threats and suppresses threats on
    /// anything attached to it. Honoured from Milestone 2 onwards.
    public var threatsDisabled: Bool

    public init(
        id: ComponentId,
        technologyId: TechnologyId,
        position: Point,
        sensitivity: DataSensitivity,
        customName: String? = nil,
        threatsDisabled: Bool = false
    ) {
        self.id = id
        self.technologyId = technologyId
        self.position = position
        self.sensitivity = sensitivity
        self.customName = customName
        self.threatsDisabled = threatsDisabled
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`:

```swift
/// The aggregate a threat model is assessed from. Connections, zones, overrides
/// and implemented controls join it in later milestones.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]

    public init(name: String = "Untitled", components: [Component] = []) {
        self.name = name
        self.components = components
    }
}
```

- [ ] **Step 4: Write the modelling gateways**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/gateway/ThreatModelGateway.swift`:

```swift
/// Holds the model currently being edited.
public protocol ThreatModelGateway: AnyObject {
    func current() -> ThreatModel
    func save(_ model: ThreatModel)
}

/// The model store for one open document. From Milestone 6 a document seeds it
/// on open and writes it back on save.
public final class InMemoryThreatModelGateway: ThreatModelGateway {
    private var model: ThreatModel

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel { model }

    public func save(_ model: ThreatModel) { self.model = model }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/gateway/IdentityGenerator.swift`:

```swift
import Foundation

public protocol IdentityGenerator {
    func next() -> String
}

public struct UUIDIdentityGenerator: IdentityGenerator {
    public init() {}

    public func next() -> String { UUID().uuidString }
}
```

Create `ThreatModelKit/Sources/TestSupport/SequentialIdentityGenerator.swift`:

```swift
import ThreatModelKit

/// Yields "id-1", "id-2", … so tests can assert on identifiers.
public final class SequentialIdentityGenerator: IdentityGenerator {
    private var issued = 0

    public init() {}

    public func next() -> String {
        issued += 1
        return "id-\(issued)"
    }
}
```

- [ ] **Step 5: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/AddComponent.swift`:

```swift
public protocol AddComponentUseCase {
    func execute(_ request: AddComponentRequest) -> AddComponentResponse
}

public struct AddComponentRequest: Equatable, Sendable {
    public let technologyId: String
    public let x: Double
    public let y: Double
    public let sensitivity: String

    public init(technologyId: String, x: Double, y: Double, sensitivity: String) {
        self.technologyId = technologyId
        self.x = x
        self.y = y
        self.sensitivity = sensitivity
    }
}

public enum AddComponentResponse: Equatable, Sendable {
    case added(componentId: String)
    case unknownTechnology
    case unknownSensitivity
}

public struct AddComponent: AddComponentUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue, ids: IdentityGenerator) {
        self.models = models
        self.catalogue = catalogue
        self.ids = ids
    }

    public func execute(_ request: AddComponentRequest) -> AddComponentResponse {
        let technologyId = TechnologyId(request.technologyId)
        guard catalogue.findById(technologyId) != nil else {
            return .unknownTechnology
        }
        guard let sensitivity = DataSensitivity(rawValue: request.sensitivity) else {
            return .unknownSensitivity
        }

        let component = Component(
            id: ComponentId(ids.next()),
            technologyId: technologyId,
            position: Point(x: request.x, y: request.y),
            sensitivity: sensitivity
        )

        var model = models.current()
        model.components.append(component)
        models.save(model)

        return .added(componentId: component.id.value)
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AddComponentTests
```

Expected: 5 tests pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: add the modelling domain and the AddComponent use case"
```

---

### Task 8: RiskScore

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/RiskScore.swift`
- Create: `ThreatModelKit/Tests/UnitTests/RiskScoreTests.swift`

**Interfaces:**
- Consumes: `ThreatSeverity`, `DataSensitivity`
- Produces:
  - `enum RiskLevel: String { case low, medium, high, critical }`
  - `RiskScore(value: Int)` and `RiskScore(severity: ThreatSeverity, sensitivity: DataSensitivity)`, with `.value: Int` and `.level: RiskLevel`

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RiskScoreTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct RiskScoreTests {
    @Test func multipliesSeverityRankBySensitivityRank() {
        #expect(RiskScore(severity: CatalogueFixture.critical, sensitivity: .restricted).value == 16)
        #expect(RiskScore(severity: CatalogueFixture.low, sensitivity: .publicData).value == 1)
        #expect(RiskScore(severity: CatalogueFixture.high, sensitivity: .confidential).value == 9)
        #expect(RiskScore(severity: CatalogueFixture.medium, sensitivity: .internalData).value == 4)
    }

    @Test func callsTwelveAndAboveCritical() {
        #expect(RiskScore(value: 12).level == .critical)
        #expect(RiskScore(value: 16).level == .critical)
    }

    @Test func callsEightToElevenHigh() {
        #expect(RiskScore(value: 8).level == .high)
        #expect(RiskScore(value: 11).level == .high)
    }

    @Test func callsFourToSevenMedium() {
        #expect(RiskScore(value: 4).level == .medium)
        #expect(RiskScore(value: 7).level == .medium)
    }

    @Test func callsBelowFourLow() {
        #expect(RiskScore(value: 3).level == .low)
        #expect(RiskScore(value: 1).level == .low)
        #expect(RiskScore(value: 0).level == .low)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RiskScoreTests
```

Expected: FAIL — `cannot find 'RiskScore' in scope`.

- [ ] **Step 3: Write the domain object**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/RiskScore.swift`:

```swift
public enum RiskLevel: String, Equatable, Sendable {
    case low
    case medium
    case high
    case critical
}

/// Severity rank multiplied by data sensitivity rank, giving 1–16.
///
/// Later milestones fold in the zone multiplier and pathway reduction; the
/// thresholds below stay as they are.
public struct RiskScore: Equatable, Sendable {
    public let value: Int

    public init(value: Int) {
        self.value = value
    }

    public init(severity: ThreatSeverity, sensitivity: DataSensitivity) {
        self.value = severity.rank * sensitivity.rank
    }

    public var level: RiskLevel {
        if value >= 12 { return .critical }
        if value >= 8 { return .high }
        if value >= 4 { return .medium }
        return .low
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RiskScoreTests
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: add the RiskScore domain object"
```

---

### Task 9: AssessThreatModel

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Create: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `TechnologyCatalogue`, `RiskScore`, `CatalogueFixture`
- Produces:
  - `protocol AssessThreatModelUseCase`, `AssessThreatModelRequest()`, `AssessThreatModelResponse(threats: [AssessedThreat])`
  - `AssessedThreat(threatId:name:description:severityId:severityLabel:stride:mitreTechniques:controls:sourceComponentId:sourceName:sourceProviderId:sensitivityId:riskScore:riskLevel:context:)`
  - `AssessedControl(description: String, isTechnologySpecific: Bool)`
  - `AssessedMitreTechnique(id: String, name: String, tactic: String)`
  - All three of the above conform to `Hashable, Sendable`, so SwiftUI can key
    a `List` on them in Task 11
  - `AssessThreatModel(models: ThreatModelGateway, catalogue: TechnologyCatalogue)`

Rules this milestone implements: one entry per (component, threat); score is severity rank × the component's sensitivity rank; technology-specific mitigations supersede a threat's generic controls; a component with `threatsDisabled` raises nothing; entries scoring zero are dropped; results are ordered by score descending, then threat id ascending, then component id ascending.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`:

```swift
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
        threatsDisabled: Bool = false
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
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

    @Test func ordersByScoreThenThreatIdThenComponentId() {
        let response = assess(
            ThreatModel(components: [ec2(id: "c2"), ec2(id: "c1", sensitivity: .publicData)])
        )
        let ordering = response.threats.map { "\($0.riskScore):\($0.threatId):\($0.sourceComponentId)" }
        #expect(ordering == [
            "12:credential-theft:c2",
            "6:misconfiguration:c2",
            "4:credential-theft:c1",
            "3:dos-attack:c2",
            "2:misconfiguration:c1",
            "1:dos-attack:c1"
        ])
    }

    @Test func namesTheSourceAfterTheTechnologyUnlessRenamed() throws {
        let plain = assess(ThreatModel(components: [ec2()]))
        #expect(plain.threats.first?.sourceName == "EC2")
        #expect(plain.threats.first?.sourceProviderId == "aws")
        #expect(plain.threats.first?.sourceComponentId == "c1")

        let renamed = assess(ThreatModel(components: [ec2(customName: "Bastion host")]))
        #expect(renamed.threats.first?.sourceName == "Bastion host")
    }

    @Test func prefersTechnologySpecificMitigationsOverGenericControls() throws {
        let response = assess(ThreatModel(components: [ec2()]))

        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(credentialTheft.controls.allSatisfy(\.isTechnologySpecific))
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
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests
```

Expected: FAIL — `cannot find 'AssessThreatModel' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`:

```swift
public protocol AssessThreatModelUseCase {
    func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse
}

public struct AssessThreatModelRequest: Equatable, Sendable {
    public init() {}
}

public struct AssessThreatModelResponse: Equatable, Sendable {
    public let threats: [AssessedThreat]

    public init(threats: [AssessedThreat]) {
        self.threats = threats
    }
}

public struct AssessedMitreTechnique: Hashable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

public struct AssessedControl: Hashable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool

    public init(description: String, isTechnologySpecific: Bool) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
    }
}

public struct AssessedThreat: Hashable, Sendable {
    public let threatId: String
    public let name: String
    public let description: String
    public let severityId: String
    public let severityLabel: String
    public let stride: [String]
    public let mitreTechniques: [AssessedMitreTechnique]
    public let controls: [AssessedControl]
    public let sourceComponentId: String
    public let sourceName: String
    public let sourceProviderId: String
    public let sensitivityId: String
    public let riskScore: Int
    public let riskLevel: String
    public let context: String?

    public init(
        threatId: String,
        name: String,
        description: String,
        severityId: String,
        severityLabel: String,
        stride: [String],
        mitreTechniques: [AssessedMitreTechnique],
        controls: [AssessedControl],
        sourceComponentId: String,
        sourceName: String,
        sourceProviderId: String,
        sensitivityId: String,
        riskScore: Int,
        riskLevel: String,
        context: String?
    ) {
        self.threatId = threatId
        self.name = name
        self.description = description
        self.severityId = severityId
        self.severityLabel = severityLabel
        self.stride = stride
        self.mitreTechniques = mitreTechniques
        self.controls = controls
        self.sourceComponentId = sourceComponentId
        self.sourceName = sourceName
        self.sourceProviderId = sourceProviderId
        self.sensitivityId = sensitivityId
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.context = context
    }
}

public struct AssessThreatModel: AssessThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        var assessed: [AssessedThreat] = []

        for component in models.current().components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = catalogue.findById(component.technologyId) else { continue }

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let score = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
                guard score.value > 0 else { continue }

                assessed.append(
                    AssessedThreat(
                        threatId: threat.id.value,
                        name: threat.name,
                        description: threat.description,
                        severityId: threat.severity.id,
                        severityLabel: threat.severity.label,
                        stride: threat.stride.map(\.value),
                        mitreTechniques: threat.mitreTechniques.map {
                            AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                        },
                        controls: Self.controls(for: threat, on: technology),
                        sourceComponentId: component.id.value,
                        sourceName: component.customName ?? technology.name,
                        sourceProviderId: technology.provider.value,
                        sensitivityId: component.sensitivity.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
                        context: technology.threatContext[threat.id]
                    )
                )
            }
        }

        return AssessThreatModelResponse(threats: assessed.sorted(by: Self.ordering))
    }

    private static func controls(for threat: Threat, on technology: Technology) -> [AssessedControl] {
        if let specific = technology.threatMitigations[threat.id], specific.isEmpty == false {
            return specific.map { AssessedControl(description: $0, isTechnologySpecific: true) }
        }
        return threat.controls.map {
            AssessedControl(description: $0.description, isTechnologySpecific: false)
        }
    }

    private static func ordering(_ a: AssessedThreat, _ b: AssessedThreat) -> Bool {
        if a.riskScore != b.riskScore { return a.riskScore > b.riskScore }
        if a.threatId != b.threatId { return a.threatId < b.threatId }
        return a.sourceComponentId < b.sourceComponentId
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests
```

Expected: 10 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: assess component threats and score their risk"
```

---

### Task 10: The acceptance test

This is the outer loop. It touches only use cases — no gateway, no Domain object.

**Files:**
- Create: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Create: `ThreatModelKit/Tests/AcceptanceTests/BuildingAThreatModelTests.swift`
- Delete: `ThreatModelKit/Tests/AcceptanceTests/Placeholder.swift`

**Interfaces:**
- Consumes: every use case from Tasks 6, 7 and 9; `CatalogueFixture`
- Produces: `TestDependencies()` exposing `listTechnologies()`, `addComponent()` and `assessThreatModel()`, each returning the use case protocol. Its gateways are private, so acceptance tests cannot reach them.

- [ ] **Step 1: Write the dependency factory**

Create `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
import ThreatModelKit

/// The composition root for tests. Mirrors the application's own `Dependencies`
/// but wires use cases to fakes. Gateways are deliberately private: an
/// acceptance test may only speak to the use case boundary.
public final class TestDependencies {
    private let catalogue: InMemoryTechnologyCatalogue
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(catalogue: InMemoryTechnologyCatalogue = CatalogueFixture.catalogue()) {
        self.catalogue = catalogue
        self.models = InMemoryThreatModelGateway()
        self.ids = SequentialIdentityGenerator()
    }

    public func listTechnologies() -> ListTechnologiesUseCase {
        ListTechnologies(catalogue: catalogue)
    }

    public func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    public func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
```

- [ ] **Step 2: Write the failing acceptance test**

Delete `ThreatModelKit/Tests/AcceptanceTests/Placeholder.swift` and create
`ThreatModelKit/Tests/AcceptanceTests/BuildingAThreatModelTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given a catalogue of technologies
/// When I add one to my threat model
/// Then its threats are raised against it, scored for the data it handles
struct BuildingAThreatModelTests {
    private let app = TestDependencies()

    @Test func offersTheCatalogueGroupedForBrowsing() throws {
        let palette = app.listTechnologies().execute(ListTechnologiesRequest())

        #expect(palette.providers.map(\.displayName) == [
            "Amazon Web Services",
            "Google Cloud Platform"
        ])

        let aws = try #require(palette.providers.first { $0.id == "aws" })
        #expect(aws.categories.map(\.label) == ["Compute", "Database"])
        #expect(aws.categories.first?.technologies.map(\.name) == ["EC2"])
    }

    @Test func raisesNoThreatsBeforeAnythingIsAdded() {
        #expect(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty)
    }

    @Test func raisesTheTechnologysThreatsOnceItIsOnTheModel() throws {
        let added = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 200, sensitivity: "confidential")
        )
        #expect(added == .added(componentId: "id-1"))

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessment.threats.map(\.threatId) == [
            "credential-theft",
            "misconfiguration",
            "dos-attack"
        ])
        #expect(assessment.threats.map(\.riskScore) == [12, 6, 3])
        #expect(assessment.threats.map(\.riskLevel) == ["critical", "medium", "low"])
        #expect(assessment.threats.allSatisfy { $0.sourceName == "EC2" })

        let worst = try #require(assessment.threats.first)
        #expect(worst.name == "Credential Theft")
        #expect(worst.severityLabel == "Critical")
        #expect(worst.stride == ["spoofing"])
        #expect(worst.mitreTechniques.map(\.id) == ["T1552"])
        #expect(worst.context == "Instance Metadata Service credential theft")
        #expect(worst.controls.map(\.description) == [
            "Enforce IMDSv2 to block SSRF-based credential theft",
            "Use IAM roles with minimal permissions"
        ])
    }

    @Test func scoresTheSameTechnologyDifferentlyForMoreSensitiveData() throws {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "public")
        )

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())
        let credentialTheft = try #require(assessment.threats.first { $0.threatId == "credential-theft" })

        #expect(credentialTheft.riskScore == 4)
        #expect(credentialTheft.riskLevel == "medium")
    }

    @Test func refusesATechnologyTheCatalogueDoesNotHave() {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-imaginary", x: 0, y: 0, sensitivity: "internal")
        )

        #expect(response == .unknownTechnology)
        #expect(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty)
    }
}
```

- [ ] **Step 3: Run the whole package suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test
```

Expected: every suite passes, including the 5 new acceptance tests. If `offersTheCatalogueGroupedForBrowsing` fails on category labels, check `CatalogueFixture.taxonomy()` still lists `compute` before `database` — the ordering is taxonomy order, not alphabetical.

- [ ] **Step 4: Check the suite is fast**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test
```

Expected: well under 30 seconds. If it is not, something is doing IO it should not.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "test: accept adding a technology and seeing its scored threats"
```

---

### Task 11: The delivery mechanism

**Files:**
- Create: `threatmodeller/Dependencies.swift`
- Create: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodeller/ContentView.swift`
- Modify: `threatmodeller/threatmodellerApp.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: `BundledTechnologyCatalogue`, every use case, `InMemoryThreatModelGateway`, `UUIDIdentityGenerator`
- Produces: `protocol UseCaseFactory`, `Dependencies()` (throwing), `ThreatModelSession(useCases: UseCaseFactory)` with `palette: [ListedProvider]`, `threats: [AssessedThreat]`, `errorMessage: String?`, and `add(technologyId: String)`

- [ ] **Step 1: Write the failing test**

Replace `threatmodellerTests/threatmodellerTests.swift`:

```swift
import Testing
import ThreatModelKit
@testable import threatmodeller

struct ThreatModelSessionTests {
    @Test func loadsTheWholeCataloguePaletteOnLaunch() throws {
        let session = ThreatModelSession(useCases: try Dependencies())

        #expect(session.palette.map(\.id) == ["aws", "azure", "gcp", "saas", "self-hosted"])
        #expect(session.threats.isEmpty)
    }

    @Test func raisesScoredThreatsWhenATechnologyIsAdded() throws {
        let session = ThreatModelSession(useCases: try Dependencies())

        session.add(technologyId: "aws-ec2")

        #expect(session.threats.count == 10)
        #expect(session.threats.first?.threatId == "credential-theft")
        #expect(session.threats.first?.riskScore == 8)
        #expect(session.threats.first?.riskLevel == "high")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsATechnologyThatIsNotInTheCatalogue() throws {
        let session = ThreatModelSession(useCases: try Dependencies())

        session.add(technologyId: "aws-imaginary")

        #expect(session.threats.isEmpty)
        #expect(session.errorMessage == "That technology is not in the catalogue.")
    }
}
```

The scores come from the real catalogue: EC2 added at the default `internal` sensitivity (rank 2), `credential-theft` at severity `critical` (rank 4), so 4 × 2 = 8, which is `high`.

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -20
```

Expected: FAIL — `cannot find 'ThreatModelSession' in scope`.

- [ ] **Step 3: Write the composition root**

Create `threatmodeller/Dependencies.swift`:

```swift
import CatalogueGateways
import ThreatModelKit

/// Everything the delivery mechanism is allowed to know about: use cases.
protocol UseCaseFactory {
    func listTechnologies() -> ListTechnologiesUseCase
    func addComponent() -> AddComponentUseCase
    func assessThreatModel() -> AssessThreatModelUseCase
}

/// The composition root. One graph per open model; from Milestone 6 that means
/// one per document window.
final class Dependencies: UseCaseFactory {
    private let catalogue: TechnologyCatalogue
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    init() throws {
        catalogue = try BundledTechnologyCatalogue()
        models = InMemoryThreatModelGateway()
        ids = UUIDIdentityGenerator()
    }

    func listTechnologies() -> ListTechnologiesUseCase {
        ListTechnologies(catalogue: catalogue)
    }

    func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
```

- [ ] **Step 4: Write the session**

Create `threatmodeller/ThreatModelSession.swift`:

```swift
import Observation
import ThreatModelKit

/// Translates user intent into use case calls and publishes the responses.
/// Holds no business rules and names no gateway.
@Observable
final class ThreatModelSession {
    private let useCases: UseCaseFactory

    private(set) var palette: [ListedProvider] = []
    private(set) var threats: [AssessedThreat] = []
    private(set) var errorMessage: String?

    init(useCases: UseCaseFactory) {
        self.useCases = useCases
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
    }

    func add(technologyId: String) {
        let response = useCases.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "internal")
        )

        switch response {
        case .added:
            errorMessage = nil
        case .unknownTechnology:
            errorMessage = "That technology is not in the catalogue."
        case .unknownSensitivity:
            errorMessage = "That data sensitivity is not recognised."
        }

        reassess()
    }

    private func reassess() {
        threats = useCases.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }
}
```

- [ ] **Step 5: Write the window**

Replace `threatmodeller/threatmodellerApp.swift`:

```swift
import SwiftUI

@main
struct ThreatModellerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .defaultSize(width: 1100, height: 700)
    }
}
```

Replace `threatmodeller/ContentView.swift`:

```swift
import SwiftUI
import ThreatModelKit

struct ContentView: View {
    @State private var session: ThreatModelSession?
    @State private var startupError: String?

    var body: some View {
        Group {
            if let session {
                ModelView(session: session)
            } else if let startupError {
                ContentUnavailableView(
                    "The catalogue could not be loaded",
                    systemImage: "exclamationmark.triangle",
                    description: Text(startupError)
                )
            } else {
                ProgressView()
            }
        }
        .task {
            guard session == nil, startupError == nil else { return }
            do {
                session = ThreatModelSession(useCases: try Dependencies())
            } catch {
                startupError = String(describing: error)
            }
        }
    }
}

private struct ModelView: View {
    let session: ThreatModelSession

    var body: some View {
        NavigationSplitView {
            PaletteView(session: session)
                .navigationSplitViewColumnWidth(min: 240, ideal: 280)
        } detail: {
            ThreatListView(session: session)
        }
    }
}

private struct PaletteView: View {
    let session: ThreatModelSession

    var body: some View {
        List {
            ForEach(session.palette, id: \.id) { provider in
                Section(provider.displayName) {
                    ForEach(provider.categories, id: \.id) { category in
                        DisclosureGroup(category.label) {
                            ForEach(category.technologies, id: \.id) { technology in
                                Button {
                                    session.add(technologyId: technology.id)
                                } label: {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(technology.name)
                                        Text(technology.description)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(2)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Technologies")
    }
}

private struct ThreatListView: View {
    let session: ThreatModelSession

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .padding()
            }

            if session.threats.isEmpty {
                ContentUnavailableView(
                    "No threats yet",
                    systemImage: "shield",
                    description: Text("Add a technology from the palette to see the threats it carries.")
                )
            } else {
                List(session.threats, id: \.self) { threat in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(threat.name).font(.headline)
                            Spacer()
                            Text("\(threat.riskLevel.capitalized) · \(threat.riskScore)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text(threat.sourceName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Text(threat.context ?? threat.description)
                            .font(.callout)
                        if threat.controls.isEmpty == false {
                            Text(threat.controls.map(\.description).joined(separator: " · "))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .navigationTitle("Threats")
    }
}
```

`List(session.threats, id: \.self)` relies on `AssessedThreat` already conforming
to `Hashable`, which Task 9 declared. No change to the package is needed here.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -20
```

Expected: the three `ThreatModelSessionTests` pass and the run ends with `TEST SUCCEEDED`.

- [ ] **Step 7: Run the app and look at it**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -derivedDataPath .build/xcode build
open .build/xcode/Build/Products/Debug/threatmodeller.app
```

Confirm by eye: five provider sections in the sidebar; expanding a category lists technologies; clicking EC2 fills the detail pane with ten threats, worst first, each showing a risk level and score.

- [ ] **Step 8: Run the full suite once more**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test
scripts/update-catalogue.sh verify
```

Expected: all package tests pass; `All 8 vendored files match the lock file`.

- [ ] **Step 9: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add -A
git commit -m "feat: show the catalogue palette and the threats it raises"
```

---

## Milestone complete

At this point:

- `swift test` from `ThreatModelKit/` runs acceptance, unit, contract and integration suites in under 30 seconds
- the fake and real catalogue gateways are held to one contract
- the app lists 277 real technologies and scores the threats of anything added
- no business rule lives in a `View`, and no Domain object crosses a use case boundary

Milestone 2 (the canvas) gets its own plan.
