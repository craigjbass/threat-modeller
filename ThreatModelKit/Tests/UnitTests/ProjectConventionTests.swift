import Testing
import TestSupport
import ThreatModelKit

@Suite("The rule that pairs a file with its project")
struct ProjectConventionTests {
    // MARK: naming a file for a system

    @Test func lowercasesANameAndJoinsItsWordsWithOneHyphen() {
        #expect(ProjectConvention.stem(forSystemNamed: "Payments") == "payments")
        #expect(ProjectConvention.stem(forSystemNamed: "Card Payments") == "card-payments")
        #expect(ProjectConvention.stem(forSystemNamed: "  Card   Payments  ") == "card-payments")
    }

    @Test func dropsEverythingThatIsNotALetterOrADigit() {
        #expect(ProjectConvention.stem(forSystemNamed: "Acme's Payments (v2)") == "acme-s-payments-v2")
        #expect(ProjectConvention.stem(forSystemNamed: "!!!") == "")
    }

    @Test func statesTheConventionDirectoryNameForEveryGateway() {
        #expect(InMemoryProject.conventionDirectory == ProjectConvention.conventionDirectoryName)
    }

    // MARK: opening a file the user double-clicked

    /// A system's files live in the convention directory, so the project is
    /// the directory above that one.
    @Test func findsTheProjectAboveTheConventionDirectory() {
        let found = ProjectConvention.system(atPath: "/work/threatmodel/payments.arch")

        #expect(found?.root == "/work")
        #expect(found?.systemName == "payments")
    }

    @Test func findsTheProjectFromAControlsFileTheSameWay() {
        let found = ProjectConvention.system(atPath: "/work/threatmodel/payments.controls")

        #expect(found?.root == "/work")
        #expect(found?.systemName == "payments")
    }

    /// A project that keeps its files in the root itself, which `discover`
    /// already allows.
    @Test func findsTheProjectAroundAFileThatSitsInTheRoot() {
        let found = ProjectConvention.system(atPath: "/work/payments.arch")

        #expect(found?.root == "/work")
        #expect(found?.systemName == "payments")
    }

    @Test func findsNoProjectForAFileThisApplicationDoesNotRead() {
        #expect(ProjectConvention.system(atPath: "/work/threatmodel/payments.md") == nil)
        #expect(ProjectConvention.system(atPath: "/work/notes.txt") == nil)
        #expect(ProjectConvention.system(atPath: "payments.arch") == nil)
    }

    // MARK: attack trees

    @Test func pairsAnAttackTreeFileWithItsArchitectureFile() throws {
        let systems = ProjectConvention.systems(
            in: "/p/threatmodel",
            fileNames: ["payments.arch", "payments.controls", "payments.attacktree"]
        )

        let system = try #require(systems.first)
        #expect(system.attackTreePath == "/p/threatmodel/payments.attacktree")
    }

    @Test func namesAnAttackTreePathForASystemThatHasNoSuchFile() throws {
        let systems = ProjectConvention.systems(in: "/p", fileNames: ["payments.arch"])

        let system = try #require(systems.first)
        #expect(system.attackTreePath == "/p/payments.attacktree")
    }

    @Test func opensAProjectFromAnAttackTreeFile() throws {
        let found = try #require(
            ProjectConvention.system(atPath: "/p/threatmodel/payments.attacktree")
        )

        #expect(found.root == "/p")
        #expect(found.systemName == "payments")
    }
}
