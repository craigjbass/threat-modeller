import Testing
import ThreatModelKit
import TestSupport

/// The fingerprint is what tells the application that a file under the project
/// changed since it last read one.
struct ReadProjectFingerprintTests {
    private let payments = """
    system "Payments" {
      component "api" { technology = "aws-ec2" }
    }
    """

    private func aProject() -> InMemoryProject {
        let project = InMemoryProject(root: "/work")
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put("system \"Reporting\" { component \"r\" { technology = \"aws-rds\" } }",
                    at: "/work/threatmodel/reporting.arch")
        return project
    }

    private func read(_ project: InMemoryProject) -> ReadProjectFingerprintResponse {
        ReadProjectFingerprint(projects: project).execute(
            ReadProjectFingerprintRequest(root: "/work")
        )
    }

    @Test func namesEveryArchitectureFile() {
        guard case .read(let fingerprint) = read(aProject()) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint.keys.sorted() == [
            "/work/threatmodel/payments.arch",
            "/work/threatmodel/reporting.arch"
        ])
    }

    @Test func namesAControlsFileThatExists() {
        let project = aProject()
        project.put("system \"Payments\" {}", at: "/work/threatmodel/payments.controls")

        guard case .read(let fingerprint) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint["/work/threatmodel/payments.controls"] != nil)
    }

    @Test func answersTheSameFingerprintForTheSameText() {
        let project = aProject()

        guard case .read(let first) = read(project), case .read(let second) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(first == second)
    }

    @Test func answersADifferentFingerprintForChangedText() {
        let project = aProject()
        guard case .read(let before) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        project.put(payments + "\n// changed\n", at: "/work/threatmodel/payments.arch")

        guard case .read(let after) = read(project) else {
            Issue.record("the project was not read")
            return
        }
        #expect(before != after)
    }

    @Test func refusesARootThatIsNotAProject() {
        let response = ReadProjectFingerprint(projects: InMemoryProject(root: "/work")).execute(
            ReadProjectFingerprintRequest(root: "/elsewhere")
        )

        #expect(response == .notAProject(reason: "/elsewhere is not a directory"))
    }

    // MARK: a split system's part files

    private func aSplitProject() -> InMemoryProject {
        let project = InMemoryProject(root: "/work")
        project.put(
            "system \"Payments\" { }",
            at: "/work/threatmodel/payments/arch/payments.arch"
        )
        project.put(
            "component \"api\" { technology = \"aws-ec2\" }",
            at: "/work/threatmodel/payments/arch/edge.arch"
        )
        return project
    }

    @Test func namesEveryArchitecturePartFile() {
        guard case .read(let fingerprint) = read(aSplitProject()) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint.keys.sorted() == [
            "/work/threatmodel/payments/arch/edge.arch",
            "/work/threatmodel/payments/arch/payments.arch"
        ])
    }

    @Test func namesAControlsPartFile() {
        let project = aSplitProject()
        project.put("", at: "/work/threatmodel/payments/controls/edge.controls")

        guard case .read(let fingerprint) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint["/work/threatmodel/payments/controls/edge.controls"] != nil)
    }

    @Test func namesAnAttackTreePartFile() {
        let project = aSplitProject()
        project.put("", at: "/work/threatmodel/payments/attacktree/edge.attacktree")

        guard case .read(let fingerprint) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint["/work/threatmodel/payments/attacktree/edge.attacktree"] != nil)
    }

    @Test func answersADifferentFingerprintForAChangedPartFile() {
        let project = aSplitProject()
        guard case .read(let before) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        project.put(
            "component \"api\" { technology = \"aws-ec2\" }\n// changed\n",
            at: "/work/threatmodel/payments/arch/edge.arch"
        )

        guard case .read(let after) = read(project) else {
            Issue.record("the project was not read")
            return
        }
        #expect(before != after)
    }

    @Test func answersTheSameFingerprintForAnUnchangedSplitSystem() {
        let project = aSplitProject()

        guard case .read(let first) = read(project), case .read(let second) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(first == second)
    }

    // MARK: a shared library

    private func aProjectWithALibrary() -> InMemoryProject {
        let project = aProject()
        project.put(
            "library \"acme\" { name = \"Acme Platform\" }",
            at: "/work/threatmodel/library/acme.lib"
        )
        return project
    }

    @Test func namesEveryLibraryFile() {
        guard case .read(let fingerprint) = read(aProjectWithALibrary()) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint["/work/threatmodel/library/acme.lib"] != nil)
    }

    @Test func answersADifferentFingerprintForAChangedLibraryFile() {
        let project = aProjectWithALibrary()
        guard case .read(let before) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        project.put(
            "library \"acme\" { name = \"Acme Platform\"\n// changed\n }",
            at: "/work/threatmodel/library/acme.lib"
        )

        guard case .read(let after) = read(project) else {
            Issue.record("the project was not read")
            return
        }
        #expect(before != after)
    }

    @Test func answersTheSameFingerprintForAnUnchangedProjectWithALibrary() {
        let project = aProjectWithALibrary()

        guard case .read(let first) = read(project), case .read(let second) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(first == second)
    }
}
