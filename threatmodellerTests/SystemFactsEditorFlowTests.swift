import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Reading and writing a system's document-control attributes in the window,
/// end to end: what the assumptions panel shows, what the save writes into the
/// `.arch` file, what `check` then says about the policy rule, and what the
/// report then says about the review date.
@MainActor
@Suite("A system's document-control facts in the window")
struct SystemFactsEditorFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let described = """
    system "Payments" {
      description  = "Takes the card payments."
      owner        = "Payments team"
      authors      = ["Ada Lovelace", "Alan Turing"]
      version      = "1.2"
      created      = "2026-01-04"
      reviewed     = "2026-03-01"
      links        = ["https://wiki.example/payments"]
      repositories = ["https://github.example/payments"]

      attribute "service_tier" {
        value = "gold"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let requiresOwner = """
    policy {
      system_requires_owner = true
    }
    """

    private func aProject(
        _ text: String? = nil,
        policy: String? = nil
    ) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? payments, at: "/work/threatmodel/payments.arch")
        if let policy { useCases.project.put(policy, at: "/work/threatmodel/policy.hcl") }
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func architecture(_ useCases: TestDependencies) -> String? {
        useCases.project.text(at: "/work/threatmodel/payments.arch")
    }

    // MARK: what the panel shows

    @Test func showsEveryFactTheFileStates() async throws {
        let (session, _) = await aProject(described)
        let model = try #require(session.model)

        let facts = model.canvas.systemFacts
        #expect(facts.owner == "Payments team")
        #expect(facts.description == "Takes the card payments.")
        #expect(facts.authors == ["Ada Lovelace", "Alan Turing"])
        #expect(facts.version == "1.2")
        #expect(facts.created == "2026-01-04")
        #expect(facts.reviewed == "2026-03-01")
        #expect(facts.links == ["https://wiki.example/payments"])
        #expect(facts.repositories == ["https://github.example/payments"])
        let attribute = try #require(facts.attributes.first)
        #expect(attribute.name == "service_tier")
        #expect(attribute.value == "gold")
    }

    // MARK: writing each attribute

    @Test func writesEveryAttributeIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemFacts(
            owner: "Payments team",
            description: "Takes the card payments.",
            authors: ["Ada Lovelace", "Alan Turing"],
            version: "1.2",
            created: "2026-01-04",
            reviewed: "2026-03-01",
            links: ["https://wiki.example/payments"],
            repositories: ["https://github.example/payments"]
        )
        model.setSystemAttribute(name: "service_tier", value: "gold")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(written).source)
        #expect(source.owner == "Payments team")
        #expect(source.description == "Takes the card payments.")
        #expect(source.authors == ["Ada Lovelace", "Alan Turing"])
        #expect(source.version == "1.2")
        #expect(source.created == "2026-01-04")
        #expect(source.reviewed == "2026-03-01")
        #expect(source.links == ["https://wiki.example/payments"])
        #expect(source.repositories == ["https://github.example/payments"])
        #expect(source.attributes.map(\.name) == ["service_tier"])
        #expect(source.attributes.map(\.value) == ["gold"])
    }

    @Test func writesTheFactsAndLeavesEveryOtherBlockWhereItWas() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        // A save with nothing changed, so the two texts differ by the
        // document-control lines alone and by nothing the writer normalises.
        await session.save()
        let before = try #require(architecture(useCases))

        model.setSystemFacts(owner: "Payments team", version: "1.2")
        model.setSystemAttribute(name: "service_tier", value: "gold")
        await session.save()
        let after = try #require(architecture(useCases))

        #expect(model.errorMessage == nil)
        #expect(after != before)
        #expect(
            Self.holdsEveryLine(of: before, inOrder: after),
            "the write moved or dropped a line the file already held"
        )

        model.setSystemFacts(owner: "", version: "")
        model.removeSystemAttribute(name: "service_tier")
        await session.save()

        #expect(architecture(useCases) == before)
    }

    /// True when every line of `before` is in `after`, in the same order. New
    /// lines are added; the lines around them must not change.
    private static func holdsEveryLine(of before: String, inOrder after: String) -> Bool {
        var wanted = before.split(separator: "\n", omittingEmptySubsequences: true)[...]
        for line in after.split(separator: "\n", omittingEmptySubsequences: true) {
            if wanted.first == line { wanted = wanted.dropFirst() }
        }
        return wanted.isEmpty
    }

    @Test func changesOneAttributeAndLeavesTheOthers() async throws {
        let (session, useCases) = await aProject(described)
        let model = try #require(session.model)

        model.setSystemFacts(version: "1.3")
        await session.save()

        let written = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(written).source)
        #expect(source.version == "1.3")
        #expect(source.owner == "Payments team")
        #expect(source.created == "2026-01-04")
        #expect(source.attributes.map(\.name) == ["service_tier"])
    }

    @Test func takesAnAttributeBlockOffTheFile() async throws {
        let (session, useCases) = await aProject(described)
        let model = try #require(session.model)

        model.removeSystemAttribute(name: "service_tier")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("attribute \"service_tier\"") == false)
    }

    // MARK: the policy rule

    @Test func thePolicyRuleForAnOwnerPassesOnceTheWindowWritesOne() async throws {
        let (session, _) = await aProject(policy: requiresOwner)
        let model = try #require(session.model)

        let before = session.checkedSystems.flatMap(\.findings)
        #expect(
            before.contains { $0.said.contains("system_requires_owner: this system states no owner") }
        )

        model.setSystemFacts(owner: "Payments team")
        await session.save()

        let after = session.checkedSystems.flatMap(\.findings)
        #expect(model.errorMessage == nil)
        #expect(after.contains { $0.said.contains("system_requires_owner") } == false)
    }

    // MARK: the review date

    @Test func theReportStopsFlaggingTheReviewDateOnceTheWindowWritesToday() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let today = CheckGovernance.today(useCases.time.now())
        let longAgo = GovernanceDate(year: today.year - 2, month: today.month, day: today.day)

        model.setSystemFacts(reviewed: try #require(longAgo).description)
        await session.save()
        #expect(Self.report(useCases).executiveSummary.isReviewOverdue)

        model.setSystemFacts(reviewed: today.description)
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(Self.report(useCases).executiveSummary.isReviewOverdue == false)
        #expect(Self.report(useCases).executiveSummary.reviewedOn == today.description)
    }

    private static func report(_ useCases: TestDependencies) -> Report {
        useCases.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
    }

    // MARK: a date field refuses a text that is not a date

    @Test func refusesADateThatIsNotADateAndWritesNothing() async throws {
        let (session, useCases) = await aProject(described)
        let model = try #require(session.model)

        model.setSystemFacts(reviewed: "last Tuesday")

        #expect(model.errorMessage == "The reviewed date is written YYYY-MM-DD.")
        #expect(model.canvas.systemFacts.reviewed == "2026-03-01")

        await session.save()
        let written = try #require(architecture(useCases))
        #expect(written.contains("last Tuesday") == false)
    }

    /// The picker states a day, and the field turns that day into the text the
    /// file holds. No text a person types reaches the model.
    @Test func theDateFieldWritesTheDayThePickerStates() throws {
        var parts = DateComponents()
        parts.year = 2026
        parts.month = 9
        parts.day = 16
        parts.hour = 12
        let picked = try #require(Calendar.current.date(from: parts))

        #expect(SystemDateField.text(of: picked) == "2026-09-16")
        #expect(SystemDateField.day(of: "2026-09-16") == picked)
        #expect(SystemDateField.day(of: "last Tuesday") == nil)
    }

    private func calendar(timeZone identifier: String) throws -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try #require(TimeZone(identifier: identifier))
        return calendar
    }

    /// A Date late in the evening at Greenwich already falls on the next day
    /// for a person east of Greenwich. `text(of:)` answers the day of the
    /// calendar it is given, not the day UTC would answer.
    @Test func textOfAnswersTheNextLocalDayEastOfGreenwich() throws {
        let auckland = try calendar(timeZone: "Pacific/Auckland")
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = try #require(TimeZone(identifier: "UTC"))

        var lateEveningAtGreenwich = DateComponents()
        lateEveningAtGreenwich.year = 2026
        lateEveningAtGreenwich.month = 9
        lateEveningAtGreenwich.day = 16
        lateEveningAtGreenwich.hour = 23
        let instant = try #require(utc.date(from: lateEveningAtGreenwich))

        #expect(SystemDateField.text(of: instant, calendar: auckland) == "2026-09-17")
    }

    /// A Date early in the morning at Greenwich still falls on the day before
    /// for a person west of Greenwich. `text(of:)` answers the day of the
    /// calendar it is given, not the day UTC would answer.
    @Test func textOfAnswersThePreviousLocalDayWestOfGreenwich() throws {
        let losAngeles = try calendar(timeZone: "America/Los_Angeles")
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = try #require(TimeZone(identifier: "UTC"))

        var earlyMorningAtGreenwich = DateComponents()
        earlyMorningAtGreenwich.year = 2026
        earlyMorningAtGreenwich.month = 9
        earlyMorningAtGreenwich.day = 16
        earlyMorningAtGreenwich.hour = 2
        let instant = try #require(utc.date(from: earlyMorningAtGreenwich))

        #expect(SystemDateField.text(of: instant, calendar: losAngeles) == "2026-09-15")
    }

    /// `day(of:)` round-trips through `text(of:)` in a named calendar, east
    /// and west of Greenwich, and answers the exact midday instant so a wider
    /// time zone never moves the day.
    @Test func dayOfRoundTripsThroughTextOfEastAndWestOfGreenwich() throws {
        for (timeZone, written) in [("Pacific/Auckland", "2026-09-17"), ("America/Los_Angeles", "2026-09-15")] {
            let zoned = try calendar(timeZone: timeZone)

            var midday = DateComponents()
            midday.year = 2026
            midday.month = 9
            midday.day = timeZone == "Pacific/Auckland" ? 17 : 15
            midday.hour = 12
            let expected = try #require(zoned.date(from: midday))

            #expect(SystemDateField.day(of: written, calendar: zoned) == expected)
            let roundTripped = try #require(SystemDateField.day(of: written, calendar: zoned))
            #expect(SystemDateField.text(of: roundTripped, calendar: zoned) == written)
        }
    }

    @Test func theCreatedSwitchOffLeavesNoCreatedLine() async throws {
        let (session, useCases) = await aProject(described)
        let model = try #require(session.model)

        model.setSystemFacts(created: "")

        await session.save()
        let written = try #require(architecture(useCases))
        #expect(written.contains("created") == false)
    }

    // MARK: the sheet

    /// #145: the document-control fields and the free attributes left the
    /// architecture sidebar for the Document Control sheet the System menu
    /// opens, so the drawing test draws the sheet.
    @Test func theDocumentControlSheetDraws() async throws {
        let (session, _) = await aProject(described)
        let model = try #require(session.model)

        let renderer = ImageRenderer(
            content: DocumentControlSheet(session: model, dismiss: {}).frame(width: 760, height: 520)
        )
        renderer.scale = 1

        #expect(renderer.cgImage != nil)
    }

    @Test func theListFieldsReadAndWriteOneLine() {
        #expect(SystemSheetWriting.joined(["Ada Lovelace", "Alan Turing"]) == "Ada Lovelace, Alan Turing")
        #expect(SystemSheetWriting.split(" Ada Lovelace , , Alan Turing ") == ["Ada Lovelace", "Alan Turing"])
    }
}
