//
//  threatmodellerUITests.swift
//  threatmodellerUITests
//
//  Created by Craig J. Bass on 07/09/2026.
//

import Foundation
import XCTest

final class threatmodellerUITests: XCTestCase {

    override func setUpWithError() throws {
        // In UI tests it is usually best to stop immediately when a failure occurs.
        continueAfterFailure = false
    }

    /// Guards against the defect the user found: clicking a category row did
    /// nothing unless the click landed on the 15-point disclosure triangle,
    /// and the category label looked interactive but was not.
    ///
    /// Walks the journey a user takes: open a category, add a technology,
    /// see its threats.
    ///
    /// Each step asserts the OUTCOME of a click, not the mechanics of the
    /// control. If a row is dead, the next thing never appears and the test
    /// fails. That covers the defect where a category label rendered as plain
    /// text and only a 15 point disclosure triangle responded.
    @MainActor
    func testAUserOpensACategoryAddsATechnologyAndSeesItsThreats() throws {
        let started = Date()
        func mark(_ step: String) {
            print(String(format: "[uitest] %5.1fs  %@", Date().timeIntervalSince(started), step))
        }

        let app = XCUIApplication()
        mark("launching")
        app.launch()

        // A document-based application offers to open a file on launch rather
        // than showing a window. The journey needs a new, empty document.
        mark("making a new document")
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared after asking for a new document."
        )

        // Every query below is scoped to one window. A previous suite in the
        // same run can leave another document open, and an unscoped query then
        // matches the same control twice.
        let window = app.windows.firstMatch

        // The palette lists the catalogue, grouped by provider then category.
        // Each row carries a stable accessibility identifier built from its
        // provider id, category id, and technology id, so the query does not
        // depend on tree order or on the row's visible label text.
        let category = window.buttons["category-aws-compute"]
        XCTAssertTrue(
            category.waitForExistence(timeout: 15),
            "The 'category-aws-compute' category never appeared in the palette."
        )
        XCTAssertTrue(
            window.staticTexts["No threats yet"].exists,
            "Expected the empty threat list before a technology is added."
        )

        // Open the category by clicking the row, not the disclosure triangle.
        mark("clicking the 'Compute' category")
        category.click()

        // If the category row were dead, this row would never appear.
        // The row is a drag source, not a button, so it is not in
        // `app.buttons`. Query by identifier across every element kind.
        let technology = window.descendants(matching: .any)["technology-aws-ec2"].firstMatch
        XCTAssertTrue(
            technology.waitForExistence(timeout: 5),
            "Clicking the 'Compute' category did not open it; the EC2 row never appeared."
        )

        // Add the technology. A single click only selects the row; a
        // double-click places it on the canvas.
        mark("double-clicking the EC2 row")
        technology.doubleClick()

        // If the row were dead, no node would appear on the canvas.
        XCTAssertTrue(
            window.descendants(matching: .any)["node-aws-ec2"].firstMatch.waitForExistence(timeout: 10),
            "Double-clicking the EC2 row did not put a node on the canvas."
        )

        // If the technology row were dead, these threats would never appear.
        XCTAssertTrue(
            window.staticTexts["Credential Theft"].firstMatch.waitForExistence(timeout: 10),
            "Clicking the EC2 row did not raise its threats."
        )
        XCTAssertFalse(
            window.staticTexts["No threats yet"].exists,
            "The empty threat list is still showing after a technology was added."
        )
        mark("threats shown")

        // Draw a zone around the node, and read the threat the zone raises.
        mark("turning on the zone drawing mode")
        let drawZone = window.descendants(matching: .any)["draw-zone"].firstMatch
        XCTAssertTrue(
            drawZone.waitForExistence(timeout: 5),
            "The 'Draw zone' control never appeared in the canvas toolbar."
        )
        drawZone.click()

        mark("dragging a zone across the canvas")
        let canvas = window.descendants(matching: .any)["canvas"].firstMatch
        XCTAssertTrue(canvas.exists, "The canvas background was not found.")
        canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.05, dy: 0.05))
            .press(
                forDuration: 0.2,
                thenDragTo: canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.85))
            )

        // The zone captures the node, so the zone's own threats appear.
        XCTAssertTrue(
            window.staticTexts["Lateral Movement"].firstMatch.waitForExistence(timeout: 10),
            "Drawing a zone did not raise the zone's own threats."
        )
        mark("zone threats shown")


        // Tick a control on a card and see the summary follow.
        mark("ticking a control")
        let summaryStrip = window.descendants(matching: .any)["risk-summary"].firstMatch
        XCTAssertTrue(
            summaryStrip.waitForExistence(timeout: 5),
            "The risk summary never appeared above the threat cards."
        )

        let firstCheckbox = window.checkBoxes.firstMatch
        XCTAssertTrue(
            firstCheckbox.waitForExistence(timeout: 5),
            "No control checkbox appeared on any threat card."
        )
        XCTAssertEqual(firstCheckbox.value as? Int, 0, "The control started ticked.")
        firstCheckbox.click()

        let recorded = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == 1"),
            object: firstCheckbox
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [recorded], timeout: 10),
            .completed,
            "Clicking the control did not record it."
        )
        mark("control recorded")

        // Open the pathway mitigations and switch them on.
        mark("opening the pathway mitigations")
        let pathwayHeader = window.descendants(matching: .any)["pathway-mitigations"].firstMatch
        XCTAssertTrue(
            pathwayHeader.waitForExistence(timeout: 5),
            "The pathway mitigations control never appeared in the sidebar."
        )
        pathwayHeader.click()

        let master = window.descendants(matching: .any)["pathway-master"].firstMatch
        XCTAssertTrue(
            master.waitForExistence(timeout: 5),
            "Opening the pathway mitigations did not reveal the master switch."
        )
        XCTAssertEqual(master.value as? Int, 0, "Pathway mitigations started on.")
        master.click()

        let switchedOn = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == 1"),
            object: master
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [switchedOn], timeout: 10),
            .completed,
            "Clicking the master switch did not turn the pathway mitigations on."
        )
        mark("pathway mitigations on")
    }

    /// The external actors are app-owned data, not part of the vendored
    /// catalogue. A user starts a diagram with the person using the system.
    @MainActor
    func testAUserPlacesAnExternalActor() throws {
        let app = XCUIApplication()
        app.launch()
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared after asking for a new document."
        )
        let window = app.windows.firstMatch

        let category = window.buttons["category-actor-person"]
        XCTAssertTrue(
            category.waitForExistence(timeout: 15),
            "The 'category-actor-person' category never appeared in the palette."
        )
        category.click()

        let actor = window.descendants(matching: .any)["technology-actor-user"].firstMatch
        XCTAssertTrue(
            actor.waitForExistence(timeout: 5),
            "Opening the 'People' category did not show the user actor."
        )
        actor.doubleClick()

        XCTAssertTrue(
            window.descendants(matching: .any)["node-actor-user"].firstMatch
                .waitForExistence(timeout: 10),
            "Double-clicking the user actor did not put a node on the canvas."
        )
    }

    /// A user whose service no library holds names it themselves, then places
    /// it like any other technology.
    @MainActor
    func testAUserDefinesTheirOwnTechnologyAndPlacesIt() throws {
        let app = XCUIApplication()
        app.launch()
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared after asking for a new document."
        )
        let window = app.windows.firstMatch

        let newTechnology = window.descendants(matching: .any)["new-technology"].firstMatch
        XCTAssertTrue(
            newTechnology.waitForExistence(timeout: 15),
            "The 'New Technology' button never appeared under the palette."
        )
        newTechnology.click()

        let nameField = app.descendants(matching: .any)["technology-name"].firstMatch
        XCTAssertTrue(
            nameField.waitForExistence(timeout: 10),
            "Clicking 'New Technology' did not open the editor."
        )
        nameField.click()
        nameField.typeText("Our Ledger")

        let save = app.descendants(matching: .any)["technology-save"].firstMatch
        XCTAssertTrue(save.exists, "The editor has no save button.")
        save.click()

        // Opening the editor leaves a second window in the tree, so every
        // query after it closes reads the application rather than one window.
        //
        // The palette groups the model's own technologies under their own
        // provider, and the group starts closed like every other category.
        // The identifier carries the category the user chose.
        let ourCategory = app.buttons
            .matching(NSPredicate(format: "identifier BEGINSWITH 'category-custom-'"))
            .firstMatch
        XCTAssertTrue(
            ourCategory.waitForExistence(timeout: 10),
            "Saving the technology did not add the model's own palette group."
        )
        ourCategory.click()

        let ourRow = app.staticTexts["Our Ledger"].firstMatch
        XCTAssertTrue(
            ourRow.waitForExistence(timeout: 10),
            "The technology the user defined never appeared in the palette."
        )
        ourRow.doubleClick()

        // The identifier carries the generated technology id, so the query
        // matches on its prefix.
        let node = app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH 'node-custom-'"))
            .firstMatch
        XCTAssertTrue(
            node.waitForExistence(timeout: 10),
            "Double-clicking the user's own technology did not put a node on the canvas."
        )
    }

    /// The four exports are offered from the File menu, and each one is
    /// enabled while a document is in front.
    @MainActor
    func testAUserFindsTheFourExportsInTheFileMenu() throws {
        let app = XCUIApplication()
        app.launch()
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared after asking for a new document."
        )

        let file = app.menuBars.menuBarItems["File"]
        XCTAssertTrue(file.waitForExistence(timeout: 10), "There is no File menu.")
        file.click()

        for title in [
            "Export as Markdown\u{2026}",
            "Export as threatcl\u{2026}",
            "Export as PDF\u{2026}",
            "Export as Image\u{2026}"
        ] {
            let item = app.menuItems[title]
            XCTAssertTrue(
                item.waitForExistence(timeout: 5),
                "The File menu has no '\(title)' item."
            )
            XCTAssertTrue(item.isEnabled, "'\(title)' is disabled with a document in front.")
        }

        // Leave the menu closed, so the next test starts on a clean window.
        app.typeKey(.escape, modifierFlags: [])
    }

    /// A user starts from an example and reads its nodes.
    @MainActor
    func testAUserOpensAnExample() throws {
        let app = XCUIApplication()
        app.launch()
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared after asking for a new document."
        )

        app.typeKey("o", modifierFlags: [.command, .shift])

        let sample = app.descendants(matching: .any)["sample-public-web"].firstMatch
        XCTAssertTrue(
            sample.waitForExistence(timeout: 10),
            "The samples browser did not list the public web example."
        )
        // A double-click opens the example, the way a double-click on a
        // palette row places a technology.
        sample.doubleClick()

        XCTAssertTrue(
            app.descendants(matching: .any)["node-aws-rds"].firstMatch
                .waitForExistence(timeout: 15),
            "Opening the example did not put its nodes on the canvas."
        )
        XCTAssertTrue(
            app.descendants(matching: .any)["zone-z1"].firstMatch.exists,
            "Opening the example did not draw its zones."
        )
        XCTAssertTrue(
            app.staticTexts["Lateral Movement"].firstMatch.waitForExistence(timeout: 10),
            "Opening the example did not raise the threats its zones carry."
        )
    }

    /// Selecting one node opens the node panel, where a user says what the
    /// node holds.
    @MainActor
    func testAUserSelectsANodeAndReadsItsPanel() throws {
        let app = XCUIApplication()
        app.launch()
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared after asking for a new document."
        )
        let window = app.windows.firstMatch

        let category = window.buttons["category-aws-compute"]
        XCTAssertTrue(category.waitForExistence(timeout: 15), "The palette never appeared.")
        category.click()

        let technology = window.descendants(matching: .any)["technology-aws-ec2"].firstMatch
        XCTAssertTrue(technology.waitForExistence(timeout: 5), "The EC2 row never appeared.")
        technology.doubleClick()

        let node = window.descendants(matching: .any)["node-aws-ec2"].firstMatch
        XCTAssertTrue(node.waitForExistence(timeout: 10), "No node appeared on the canvas.")
        node.click()

        let sensitivity = window.descendants(matching: .any)["component-sensitivity"].firstMatch
        XCTAssertTrue(
            sensitivity.waitForExistence(timeout: 10),
            "Selecting a node did not open the node panel."
        )
        XCTAssertTrue(
            window.descendants(matching: .any)["component-name"].firstMatch.exists,
            "The node panel has no name field."
        )

        let threatsRaised = window.descendants(matching: .any)["component-threats-raised"]
            .firstMatch
        XCTAssertTrue(threatsRaised.exists, "The node panel has no threats switch.")
        XCTAssertEqual(threatsRaised.value as? Int, 1, "The node started with its threats off.")
    }

    /// A project directory a team commits, opened in the application.
    ///
    /// The application takes `-project <path>` because an open panel cannot be
    /// driven from an interface test.
    @MainActor
    func testAUserOpensAProjectDirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-journey-\(UUID().uuidString)")
        let directory = root.appendingPathComponent("threatmodel")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        try """
        system "Payments" {
          zone "app" {
            kind    = "private"
            network = "vpc"

            component "api" {
              technology = "aws-ec2"
              name       = "Application Server"
              data       = "confidential"
            }

            component "db" {
              technology = "aws-rds"
              data       = "restricted"
            }
          }

          flow api -> db
        }

        """.write(
            to: directory.appendingPathComponent("payments.arch"),
            atomically: true,
            encoding: .utf8
        )

        let app = XCUIApplication()
        app.launchArguments = ["-project", root.path]
        app.launch()

        // The project window is a scene of its own, opened from the File menu.
        let file = app.menuBars.menuBarItems["File"]
        XCTAssertTrue(file.waitForExistence(timeout: 15), "There is no File menu.")
        file.click()
        let openProject = app.menuItems["Open Project\u{2026}"]
        XCTAssertTrue(
            openProject.waitForExistence(timeout: 5),
            "The File menu has no 'Open Project' item."
        )
        app.typeKey(.escape, modifierFlags: [])

        // The window the launch argument filled is already open behind the
        // document window, so the picker names the system the file describes.
        let picker = app.descendants(matching: .any)["system-picker"].firstMatch
        if picker.waitForExistence(timeout: 5) == false {
            // The project scene opens on demand; ask for it by its keyboard
            // shortcut and cancel the panel the command shows.
            app.typeKey("o", modifierFlags: [.command, .option])
            app.typeKey(.escape, modifierFlags: [])
        }
        XCTAssertTrue(
            picker.waitForExistence(timeout: 15),
            "The project window never showed its systems picker."
        )

        XCTAssertTrue(
            app.descendants(matching: .any)["node-aws-ec2"].firstMatch
                .waitForExistence(timeout: 15),
            "The project window did not draw the components the file describes."
        )
        XCTAssertTrue(
            app.descendants(matching: .any)["node-aws-rds"].firstMatch.exists,
            "The project window drew one component and not the other."
        )
        XCTAssertTrue(
            app.staticTexts["Credential Theft"].firstMatch.waitForExistence(timeout: 10),
            "The project window did not raise the threats the file's components carry."
        )
    }

    /// A project whose answers are committed beside its architecture. The
    /// sidebar shows what the file says.
    @MainActor
    func testAUserOpensAProjectWithItsAnswers() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-answers-\(UUID().uuidString)")
        let directory = root.appendingPathComponent("threatmodel")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        try """
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            name       = "Application Server"
            data       = "confidential"
          }
        }

        """.write(
            to: directory.appendingPathComponent("payments.arch"),
            atomically: true,
            encoding: .utf8
        )

        try """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            control "Use IAM roles with minimal permissions instead of long-lived access keys" {
              status = "implemented"
            }

            compensating "Watched by the SIEM" {
              reduces_risk_by = 50
              rationale       = "The one account left alerts on use."
            }
          }
        }

        """.write(
            to: directory.appendingPathComponent("payments.controls"),
            atomically: true,
            encoding: .utf8
        )

        let app = XCUIApplication()
        app.launchArguments = ["-project", root.path]
        app.launch()

        let picker = app.descendants(matching: .any)["system-picker"].firstMatch
        if picker.waitForExistence(timeout: 5) == false {
            app.typeKey("o", modifierFlags: [.command, .option])
            app.typeKey(.escape, modifierFlags: [])
        }
        XCTAssertTrue(
            picker.waitForExistence(timeout: 15),
            "The project window never showed its systems picker."
        )

        XCTAssertTrue(
            app.descendants(matching: .any)["node-aws-ec2"].firstMatch
                .waitForExistence(timeout: 15),
            "The project window did not draw the component the file describes."
        )

        // The summary counts the control the committed file records. The
        // threat cards themselves scroll, so the summary is what an interface
        // test can read without scrolling to a card.
        let recorded = app.progressIndicators.matching(
            NSPredicate(format: "label BEGINSWITH '1 of '")
        ).firstMatch
        XCTAssertTrue(
            recorded.waitForExistence(timeout: 15),
            "The sidebar did not record the control the committed answers hold."
        )
    }
}
