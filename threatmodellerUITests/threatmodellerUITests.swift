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
}
