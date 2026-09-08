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

        // The palette lists the catalogue, grouped by provider then category.
        // Each row carries a stable accessibility identifier built from its
        // provider id, category id, and technology id, so the query does not
        // depend on tree order or on the row's visible label text.
        let category = app.buttons["category-aws-compute"]
        XCTAssertTrue(
            category.waitForExistence(timeout: 15),
            "The 'category-aws-compute' category never appeared in the palette."
        )
        XCTAssertTrue(
            app.staticTexts["No threats yet"].exists,
            "Expected the empty threat list before a technology is added."
        )

        // Open the category by clicking the row, not the disclosure triangle.
        mark("clicking the 'Compute' category")
        category.click()

        // If the category row were dead, this row would never appear.
        // The row is a drag source, not a button, so it is not in
        // `app.buttons`. Query by identifier across every element kind.
        let technology = app.descendants(matching: .any)["technology-aws-ec2"].firstMatch
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
            app.descendants(matching: .any)["node-aws-ec2"].firstMatch.waitForExistence(timeout: 10),
            "Double-clicking the EC2 row did not put a node on the canvas."
        )

        // If the technology row were dead, these threats would never appear.
        XCTAssertTrue(
            app.staticTexts["Credential Theft"].firstMatch.waitForExistence(timeout: 10),
            "Clicking the EC2 row did not raise its threats."
        )
        XCTAssertFalse(
            app.staticTexts["No threats yet"].exists,
            "The empty threat list is still showing after a technology was added."
        )
        mark("threats shown")
    }
}
