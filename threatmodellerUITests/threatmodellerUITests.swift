//
//  threatmodellerUITests.swift
//  threatmodellerUITests
//
//  Created by Craig J. Bass on 07/09/2026.
//

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
    /// This test clicks a category row on its label, not on the triangle,
    /// and confirms the category opens. It then clicks a technology row and
    /// confirms the threat list updates. A click that lands on a dead
    /// control raises an `XCTest` error because `isHittable` is asserted
    /// first, so this test fails loudly instead of passing on a frozen UI.
    @MainActor
    func testClickingACategoryLabelExpandsItAndClickingATechnologyAddsItsThreats() throws {
        let app = XCUIApplication()
        app.launch()

        // Click the category row on its label, not on the disclosure triangle.
        let categoryLabel = app.staticTexts["Compute"]
        XCTAssertTrue(
            categoryLabel.waitForExistence(timeout: 15),
            "The 'Compute' category row did not appear in the palette."
        )
        XCTAssertTrue(
            categoryLabel.isHittable,
            "The 'Compute' category label is not hittable. Only the disclosure " +
            "triangle would respond to a click, which is the defect this test guards against."
        )
        categoryLabel.click()

        // The category must now be expanded: its technology row appears.
        let technologyRow = app.buttons["EC2, Virtual servers in the cloud"]
        XCTAssertTrue(
            technologyRow.waitForExistence(timeout: 5),
            "Clicking the 'Compute' category label did not expand it; the EC2 row never appeared."
        )
        XCTAssertTrue(
            technologyRow.isHittable,
            "The EC2 technology row is not hittable across its full width."
        )

        // Before adding anything, the threat list shows its empty state.
        XCTAssertTrue(
            app.staticTexts["No threats yet"].exists,
            "Expected the empty threat list state before any technology is added."
        )

        // Click the technology row anywhere on it, not on any particular sub-element.
        technologyRow.click()

        // The threat list must now show EC2's threats, worst first.
        let firstThreat = app.staticTexts["Credential Theft"]
        XCTAssertTrue(
            firstThreat.waitForExistence(timeout: 10),
            "Clicking the EC2 technology row did not raise its threats; " +
            "'Credential Theft' never appeared in the threat list."
        )
        XCTAssertFalse(
            app.staticTexts["No threats yet"].exists,
            "The empty threat list state is still showing after a technology was added."
        )
    }

    @MainActor
    func testLaunchPerformance() throws {
        // This measures how long it takes to launch your application.
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }
}
