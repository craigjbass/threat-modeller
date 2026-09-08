import Foundation
import FileGateways
import Testing
import ThreatModelKit

/// What every sample gateway owes its callers, run against the fake and
/// against the real bundle.
public func verifySampleModelGatewayContract(_ make: () -> SampleModelGateway) {
    let gateway = make()
    let samples = gateway.all()

    #expect(samples.isEmpty == false, "A sample gateway with nothing in it has nothing to browse.")
    #expect(
        Set(samples.map(\.id)).count == samples.count,
        "Two samples share an identifier, so one of them cannot be opened."
    )

    for sample in samples {
        #expect(sample.name.isEmpty == false, "\(sample.id) has no name.")
        #expect(sample.description.isEmpty == false, "\(sample.id) has no description.")

        do {
            // A sample is a document, read by the codec a user's own file goes
            // through. A sample that stops opening is a format defect.
            let model = try ThreatModelCodec().decode(try gateway.document(id: sample.id))
            #expect(model.name.isEmpty == false, "\(sample.id) opens with no name.")
            #expect(
                model.components.isEmpty == false,
                "\(sample.id) opens with nothing on the canvas."
            )
        } catch {
            Issue.record("\(sample.id) did not open: \(error)")
        }
    }

    #expect(throws: SampleModelError.unknownSample(id: "no-such-sample")) {
        _ = try gateway.document(id: "no-such-sample")
    }
}
