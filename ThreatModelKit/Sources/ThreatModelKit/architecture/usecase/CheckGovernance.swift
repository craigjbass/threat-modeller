import Foundation

public protocol CheckGovernanceUseCase {
    func execute(_ request: CheckGovernanceRequest) -> CheckGovernanceResponse
}

public struct CheckGovernanceRequest: Equatable, Sendable {
    /// The answers the controls compile wrote.
    public let controlsText: String
    /// The governance beside them, or nil when the project holds none.
    public let governanceText: String?

    public init(controlsText: String, governanceText: String? = nil) {
        self.controlsText = controlsText
        self.governanceText = governanceText
    }
}

public enum CheckGovernanceResponse: Equatable, Sendable {
    /// One line per failure, in the shape `check` prints.
    case checked(failures: [String])
    case refused(diagnostics: [Diagnostic])
}

/// Says what an accepted risk has not stated.
///
/// An accepted risk with no owner and no review date is not a decision; it is
/// a threat somebody stopped reading. Planned work fails nothing: a plan with
/// no owner is a gap in a plan, and the report prints it.
public struct CheckGovernance: CheckGovernanceUseCase {
    private let controlsSources: ControlsSourceGateway
    private let governanceSources: GovernanceSourceGateway
    private let clock: Clock

    public init(
        controlsSources: ControlsSourceGateway,
        governanceSources: GovernanceSourceGateway,
        clock: Clock
    ) {
        self.controlsSources = controlsSources
        self.governanceSources = governanceSources
        self.clock = clock
    }

    public func execute(_ request: CheckGovernanceRequest) -> CheckGovernanceResponse {
        let read = controlsSources.read(request.controlsText)
        guard let answers = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        var governance: GovernanceSource?
        if let governanceText = request.governanceText, governanceText.isEmpty == false {
            let read = governanceSources.read(governanceText)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            governance = source
        }

        let today = Self.today(clock.now())
        var failures: [String] = []

        for answer in answers.answers where answer.isStale == false {
            let accepted = answer.controls.filter { $0.status == .accepted }
            guard accepted.isEmpty == false else { continue }
            let governed = governance?.threat(for: answer.key)

            for control in accepted {
                let key = answer.key.value
                guard let stanza = governed?.accepted.first(where: {
                    $0.control == control.description && $0.isStale == false
                }) else {
                    failures.append(
                        "\(key) is accepted and has no governance entry;"
                            + " run threatmodeller compile"
                    )
                    continue
                }

                if stanza.owner.isEmpty {
                    failures.append("\(key) is accepted by nobody; the accepted risk needs an owner")
                }
                guard let reviewBy = stanza.reviewBy,
                      let date = try? GovernanceDate.read(reviewBy).get() else {
                    failures.append("\(key) is accepted with no review date")
                    continue
                }
                if date < today {
                    failures.append(
                        "\(key) was accepted for review by \(date), which has passed"
                    )
                }
            }
        }

        return .checked(failures: failures)
    }

    /// The day the clock names, read in UTC so a test and a build agree
    /// whatever machine they run on.
    public static func today(_ now: Date) -> GovernanceDate {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        let parts = calendar.dateComponents([.year, .month, .day], from: now)
        return GovernanceDate(
            year: parts.year ?? 1970,
            month: parts.month ?? 1,
            day: parts.day ?? 1
        ) ?? GovernanceDate(year: 1970, month: 1, day: 1)!
    }
}
