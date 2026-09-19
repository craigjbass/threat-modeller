/// What the clearances the legitimate users hold take off the threats an
/// insider performs, by source.
///
/// Issue #259. A clearance is a compensating control on an `insider`-tier
/// threat, on the components the cleared legitimate users reach. The reduction
/// on one component is the weakest clearance among the legitimate users that
/// reach it, so one uncleared user leaves the risk where it was. An adversary
/// is not a legitimate user and reduces nothing.
///
/// A pure value built once from the model. It reads no gateway.
public struct ClearanceCover: Sendable {
    /// What one component's insider threats are compensated by.
    public struct Cover: Equatable, Sendable {
        public let clearance: Clearance
        /// The ids of the users that hold it, in model order.
        public let userIds: [String]

        public init(clearance: Clearance, userIds: [String]) {
            self.clearance = clearance
            self.userIds = userIds
        }

        /// The compensating control this cover is, as the report and the
        /// export read it.
        public var asCompensatingControl: CompensatingControl {
            CompensatingControl(
                label: "Security clearance \"\(clearance.name)\", held by \(Self.named(userIds))",
                reducesRiskBy: clearance.reducesInsiderRiskBy,
                rationale: clearance.rationale,
                sources: clearance.sources
            )
        }

        private static func named(_ ids: [String]) -> String {
            switch ids.count {
            case 0: return "nobody"
            case 1: return ids[0]
            default: return ids.dropLast().joined(separator: ", ") + " and " + ids[ids.count - 1]
            }
        }
    }

    private let covers: [String: Cover]

    public init(model: ThreatModel) {
        let held = Dictionary(
            model.clearances.map { ($0.id, $0) },
            uniquingKeysWith: { _, later in later }
        )
        var reached: [String: [(userId: String, clearance: Clearance?)]] = [:]
        for user in model.components {
            guard let facts = user.user, facts.isAdversary == false else { continue }
            let clearance = facts.clearanceId.flatMap { held[$0] }
            for componentId in Set(facts.uses + facts.reaches).sorted() {
                reached["component:\(componentId)", default: []]
                    .append((userId: user.id.value, clearance: clearance))
            }
        }

        var covers: [String: Cover] = [:]
        for (sourceId, users) in reached {
            let clearances = users.compactMap(\.clearance)
            guard clearances.count == users.count else { continue }
            guard let weakest = clearances.min(by: {
                $0.reducesInsiderRiskBy < $1.reducesInsiderRiskBy
            }) else { continue }
            guard weakest.reducesInsiderRiskBy > 0 else { continue }
            covers[sourceId] = Cover(
                clearance: weakest,
                userIds: users.map(\.userId).sorted()
            )
        }
        self.covers = covers
    }

    /// What compensates the insider threats on this source, or nil.
    public func cover(on sourceId: String) -> Cover? {
        covers[sourceId]
    }
}
