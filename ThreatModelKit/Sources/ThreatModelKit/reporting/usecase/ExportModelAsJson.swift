import Foundation

public protocol ExportModelAsJsonUseCase {
    func execute(_ request: ExportModelAsJsonRequest) -> ExportModelAsJsonResponse
}

public struct ExportModelAsJsonRequest: Equatable, Sendable {
    public init() {}
}

public struct ExportModelAsJsonResponse: Equatable, Sendable {
    public let json: String
    public let fileName: String

    public init(json: String, fileName: String) {
        self.json = json
        self.fileName = fileName
    }
}

/// Writes the assessed model as data another program reads.
///
/// A risk register, a dashboard and a spreadsheet all want the numbers, and
/// none of them should parse Markdown to get them. The shape is stated in
/// `docs/threatmodel-export.schema.json` and the file names the version it
/// was written against, so a reader knows what it holds.
///
/// Keys are written in alphabetical order and the whole file is printed the
/// same way every time, so two exports of one model are the same bytes.
public struct ExportModelAsJson: ExportModelAsJsonUseCase {
    /// The version of `docs/threatmodel-export.schema.json` this writes. It
    /// goes up when a key changes meaning or leaves.
    public static let schemaVersion = "1.0.0"

    private let reports: BuildThreatModelReportUseCase

    public init(reports: BuildThreatModelReportUseCase) {
        self.reports = reports
    }

    public func execute(_ request: ExportModelAsJsonRequest) -> ExportModelAsJsonResponse {
        let report = reports.execute(BuildThreatModelReportRequest()).report
        let document = ExportedModel(report)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(document)) ?? Data()

        return ExportModelAsJsonResponse(
            json: String(decoding: data, as: UTF8.self) + "\n",
            fileName: "\(FileNaming.stem(from: report.modelName)).json"
        )
    }
}

/// The exported shape. Every type here is data: no behaviour, and no type
/// from the model, so a change to the model is a change a person makes here
/// on purpose.
struct ExportedModel: Codable {
    let schemaVersion: String
    let system: ExportedSystem
    let summary: ExportedSummary
    let zones: [ExportedZone]
    let components: [ExportedComponent]
    let flows: [ExportedFlow]
    let assets: [ExportedAsset]
    let thirdParties: [ExportedThirdParty]
    let assumptions: [ExportedAssumption]
    let useCases: [ExportedLabelledText]
    let exclusions: [ExportedExclusion]
    let threats: [ExportedThreat]
    let recommendations: [ExportedRecommendation]
    let leverage: [ExportedAction]
    let acceptedRisks: [ExportedAcceptedRisk]

    init(_ report: Report) {
        schemaVersion = ExportModelAsJson.schemaVersion
        system = ExportedSystem(report)
        summary = ExportedSummary(report)
        zones = report.zones.map(ExportedZone.init)
        components = report.components.map(ExportedComponent.init)
        flows = report.connections.map(ExportedFlow.init)
        assets = report.dataInventory.map(ExportedAsset.init)
        thirdParties = report.thirdParties.map(ExportedThirdParty.init)
        assumptions = report.assumptions.map(ExportedAssumption.init)
        useCases = report.useCases.map { ExportedLabelledText(label: $0.label, text: $0.text) }
        exclusions = report.exclusions.map(ExportedExclusion.init)
        threats = report.threats.map(ExportedThreat.init)
        recommendations = report.recommendations.map(ExportedRecommendation.init)
        leverage = report.actions.map(ExportedAction.init)
        acceptedRisks = report.acceptedRisks.map(ExportedAcceptedRisk.init)
    }
}

struct ExportedSystem: Codable {
    let name: String
    let owner: String?
    let description: String?
    let authors: [String]
    let version: String?
    let created: String?
    let reviewed: String?
    let catalogueTag: String?
    let riskTolerance: String
    let links: [String]
    let repositories: [String]

    init(_ report: Report) {
        links = report.documentControl.links
        repositories = report.documentControl.repositories
        name = report.modelName
        owner = report.documentControl.owner
        description = report.documentControl.description
        authors = report.documentControl.authors
        version = report.documentControl.version
        created = report.documentControl.created
        reviewed = report.documentControl.reviewed
        catalogueTag = report.catalogueTag
        riskTolerance = report.toleranceLabel
    }
}

struct ExportedSummary: Codable {
    let totalThreats: Int
    let unansweredThreats: Int
    let controlsOffered: Int
    let controlsRecorded: Int
    let byLevel: [ExportedCount]
    let byStride: [ExportedCount]
    let byControlStatus: [ExportedCount]
    let openByImpact: [ExportedCount]
    let exclusions: Int
    let hardDependencies: Int

    init(_ report: Report) {
        totalThreats = report.summary.totalThreats
        unansweredThreats = report.executiveSummary.unansweredCount
        controlsOffered = report.summary.controlsOffered
        controlsRecorded = report.summary.controlsRecorded
        byLevel = report.summary.byLevel.map(ExportedCount.init)
        byStride = report.summary.byStride.map(ExportedCount.init)
        byControlStatus = report.summary.byControlStatus.map(ExportedCount.init)
        openByImpact = report.executiveSummary.openByImpact.map(ExportedCount.init)
        exclusions = report.executiveSummary.exclusionCount
        hardDependencies = report.executiveSummary.hardDependencyCount
    }
}

struct ExportedCount: Codable {
    let label: String
    let count: Int

    init(_ count: ReportCount) {
        label = count.label
        self.count = count.count
    }
}

struct ExportedZone: Codable {
    let name: String
    let networkZone: String
    let networkType: String
    let boundary: String
    let componentIds: [String]
    let riskReductionPercent: Int?

    init(_ zone: ReportZone) {
        name = zone.name
        networkZone = zone.networkZoneLabel
        networkType = zone.networkTypeLabel
        boundary = zone.boundaryLabel
        componentIds = zone.componentIds
        riskReductionPercent = zone.riskReductionPercent
    }
}

struct ExportedComponent: Codable {
    let id: String
    let name: String
    let technologyId: String
    let categoryId: String
    let sensitivity: String
    let privilege: String
    let zoneName: String?
    let assetNames: [String]

    init(_ component: ReportComponent) {
        id = component.id
        name = component.name
        technologyId = component.technologyId
        categoryId = component.categoryId
        sensitivity = component.sensitivityLabel
        privilege = component.privilegeLabel
        zoneName = component.zoneName
        assetNames = component.assetNames
    }
}

struct ExportedFlow: Codable {
    let sourceName: String
    let targetName: String
    let kind: String
    let description: String?

    init(_ connection: ReportConnection) {
        sourceName = connection.sourceName
        targetName = connection.targetName
        kind = connection.kindLabel
        description = connection.description
    }
}

struct ExportedAsset: Codable {
    let id: String
    let name: String
    let classification: String
    let description: String
    let owner: String?
    let heldBy: [String]
    let carriedBy: [String]
    let worstOpenThreat: String?
    let worstOpenScore: Int?

    init(_ row: ReportAssetRow) {
        id = row.id
        name = row.name
        classification = row.classificationLabel
        description = row.description
        owner = row.owner
        heldBy = row.heldBy
        carriedBy = row.carriedBy
        worstOpenThreat = row.worstOpenThreat
        worstOpenScore = row.worstOpenScore
    }
}

struct ExportedThirdParty: Codable {
    let id: String
    let name: String
    let description: String
    let kind: String
    let payingCustomer: Bool
    let uptime: String
    let uptimeNotes: String
    let owner: String?
    let link: String?
    let provides: [String]
    let assetNames: [String]

    init(_ party: ReportThirdParty) {
        id = party.id
        name = party.name
        description = party.description
        kind = party.kindLabel
        payingCustomer = party.payingCustomer
        uptime = party.uptimeLabel
        uptimeNotes = party.uptimeNotes
        owner = party.owner
        link = party.link
        provides = party.provides
        assetNames = party.assetNames
    }
}

struct ExportedAssumption: Codable {
    let label: String
    let text: String
    let owner: String?

    init(_ assumption: ReportAssumption) {
        label = assumption.label
        text = assumption.text
        owner = assumption.owner
    }
}

struct ExportedLabelledText: Codable {
    let label: String
    let text: String
}

struct ExportedExclusion: Codable {
    let label: String
    let text: String
    let rationale: String

    init(_ exclusion: ReportExclusion) {
        label = exclusion.label
        text = exclusion.text
        rationale = exclusion.rationale
    }
}

struct ExportedThreat: Codable {
    let id: String
    let name: String
    let description: String
    let severity: String
    let riskScore: Int
    let riskLevel: String
    let inherentScore: Int
    let isOpen: Bool
    let stride: [String]
    let impacts: [String]
    let assetsAtRisk: [String]
    let mitreTechniqueIds: [String]
    let performedBy: [String]
    let likelihood: String
    let likelihoodRationale: String?
    let sourceId: String
    let sourceKind: String
    let sourceName: String
    let controls: [ExportedControl]
    let compensating: [ExportedCompensatingControl]
    let answeredUpstreamBy: [String]
    let reducedBy: [String]

    init(_ threat: ReportThreat) {
        id = threat.threatId
        name = threat.name
        description = threat.description
        severity = threat.severityLabel
        riskScore = threat.riskScore
        riskLevel = threat.riskLevel
        inherentScore = threat.inherentScore
        isOpen = threat.isOpen
        stride = threat.strideLabels
        impacts = threat.impactLabels
        assetsAtRisk = threat.assetsAtRisk
        mitreTechniqueIds = threat.mitreTechniqueIds
        performedBy = threat.performedByLabels
        likelihood = threat.likelihoodLabel
        likelihoodRationale = threat.likelihoodRationale
        sourceId = threat.sourceId
        sourceKind = threat.sourceKind
        sourceName = threat.sourceName
        controls = threat.controls.map(ExportedControl.init)
        compensating = threat.compensating.map(ExportedCompensatingControl.init)
        answeredUpstreamBy = threat.pathwayMitigationLabels
        reducedBy = threat.mitigatedByComponentLabels
    }
}

struct ExportedControl: Codable {
    let description: String
    let status: String
    let isImplemented: Bool
    let evidence: String?

    init(_ control: ReportControl) {
        description = control.description
        status = control.statusLabel
        isImplemented = control.isImplemented
        evidence = control.evidence
    }
}

struct ExportedCompensatingControl: Codable {
    let label: String
    let reducesRiskBy: Int
    let rationale: String
    let evidence: String?
    let sources: [String]

    init(_ control: ReportCompensatingControl) {
        label = control.label
        reducesRiskBy = control.reducesRiskBy
        rationale = control.rationale
        evidence = control.evidence
        sources = control.sources
    }
}

struct ExportedRecommendation: Codable {
    let text: String
    let note: String?
    let threatId: String
    let threatName: String
    let sourceId: String
    let sourceName: String
    let riskScore: Int
    let governance: String?
    let sources: [String]

    init(_ recommendation: ReportRecommendation) {
        text = recommendation.text
        note = recommendation.note
        threatId = recommendation.threatId
        threatName = recommendation.threatName
        sourceId = recommendation.sourceId
        sourceName = recommendation.sourceName
        riskScore = recommendation.riskScore
        governance = recommendation.governance
        sources = recommendation.sources
    }
}

struct ExportedAction: Codable {
    let label: String
    let text: String
    let note: String?
    let blockedBy: String?
    let governance: String?
    let removes: Int
    let totalResidual: Int
    let threatsMoved: Int
    let worstBefore: Int
    let worstAfter: Int
    let sources: [String]

    init(_ action: ReportAction) {
        label = action.label
        text = action.text
        note = action.note
        blockedBy = action.blockedBy
        governance = action.governance
        removes = action.removes
        totalResidual = action.totalResidual
        threatsMoved = action.threatsMoved
        worstBefore = action.worstBefore
        worstAfter = action.worstAfter
        sources = action.sources
    }
}

struct ExportedAcceptedRisk: Codable {
    let threatName: String
    let sourceName: String
    let riskScore: Int
    let control: String
    let owner: String
    let acceptedOn: String?
    let reviewBy: String?
    let rationale: String
    let isOverdue: Bool

    init(_ risk: ReportAcceptedRisk) {
        threatName = risk.threatName
        sourceName = risk.sourceName
        riskScore = risk.riskScore
        control = risk.control
        owner = risk.owner
        acceptedOn = risk.acceptedOn
        reviewBy = risk.reviewBy
        rationale = risk.rationale
        isOverdue = risk.isOverdue
    }
}
