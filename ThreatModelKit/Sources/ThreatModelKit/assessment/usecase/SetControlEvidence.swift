public protocol SetControlEvidenceUseCase {
    func execute(_ request: SetControlEvidenceRequest) -> SetControlEvidenceResponse
}

public struct SetControlEvidenceRequest: Equatable, Sendable {
    public let controlKey: String
    /// The tier, or nil for a control that states none.
    public let evidenceId: String?
    /// Where the proof is: a URL, a document number, a test name.
    public let reference: String
    /// When somebody last checked, written `YYYY-MM-DD`, or nil.
    public let verifiedOn: String?

    public init(controlKey: String, evidenceId: String?, reference: String, verifiedOn: String?) {
        self.controlKey = controlKey
        self.evidenceId = evidenceId
        self.reference = reference
        self.verifiedOn = verifiedOn
    }
}

public enum SetControlEvidenceResponse: Equatable, Sendable {
    case recorded
    case unknownEvidence
    case notADate(String)

    /// Puts what went wrong where a delivery mechanism shows it, or clears it.
    public func describe(into message: inout String?) {
        switch self {
        case .recorded:
            message = nil
        case .unknownEvidence:
            message = "That evidence tier is not one this application holds."
        case .notADate(let said):
            message = said
        }
    }
}

/// Records what proves one control is in place.
///
/// The tier moves no score. It says how well a reader can check the claim,
/// and `requires_evidence_above` is what makes a missing tier fail a check.
public struct SetControlEvidence: SetControlEvidenceUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetControlEvidenceRequest) -> SetControlEvidenceResponse {
        switch ControlProofReading.read(
            evidenceId: request.evidenceId,
            reference: request.reference,
            verifiedOn: request.verifiedOn
        ) {
        case .failure(.unknownEvidence):
            return .unknownEvidence
        case .failure(.notADate(let said)):
            return .notADate(said)
        case .success(let proof):
            return models.mutate(label: ChangeLabel.setControlEvidence) { model in
                model.controlProofs[ControlKey(request.controlKey)] = proof.isEmpty ? nil : proof
                return .recorded
            }
        }
    }
}

/// Reads the three evidence attributes a request states into a proof.
/// `SetControlEvidence` and `SetCompensatingControl` both take them, and the
/// two refuse the same words the same way.
enum ControlProofReading {
    enum Refusal: Equatable, Error {
        case unknownEvidence
        case notADate(String)
    }

    static func read(
        evidenceId: String?,
        reference: String,
        verifiedOn: String?
    ) -> Result<ControlProof, Refusal> {
        var evidence: ControlEvidence?
        if let evidenceId {
            guard let tier = ControlEvidence(rawValue: evidenceId) else {
                return .failure(.unknownEvidence)
            }
            evidence = tier
        }

        var verified: GovernanceDate?
        if let verifiedOn {
            switch GovernanceDate.read(verifiedOn) {
            case .success(let day):
                verified = day
            case .failure(let fault):
                return .failure(.notADate(fault.message(attribute: "verified_on", raw: verifiedOn)))
            }
        }

        return .success(
            ControlProof(
                evidence: evidence,
                reference: reference.trimmingWhitespace(),
                verifiedOn: verified
            )
        )
    }
}
