import Testing
import ThreatModelKit

struct SensitivityLadderTests {
    @Test func picksTheHigherOfTwoSensitivities() {
        #expect(SensitivityLadder.higher(.publicData, .restricted) == .restricted)
        #expect(SensitivityLadder.higher(.restricted, .publicData) == .restricted)
        #expect(SensitivityLadder.higher(.internalData, .confidential) == .confidential)
    }

    @Test func returnsTheSameValueWhenBothMatch() {
        #expect(SensitivityLadder.higher(.confidential, .confidential) == .confidential)
    }

    @Test func rankOrderDecidesNotDeclarationOrder() {
        for first in DataSensitivity.allCases {
            for second in DataSensitivity.allCases {
                let picked = SensitivityLadder.higher(first, second)
                #expect(picked.rank == max(first.rank, second.rank))
            }
        }
    }
}
