import ArchitectureDSL
import Testing
import TestSupport

@Suite("The HCL library source")
struct HclLibrarySourceTests {
    @Test func meetsTheContract() {
        assertLibrarySourceGateway(HclLibrarySource())
    }
}
