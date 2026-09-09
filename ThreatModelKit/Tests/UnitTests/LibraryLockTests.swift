import Testing
@testable import ThreatModelKit

@Suite("The library lock file")
struct LibraryLockTests {
    private let lock = LibraryLock(libraries: [
        LockedLibrary(
            label: "acme",
            repository: "git@github.com:acme/threat-elements.git",
            tag: "v2.1.0",
            files: ["acme.lib": "ab12"]
        )
    ])

    @Test func readsWhatItWrites() {
        #expect(LibraryLock.read(lock.written()) == lock)
    }

    @Test func writesTheSameTextTwice() {
        #expect(lock.written() == lock.written())
    }

    @Test func readsALockFileWithTwoLibrariesInOneOrder() {
        let two = LibraryLock(libraries: [
            LockedLibrary(label: "beta", repository: "r2", tag: "v1", files: [:]),
            LockedLibrary(label: "acme", repository: "r1", tag: "v2", files: [:])
        ])

        // Sorted by label, so two writes of one project give the same file.
        #expect(LibraryLock.read(two.written()).libraries.map(\.label) == ["acme", "beta"])
    }

    @Test func readsNothingFromTextThatIsNotALockFile() {
        #expect(LibraryLock.read("not json").libraries.isEmpty)
    }

    @Test func readsNothingFromAnEmptyLockFile() {
        #expect(LibraryLock.read("{}").libraries.isEmpty)
    }

    @Test func checksumsTheSameTextTheSameWay() {
        #expect(LibraryLock.checksum("abc") == LibraryLock.checksum("abc"))
        #expect(LibraryLock.checksum("abc") != LibraryLock.checksum("abd"))
        #expect(LibraryLock.checksum("abc").count == 64)
    }

    @Test func checksumsWhatSha256Says() {
        // The published SHA-256 digests, from FIPS 180-4.
        #expect(
            LibraryLock.checksum("")
                == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        #expect(
            LibraryLock.checksum("abc")
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        #expect(
            LibraryLock.checksum("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
                == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
    }

    @Test func checksumsTextLongerThanOneBlock() {
        // 1,000,000 "a" characters, the third published test vector.
        #expect(
            LibraryLock.checksum(String(repeating: "a", count: 1_000_000))
                == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )
    }
}
