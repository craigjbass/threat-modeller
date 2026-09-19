import ArchitectureDSL
import Testing
import ThreatModelKit

/// The declared vocabulary is the parser's vocabulary.
///
/// Issue #152: the window has one-to-one parity with the code model, and the
/// parity test walks `LanguageVocabulary`. That walk is only worth taking
/// while the parsers read their word lists from the same declaration, so each
/// test below feeds one parser a word it does not hold and reads the message
/// back.
@Suite("The declared language vocabulary")
struct LanguageVocabularyTests {
    private func messages(_ diagnostics: [Diagnostic]) -> [String] {
        diagnostics.map(\.message)
    }

    // MARK: the message every parser records

    @Test func theArchitectureParserNamesTheDeclaredComponentWords() {
        let read = HclArchitectureSource().read("""
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            colour     = "red"
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.archComponent.unknownAttribute("colour"))
        )
    }

    @Test func theArchitectureParserNamesTheDeclaredZoneWords() {
        let read = HclArchitectureSource().read("""
        system "Payments" {
          zone "app" {
            kind   = "private"
            colour = "red"
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.archZone.unknownAttribute("colour"))
        )
    }

    @Test func theControlsParserNamesTheDeclaredControlWords() {
        let read = HclControlsSource().read("""
        controls for "Payments" {
          threat "spoofing" on component "api" {
            control "mfa" {
              status = "implemented"
              colour = "red"
            }
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.controlsControl.unknownAttribute("colour"))
        )
    }

    @Test func theAttackTreeParserNamesTheDeclaredTreeWords() {
        let read = HclAttackTreeSource().read("""
        attack_trees for "Payments" {
          tree "steal" {
            goal   = "Steal the money"
            colour = "red"
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.attackTreeTree.unknownAttribute("colour"))
        )
    }

    @Test func theAttackTreeParserNamesTheBlockKeywordOfANode() {
        let read = HclAttackTreeSource().read("""
        attack_trees for "Payments" {
          tree "steal" {
            goal = "Steal the money"
            all_of {
              colour = "red"
            }
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.attackTreeAllOf.unknownAttribute("colour"))
        )
    }

    @Test func theGovernanceParserNamesTheDeclaredAcceptedWords() {
        let read = HclGovernanceSource().read("""
        governance for "Payments" {
          threat "spoofing" on component "api" {
            accepted "the risk is small" {
              owner  = "Ada"
              colour = "red"
            }
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.governanceAccepted.unknownAttribute("colour"))
        )
    }

    @Test func thePolicyParserNamesTheDeclaredPolicyWords() {
        let read = HclPolicySource().read("""
        policy {
          no_critical_threats = true
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.policyDocument.unknownAttribute("no_critical_threats"))
        )
    }

    @Test func theLibraryParserNamesTheDeclaredThreatWords() {
        let read = HclLibrarySource().read("""
        library "Extra" {
          threat "spoofing" {
            name   = "Spoofing"
            colour = "red"
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.libraryThreat.unknownAttribute("colour"))
        )
    }

    @Test func theLibraryParserNamesTheDeclaredTechnologyWords() {
        let read = HclLibrarySource().read("""
        library "Extra" {
          technology "aws-ec2" {
            name   = "EC2"
            colour = "red"
          }
        }
        """)

        #expect(
            messages(read.diagnostics)
                .contains(LanguageBlockId.libraryTechnology.unknownAttribute("colour"))
        )
    }

    // MARK: the shape of the declaration

    @Test func everyBlockNamesItsLanguageAndItsOwnName() {
        var seen: Set<String> = []
        for block in LanguageVocabulary.blocks {
            #expect(block.language.isEmpty == false)
            #expect(block.name.isEmpty == false)
            #expect(block.attributes.isEmpty == false)
            let key = "\(block.language).\(block.name)"
            #expect(seen.contains(key) == false, "two blocks are called \(key)")
            seen.insert(key)
        }
    }

    @Test func noBlockStatesOneAttributeTwice() {
        for block in LanguageVocabulary.blocks {
            #expect(
                Set(block.attributes).count == block.attributes.count,
                "\(block.language).\(block.name) states an attribute twice"
            )
        }
    }

    @Test func theSentenceReadsAsTheMessageDoes() {
        let one = LanguageBlock(
            language: "arch",
            name: "one",
            keywords: ["one"],
            within: [],
            phrase: "a one holds",
            attributes: ["a"]
        )
        let three = LanguageBlock(
            language: "arch",
            name: "three",
            keywords: ["three"],
            within: [],
            phrase: "a three holds",
            attributes: ["a", "b", "c"]
        )
        let commas = LanguageBlock(
            language: "arch",
            name: "commas",
            keywords: ["commas"],
            within: [],
            phrase: "a commas holds",
            attributes: ["a", "b", "c"],
            listsWithCommasAlone: true
        )

        #expect(one.unknownAttribute("z") == "a one holds a, not \"z\"")
        #expect(three.unknownAttribute("z") == "a three holds a, b and c, not \"z\"")
        #expect(commas.unknownAttribute("z") == "a commas holds a, b, c, not \"z\"")
    }
}
