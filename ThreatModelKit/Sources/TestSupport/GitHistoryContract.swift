import Foundation
import Testing
import ThreatModelKit

/// The behaviour every `GitHistoryGateway` must exhibit.
///
/// `root` holds a repository with at least two commits that touched
/// `path`, newest first, and `unheldPath` is a path the newest commit does not
/// hold.
public func verifyGitHistoryContract(
    _ subject: GitHistoryGateway,
    root: String,
    path: String,
    unheldPath: String
) throws {
    #expect(subject.isRepository(root: root))

    let commits = try subject.commits(root: root, touching: [path], limit: 10)
    #expect(commits.count >= 2)
    #expect(Set(commits.map(\.hash)).count == commits.count)
    for commit in commits {
        #expect(commit.hash.isEmpty == false)
        #expect(commit.shortHash.count <= commit.hash.count)
        #expect(commit.author.isEmpty == false)
    }

    // Newest first, so a reader takes the head of the list as today.
    let dates = commits.map(\.date)
    #expect(dates == dates.sorted(by: >))

    // A bound is a bound.
    #expect(try subject.commits(root: root, touching: [path], limit: 1).count == 1)

    let newest = try #require(commits.first)
    let text = try subject.file(root: root, at: newest.hash, path: path)
    #expect(text?.isEmpty == false)

    // A path the commit does not hold is nil, not an error: a project gains
    // files over its life.
    #expect(try subject.file(root: root, at: newest.hash, path: unheldPath) == nil)
}
