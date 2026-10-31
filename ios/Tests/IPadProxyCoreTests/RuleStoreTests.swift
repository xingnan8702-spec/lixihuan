import Foundation
import XCTest
@testable import IPadProxyCore

private struct FailingRulePersistence: RulePersistence {
    func persist(_ data: Data, to destination: URL) throws {
        throw RuleStoreError.persistenceFailed
    }
}

final class RuleStoreTests: XCTestCase, @unchecked Sendable {
    func testPersistenceFailureKeepsOldActiveGeneration() async throws {
        let store = RuleStore(persistence: FailingRulePersistence())
        let first = Data(#"{"version":1,"rules":[],"final":"DIRECT"}"#.utf8)
        let second = Data(#"{"version":1,"rules":[],"final":"PROXY"}"#.utf8)
        let initial = try await store.importRules(from: first)

        do {
            _ = try await store.importRules(
                from: second,
                persistTo: URL(fileURLWithPath: "/unused/rules.json")
            )
            XCTFail("expected persistence failure")
        } catch {}

        let active = try await store.snapshot()
        XCTAssertEqual(active.generation, initial.generation)
        XCTAssertEqual(active.configuration.final, .direct)
        XCTAssertEqual(active.trust, .localImportOnly)
    }

    func testAtomicPersistenceAndStartupLoad() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ipad-proxy-rules-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("rules.json")
        let first = Data(#"{"version":1,"rules":[],"final":"DIRECT"}"#.utf8)
        let second = Data(#"{"version":1,"rules":[],"final":"REJECT"}"#.utf8)
        let store = RuleStore()
        _ = try await store.importRules(from: first, persistTo: destination)
        _ = try await store.importRules(from: second, persistTo: destination)

        let loaded = try RuleStore(startupURL: destination)
        let snapshot = try await loaded.snapshot()
        XCTAssertEqual(snapshot.configuration.final, .reject)
        XCTAssertEqual(snapshot.generation, 1)
    }

    func testMalformedImportDoesNotReplaceActiveRules() async throws {
        let store = RuleStore()
        _ = try await store.importRules(
            from: Data(#"{"version":1,"rules":[],"final":"PROXY"}"#.utf8)
        )
        do {
            _ = try await store.importRules(from: Data(#"{"version":1,"rules":[],"final":"DIRECT","extra":1}"#.utf8))
            XCTFail("expected validation error")
        } catch {}
        let active = try await store.snapshot()
        let generation = await store.generation
        XCTAssertEqual(active.configuration.final, .proxy)
        XCTAssertEqual(generation, 1)
    }
}

extension RuleStoreTests {
    func testOversizedImportIsRejectedWithoutReplacingActiveRules() async throws {
        let store = RuleStore()
        _ = try await store.importRules(
            from: Data(#"{"version":1,"rules":[],"final":"DIRECT"}"#.utf8)
        )
        let oversized = Data(repeating: 0x20, count: RuleStore.maximumInputBytes + 1)
        do {
            _ = try await store.importRules(from: oversized)
            XCTFail("expected input size rejection")
        } catch {
            XCTAssertEqual(error as? RuleStoreError, .inputTooLarge(oversized.count))
        }
        let active = try await store.snapshot()
        XCTAssertEqual(active.generation, 1)
        XCTAssertEqual(active.configuration.final, .direct)
    }
}
