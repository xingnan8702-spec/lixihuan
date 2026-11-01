import Foundation
import XCTest
@testable import IPadProxyCore

private enum LifecycleTestError: Error, Equatable, Sendable {
    case activationFailed
}

private actor ControlledLifecycleRuntime: TunnelLifecycleRuntime {
    struct Counts: Sendable {
        let prepare: Int
        let activate: Int
        let quiesce: Int
        let close: Int
    }

    private var shouldBlockPrepare: Bool
    private let shouldFailActivation: Bool
    private var shouldBlockClose: Bool
    private var prepareCount = 0
    private var activateCount = 0
    private var quiesceCount = 0
    private var closeCount = 0

    init(blockPrepare: Bool = false, failActivation: Bool = false, blockClose: Bool = false) {
        shouldBlockPrepare = blockPrepare
        shouldFailActivation = failActivation
        shouldBlockClose = blockClose
    }

    func prepare() async throws {
        prepareCount += 1
        while shouldBlockPrepare {
            try Task.checkCancellation()
            try await Task.sleep(nanoseconds: 100_000)
        }
    }

    func activate() async throws {
        activateCount += 1
        if shouldFailActivation { throw LifecycleTestError.activationFailed }
    }

    func quiesce() async { quiesceCount += 1 }

    func close() async throws {
        closeCount += 1
        while shouldBlockClose {
            try Task.checkCancellation()
            try await Task.sleep(nanoseconds: 100_000)
        }
    }

    func allowPrepare() { shouldBlockPrepare = false }
    func allowClose() { shouldBlockClose = false }

    func counts() -> Counts {
        Counts(prepare: prepareCount, activate: activateCount, quiesce: quiesceCount, close: closeCount)
    }
}

private actor FirstImmediateLifecycleSleeper: TunnelLifecycleSleeper {
    private var calls = 0

    func sleep(for interval: TimeInterval) async throws {
        calls += 1
        if calls == 1 { return }
        try await Task.sleep(nanoseconds: UInt64.max)
    }
}

final class TunnelLifecycleControllerTests: XCTestCase, @unchecked Sendable {
    func testStopDuringStartCancelsStartupAndCleansOnce() async throws {
        let runtime = ControlledLifecycleRuntime(blockPrepare: true)
        let controller = TunnelLifecycleController(runtime: runtime)
        let start = Task { try await controller.start() }
        await waitUntil { await runtime.counts().prepare == 1 }

        async let firstStop: Void = controller.stop()
        async let secondStop: Void = controller.stop()
        _ = await (firstStop, secondStop)

        do {
            _ = try await start.value
            XCTFail("expected cancelled start")
        } catch {
            XCTAssertEqual(error as? TunnelLifecycleError, .startCancelled)
        }
        let counts = await runtime.counts()
        XCTAssertEqual(counts.activate, 0)
        XCTAssertEqual(counts.quiesce, 1)
        XCTAssertEqual(counts.close, 1)
        let snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .stopped)
        XCTAssertEqual(snapshot.generation, 1)
    }

    func testRepeatedStopIsIdempotent() async throws {
        let runtime = ControlledLifecycleRuntime()
        let controller = TunnelLifecycleController(runtime: runtime)
        _ = try await controller.start()

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 { group.addTask { await controller.stop() } }
        }

        let counts = await runtime.counts()
        XCTAssertEqual(counts.quiesce, 1)
        XCTAssertEqual(counts.close, 1)
        let snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .stopped)
    }

    func testActivationFailureRollsBackAndAllowsNewGeneration() async throws {
        let runtime = ControlledLifecycleRuntime(failActivation: true)
        let controller = TunnelLifecycleController(runtime: runtime)

        do {
            _ = try await controller.start()
            XCTFail("expected startup failure")
        } catch let error as TunnelLifecycleError {
            guard case .startupFailed = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }

        let counts = await runtime.counts()
        XCTAssertEqual(counts.prepare, 1)
        XCTAssertEqual(counts.activate, 1)
        XCTAssertEqual(counts.quiesce, 1)
        XCTAssertEqual(counts.close, 1)
        let snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .failed)
        XCTAssertFalse(snapshot.hasResidualResources)
    }

    func testCleanupTimeoutBlocksRestartUntilSuccessfulStopRetry() async throws {
        let runtime = ControlledLifecycleRuntime(blockClose: true)
        let configuration = try TunnelLifecycleController.Configuration(cleanupTimeout: 1)
        let controller = TunnelLifecycleController(
            runtime: runtime,
            configuration: configuration,
            sleeper: FirstImmediateLifecycleSleeper()
        )
        _ = try await controller.start()
        await controller.stop()

        var snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .failed)
        XCTAssertEqual(snapshot.failure, .cleanupTimedOut)
        XCTAssertTrue(snapshot.hasResidualResources)
        do {
            _ = try await controller.start()
            XCTFail("expected residual-resource block")
        } catch {
            XCTAssertEqual(error as? TunnelLifecycleError, .residualResources)
        }

        await runtime.allowClose()
        await controller.stop()
        snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .stopped)
        XCTAssertFalse(snapshot.hasResidualResources)
    }

    func testFatalErrorUsesCleanupAndEndsFailedWithoutResiduals() async throws {
        let runtime = ControlledLifecycleRuntime()
        let controller = TunnelLifecycleController(runtime: runtime)
        _ = try await controller.start()

        await controller.handleFatalError(LifecycleTestError.activationFailed)

        let counts = await runtime.counts()
        XCTAssertEqual(counts.quiesce, 1)
        XCTAssertEqual(counts.close, 1)
        let snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .failed)
        XCTAssertEqual(snapshot.failure, .fatal("activationFailed"))
        XCTAssertFalse(snapshot.hasResidualResources)
    }

    func testGenerationIncrementsOnlyForStarts() async throws {
        let runtime = ControlledLifecycleRuntime()
        let controller = TunnelLifecycleController(runtime: runtime)
        let first = try await controller.start()
        await controller.stop()
        let second = try await controller.start()

        XCTAssertEqual(first, 1)
        XCTAssertEqual(second, 2)
        let snapshot = await controller.snapshot
        XCTAssertEqual(snapshot.state, .running)
        await controller.stop()
    }

    func testConfigurationValidation() {
        XCTAssertThrowsError(try TunnelLifecycleController.Configuration(cleanupTimeout: 0))
        XCTAssertThrowsError(try TunnelLifecycleController.Configuration(cleanupTimeout: .infinity))
    }

    private func waitUntil(
        _ predicate: @escaping @Sendable () async -> Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        for _ in 0..<10_000 {
            if await predicate() { return }
            await Task.yield()
        }
        XCTFail("condition was not reached", file: file, line: line)
    }
}
