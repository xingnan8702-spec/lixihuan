import Foundation

public protocol TunnelLifecycleRuntime: Sendable {
    /// Startup methods must observe task cancellation. Cleanup methods must be
    /// idempotent; `close()` must also observe cancellation so a timed-out
    /// cleanup can be retried without overlapping an abandoned close forever.
    func prepare() async throws
    func activate() async throws
    func quiesce() async
    func close() async throws
}

public protocol TunnelLifecycleSleeper: Sendable {
    func sleep(for interval: TimeInterval) async throws
}

public struct SystemTunnelLifecycleSleeper: TunnelLifecycleSleeper {
    public init() {}

    public func sleep(for interval: TimeInterval) async throws {
        let nanoseconds = interval * 1_000_000_000
        let bounded = min(nanoseconds, Double(UInt64.max))
        try await Task.sleep(nanoseconds: UInt64(bounded))
    }
}

public enum TunnelLifecycleState: Equatable, Sendable {
    case stopped
    case starting
    case running
    case stopping
    case failed
}

public enum TunnelLifecycleFailure: Equatable, Sendable {
    case startup(String)
    case fatal(String)
    case cleanup(String)
    case cleanupTimedOut
}

public enum TunnelLifecycleError: Error, Equatable, Sendable {
    case invalidConfiguration
    case alreadyStarting
    case alreadyRunning
    case stopping
    case residualResources
    case generationExhausted
    case startCancelled
    case startupFailed(String)
}

public struct TunnelLifecycleSnapshot: Equatable, Sendable {
    public let state: TunnelLifecycleState
    public let generation: UInt64
    public let failure: TunnelLifecycleFailure?
    public let hasResidualResources: Bool

    public init(
        state: TunnelLifecycleState,
        generation: UInt64,
        failure: TunnelLifecycleFailure?,
        hasResidualResources: Bool
    ) {
        self.state = state
        self.generation = generation
        self.failure = failure
        self.hasResidualResources = hasResidualResources
    }
}

/// Coordinates runtime startup and cleanup without depending on NetworkExtension.
///
/// Stop during startup cancels the startup task and waits for the same cleanup
/// gate used by startup rollback and fatal-error handling. A cleanup timeout or
/// cleanup error records residual resources and blocks the next generation until
/// a later `stop()` retry completes cleanup.
public actor TunnelLifecycleController {
    public struct Configuration: Equatable, Sendable {
        public let cleanupTimeout: TimeInterval

        public init(cleanupTimeout: TimeInterval = 5) throws {
            guard cleanupTimeout.isFinite, cleanupTimeout > 0 else {
                throw TunnelLifecycleError.invalidConfiguration
            }
            self.cleanupTimeout = cleanupTimeout
        }
    }

    private enum StartOutcome: Sendable {
        case activated
        case failed(String)
    }

    private enum CleanupOutcome: Sendable {
        case completed
        case failed(String)
        case timedOut
    }

    private enum CleanupIntent: Sendable {
        case stop
        case startupFailure(String)
        case fatal(String)
    }

    private let runtime: any TunnelLifecycleRuntime
    private let sleeper: any TunnelLifecycleSleeper
    private let configuration: Configuration
    private var state: TunnelLifecycleState = .stopped
    private var generation: UInt64 = 0
    private var failure: TunnelLifecycleFailure?
    private var hasResidualResources = false
    private var startTask: Task<StartOutcome, Never>?
    private var cleanupTask: Task<CleanupOutcome, Never>?
    private var cleanupIdentity: UUID?

    public init(
        runtime: any TunnelLifecycleRuntime,
        configuration: Configuration = try! Configuration(),
        sleeper: any TunnelLifecycleSleeper = SystemTunnelLifecycleSleeper()
    ) {
        self.runtime = runtime
        self.configuration = configuration
        self.sleeper = sleeper
    }

    /// Starts one generation and returns its generation number after activation.
    @discardableResult
    public func start() async throws -> UInt64 {
        switch state {
        case .starting:
            throw TunnelLifecycleError.alreadyStarting
        case .running:
            throw TunnelLifecycleError.alreadyRunning
        case .stopping:
            throw TunnelLifecycleError.stopping
        case .failed where hasResidualResources:
            throw TunnelLifecycleError.residualResources
        case .stopped, .failed:
            break
        }
        guard generation < UInt64.max else { throw TunnelLifecycleError.generationExhausted }

        generation += 1
        let requestedGeneration = generation
        state = .starting
        failure = nil
        hasResidualResources = false

        let runtime = self.runtime
        let task = Task<StartOutcome, Never> {
            do {
                try Task.checkCancellation()
                try await runtime.prepare()
                try Task.checkCancellation()
                try await runtime.activate()
                try Task.checkCancellation()
                return .activated
            } catch {
                return .failed(Self.describe(error))
            }
        }
        startTask = task
        let outcome = await task.value

        guard generation == requestedGeneration else {
            throw TunnelLifecycleError.startCancelled
        }
        if state == .stopping {
            if let cleanupTask { _ = await cleanupTask.value }
            throw TunnelLifecycleError.startCancelled
        }
        guard state == .starting else { throw TunnelLifecycleError.startCancelled }

        startTask = nil
        switch outcome {
        case .activated:
            state = .running
            return requestedGeneration
        case let .failed(message):
            state = .stopping
            let cleanup = beginCleanup(intent: .startupFailure(message), startTask: nil)
            _ = await cleanup.value
            throw TunnelLifecycleError.startupFailed(message)
        }
    }

    /// Idempotently stops the current generation. Concurrent callers share one
    /// cleanup task. A failed cleanup with residual resources may be retried by
    /// a later stop; restart remains blocked until that retry succeeds.
    public func stop() async {
        switch state {
        case .stopped:
            return
        case .stopping:
            if let cleanupTask { _ = await cleanupTask.value }
            return
        case .failed where !hasResidualResources:
            return
        case .starting, .running, .failed:
            state = .stopping
            let task = beginCleanup(intent: .stop, startTask: startTask)
            _ = await task.value
        }
    }

    /// Records a fatal runtime error and enters the shared cleanup gate.
    public func handleFatalError(_ error: any Error) async {
        let message = Self.describe(error)
        switch state {
        case .stopped, .failed:
            return
        case .stopping:
            if let cleanupTask { _ = await cleanupTask.value }
        case .starting, .running:
            state = .stopping
            let task = beginCleanup(intent: .fatal(message), startTask: startTask)
            _ = await task.value
        }
    }

    public var snapshot: TunnelLifecycleSnapshot {
        TunnelLifecycleSnapshot(
            state: state,
            generation: generation,
            failure: failure,
            hasResidualResources: hasResidualResources
        )
    }

    private func beginCleanup(
        intent: CleanupIntent,
        startTask taskBeingStopped: Task<StartOutcome, Never>?
    ) -> Task<CleanupOutcome, Never> {
        if let cleanupTask { return cleanupTask }

        taskBeingStopped?.cancel()
        let identity = UUID()
        cleanupIdentity = identity
        let runtime = self.runtime
        let sleeper = self.sleeper
        let timeout = configuration.cleanupTimeout
        let controller = self

        let task = Task<CleanupOutcome, Never> {
            let outcome = await Self.performCleanup(
                runtime: runtime,
                sleeper: sleeper,
                timeout: timeout,
                startTask: taskBeingStopped
            )
            await controller.completeCleanup(outcome, identity: identity, intent: intent)
            return outcome
        }
        cleanupTask = task
        return task
    }

    private func completeCleanup(
        _ outcome: CleanupOutcome,
        identity: UUID,
        intent: CleanupIntent
    ) {
        guard cleanupIdentity == identity else { return }
        cleanupTask = nil
        cleanupIdentity = nil
        startTask = nil

        switch outcome {
        case .completed:
            hasResidualResources = false
            switch intent {
            case .stop:
                state = .stopped
                failure = nil
            case let .startupFailure(message):
                state = .failed
                failure = .startup(message)
            case let .fatal(message):
                state = .failed
                failure = .fatal(message)
            }
        case let .failed(message):
            state = .failed
            hasResidualResources = true
            failure = .cleanup(message)
        case .timedOut:
            state = .failed
            hasResidualResources = true
            failure = .cleanupTimedOut
        }
    }

    private static func performCleanup(
        runtime: any TunnelLifecycleRuntime,
        sleeper: any TunnelLifecycleSleeper,
        timeout: TimeInterval,
        startTask: Task<StartOutcome, Never>?
    ) async -> CleanupOutcome {
        let gate = CleanupRaceGate<CleanupOutcome>()
        let cleanup = Task {
            if let startTask {
                startTask.cancel()
                _ = await startTask.value
            }
            await runtime.quiesce()
            do {
                try await runtime.close()
                await gate.publish(.completed)
            } catch {
                await gate.publish(.failed(describe(error)))
            }
        }
        let timer = Task {
            do {
                try await sleeper.sleep(for: timeout)
                try Task.checkCancellation()
                await gate.publish(.timedOut)
            } catch {
                // Cancellation means cleanup won the race.
            }
        }

        let outcome = await gate.wait()
        cleanup.cancel()
        timer.cancel()
        return outcome
    }

    private static func describe(_ error: any Error) -> String {
        String(describing: error)
    }
}

private actor CleanupRaceGate<Value: Sendable> {
    private var value: Value?
    private var continuation: CheckedContinuation<Value, Never>?

    func publish(_ value: Value) {
        guard self.value == nil else { return }
        self.value = value
        continuation?.resume(returning: value)
        continuation = nil
    }

    func wait() async -> Value {
        if let value { return value }
        return await withCheckedContinuation { continuation in
            if let value {
                continuation.resume(returning: value)
            } else {
                self.continuation = continuation
            }
        }
    }
}
