#if canImport(NetworkExtension) && canImport(Tun2SocksKit)
@preconcurrency import Foundation
import IPadProxyCore
import NetworkExtension
import Tun2SocksKit

public enum HEVPacketStackAdapterError: Error, Equatable, Sendable {
    case invalidState
    case invalidSOCKSPort
    case immediateExit(Int32)
    case unexpectedRuntimeExit(Int32)
    case exitWaitTimedOut
}

/// Packet-stack adapter for v0.2.5. Tun2SocksKit reconstructs TCP streams and
/// forwards UDP through the loopback SOCKS5 UDP relay. DNS is intercepted at
/// the configured Fake DNS addresses before managed target routing.
@MainActor
public final class HEVPacketStackAdapter: PacketStackAdapter, TunnelDiagnosticsSource {
    public typealias FatalErrorHandler = @MainActor @Sendable (HEVPacketStackAdapterError) -> Void
    public static let exitWaitTimeoutNanoseconds: UInt64 = 5_000_000_000

    private enum State {
        case idle
        case starting(UUID)
        case running(UUID)
        case stopping(UUID)
        case stopped
    }

    private let bridge: LocalSOCKS5TCPBridge
    private let coordinator: ManagedFlowCoordinator
    private let diagnostics: TunnelDiagnostics
    private let fatalErrorHandler: FatalErrorHandler

    // Strong ownership for the complete generation. Do not reduce these to local
    // makeDependencies variables: flow wrappers and callbacks outlive that call.
    private let ruleStore: RuleStore
    private let fakeIPStore: FakeIPStore
    private let limiter: FlowLimiter
    private let directTransport: NetworkFrameworkDirectTransport
    private let proxyTransport: NetworkFrameworkTLSTransport
    private let credentials: KeychainCredentialStore

    private var state: State = .idle
    private var exitGate: HEVExitGate?
    private var stopTask: Task<Bool, Never>?
    private var didReportFatalError = false
    public private(set) var terminalError: HEVPacketStackAdapterError?

    public init(
        bridge: LocalSOCKS5TCPBridge,
        coordinator: ManagedFlowCoordinator,
        diagnostics: TunnelDiagnostics,
        ruleStore: RuleStore,
        fakeIPStore: FakeIPStore,
        limiter: FlowLimiter,
        directTransport: NetworkFrameworkDirectTransport,
        proxyTransport: NetworkFrameworkTLSTransport,
        credentials: KeychainCredentialStore,
        fatalErrorHandler: @escaping FatalErrorHandler
    ) {
        self.bridge = bridge
        self.coordinator = coordinator
        self.diagnostics = diagnostics
        self.ruleStore = ruleStore
        self.fakeIPStore = fakeIPStore
        self.limiter = limiter
        self.directTransport = directTransport
        self.proxyTransport = proxyTransport
        self.credentials = credentials
        self.fatalErrorHandler = fatalErrorHandler
    }

    public func start(packetFlow: NEPacketTunnelFlow) async throws {
        guard case .idle = state else { throw HEVPacketStackAdapterError.invalidState }
        _ = packetFlow // Tun2SocksKit 5.16.0 locates the active utun descriptor internally.

        let generation = UUID()
        state = .starting(generation)
        let port: UInt16
        do {
            port = try await bridge.start()
        } catch {
            await diagnostics.recordTransportFailure()
            await diagnostics.recordTerminalError(.bridge)
            if case let .starting(activeGeneration) = state, activeGeneration == generation {
                state = .stopped
            }
            throw error
        }

        // stop() can run while bridge.start() is suspended. Never start HEV after
        // that stop has already begun or completed.
        guard case let .starting(activeGeneration) = state,
              activeGeneration == generation
        else {
            await bridge.stop()
            throw CancellationError()
        }
        guard port != 0 else {
            await bridge.stop()
            await diagnostics.recordTransportFailure()
            await diagnostics.recordTerminalError(.bridge)
            state = .stopped
            throw HEVPacketStackAdapterError.invalidSOCKSPort
        }

        let gate = HEVExitGate()
        exitGate = gate
        let config = Self.configuration(socksPort: port)
        Socks5Tunnel.run(withConfig: .string(content: config)) { [weak self, gate] code in
            gate.complete(code)
            Task { @MainActor [weak self] in
                await self?.handleCompletion(code: code, generation: generation)
            }
        }

        // The wrapper has no positive readiness callback. This grace interval only
        // detects synchronous/early exits; physical-device readiness is a release gate.
        try await Task.sleep(nanoseconds: 150_000_000)
        try Task.checkCancellation()
        if let code = gate.completedCode {
            await bridge.stop()
            await coordinator.closeAll()
            let error = HEVPacketStackAdapterError.immediateExit(code)
            terminalError = error
            await diagnostics.recordTransportFailure()
            await diagnostics.recordTerminalError(.hevImmediateExit)
            state = .stopped
            exitGate = nil
            throw error
        }
        guard case let .starting(runningGeneration) = state,
              runningGeneration == generation
        else {
            await stop()
            throw CancellationError()
        }
        state = .running(generation)
    }

    public func stop() async {
        if let stopTask {
            _ = await stopTask.value
            return
        }
        switch state {
        case .idle:
            await bridge.stop()
            await coordinator.closeAll()
            state = .stopped
            return
        case .stopped:
            return
        case let .starting(generation), let .running(generation), let .stopping(generation):
            state = .stopping(generation)
        }

        let gate = exitGate
        let bridge = bridge
        let coordinator = coordinator
        Socks5Tunnel.quit()
        let task = Task { @MainActor in
            let timedOut: Bool
            if let gate {
                timedOut = await gate.wait(
                    timeoutNanoseconds: Self.exitWaitTimeoutNanoseconds
                ) == nil
            } else {
                timedOut = false
            }
            // Cleanup is mandatory even when the HEV completion never arrives.
            await bridge.stop()
            await coordinator.closeAll()
            return timedOut
        }
        stopTask = task
        let timedOut = await task.value
        exitGate = nil
        stopTask = nil
        state = .stopped

        if timedOut {
            let error = HEVPacketStackAdapterError.exitWaitTimedOut
            terminalError = error
            await diagnostics.recordTransportFailure()
            await diagnostics.recordTerminalError(.hevStopTimeout)
            reportFatalError(error)
        }
    }

    /// Combines the event-owned core snapshot with live coordinator/limiter
    /// gauges. Core counters remain authoritative, so reset cannot resurrect
    /// lifetime limiter totals or double-count managed-flow events.
    public func diagnosticsSnapshot() async -> TunnelDiagnosticsSnapshot {
        let core = await diagnostics.snapshot
        let managed = await coordinator.snapshot
        let limits = await limiter.snapshot
        let liveTotal = max(0, min(managed.active, limits.active))
        let liveUDP = max(0, min(limits.activeUDP, liveTotal))
        let liveTCP = max(0, liveTotal - liveUDP)
        let activeTCP = max(core.activeTCP, UInt64(liveTCP))
        let activeUDP = max(core.activeUDP, UInt64(liveUDP))

        // Tun2SocksKit 5.16.0 exposes no stable Socks5Tunnel statistics API.
        // HEV counters are therefore not guessed or merged into core counters.
        return TunnelDiagnosticsSnapshot(
            timestamp: core.timestamp,
            uptime: core.uptime,
            activeTCP: activeTCP,
            highWaterTCP: max(core.highWaterTCP, activeTCP),
            activeUDP: activeUDP,
            highWaterUDP: max(core.highWaterUDP, activeUDP),
            bytesUp: core.bytesUp,
            bytesDown: core.bytesDown,
            packetsUp: core.packetsUp,
            packetsDown: core.packetsDown,
            dnsTotal: core.dnsTotal,
            dnsFailures: core.dnsFailures,
            rejectedFlows: core.rejectedFlows,
            resourceRejections: core.resourceRejections,
            transportFailures: core.transportFailures,
            lastTerminalErrorCategory: core.lastTerminalErrorCategory
        )
    }

    public func resetDiagnostics() async -> TunnelDiagnosticsSnapshot {
        _ = await diagnostics.resetDiagnostics()
        return await diagnosticsSnapshot()
    }

    private func handleCompletion(code: Int32, generation: UUID) async {
        switch state {
        case let .starting(activeGeneration) where activeGeneration == generation:
            // start() observes the gate and reports immediateExit.
            return
        case let .running(activeGeneration) where activeGeneration == generation:
            state = .stopping(generation)
            await bridge.stop()
            await coordinator.closeAll()
            exitGate = nil
            state = .stopped
            let error = HEVPacketStackAdapterError.unexpectedRuntimeExit(code)
            terminalError = error
            await diagnostics.recordTransportFailure()
            await diagnostics.recordTerminalError(.hevRuntimeExit)
            reportFatalError(error)
        case .stopping, .idle, .stopped, .starting, .running:
            // Completion caused by a normal stop is expected and never fatal.
            return
        }
    }

    private func reportFatalError(_ error: HEVPacketStackAdapterError) {
        guard !didReportFatalError else { return }
        didReportFatalError = true
        fatalErrorHandler(error)
    }

    private static func configuration(socksPort: UInt16) -> String {
        // HEV uses RFC 1928 UDP ASSOCIATE and the BND endpoint returned by the
        // loopback bridge. This string contains no relay endpoint, App Group path,
        // DNS target, or token.
        """
        tunnel:
          mtu: 1280

        socks5:
          address: 127.0.0.1
          port: \(socksPort)
          udp: 'udp'

        misc:
          task-stack-size: 24576
          tcp-buffer-size: 32768
          max-session-count: 1024
          connect-timeout: 5000
          read-write-timeout: 60000
          log-file: stderr
          log-level: error
        """
    }
}

private final class HEVExitGate: @unchecked Sendable {
    private let lock = NSLock()
    private var code: Int32?
    private var waiters: [UUID: CheckedContinuation<Int32?, Never>] = [:]

    var completedCode: Int32? {
        lock.lock()
        defer { lock.unlock() }
        return code
    }

    func complete(_ code: Int32) {
        lock.lock()
        guard self.code == nil else {
            lock.unlock()
            return
        }
        self.code = code
        let continuations = Array(waiters.values)
        waiters.removeAll()
        lock.unlock()
        continuations.forEach { $0.resume(returning: code) }
    }

    func wait(timeoutNanoseconds: UInt64) async -> Int32? {
        if let completedCode { return completedCode }
        let id = UUID()
        return await withCheckedContinuation { continuation in
            lock.lock()
            if let code {
                lock.unlock()
                continuation.resume(returning: code)
                return
            }
            waiters[id] = continuation
            lock.unlock()

            Task { [weak self] in
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                self?.timeout(id: id)
            }
        }
    }

    private func timeout(id: UUID) {
        lock.lock()
        let continuation = waiters.removeValue(forKey: id)
        lock.unlock()
        continuation?.resume(returning: nil)
    }
}
#endif
