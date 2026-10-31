#if canImport(NetworkExtension)
import Foundation
import IPadProxyCore
import NetworkExtension

/// Adapter boundary for a reviewed user-space TCP/IP stack. `start` may begin reading
/// packets only after the provider has successfully installed network settings.
/// `stop` must be idempotent and cancel packet reads, per-flow tasks, sockets, and timers.
@MainActor
protocol PacketStackAdapter: AnyObject {
    func start(packetFlow: NEPacketTunnelFlow) async throws
    func stop() async
}

@MainActor
struct PacketTunnelDependencies {
    let packetStack: any PacketStackAdapter
    let networkSettings: NEPacketTunnelNetworkSettings
    let diagnostics: TunnelDiagnostics
    let diagnosticsSource: any TunnelDiagnosticsSource
}

/// Fail-closed lifecycle template. A containing extension must override
/// `makeDependencies()` with the reviewed packet stack and configured core.
class PacketTunnelProvider: NEPacketTunnelProvider {
    enum IntegrationError: LocalizedError {
        case missingDependencies
        case invalidLifecycleState

        var errorDescription: String? {
            switch self {
            case .missingDependencies:
                "Packet Tunnel dependencies are missing; no packets were accepted or forwarded."
            case .invalidLifecycleState:
                "Packet Tunnel is already starting, running, or stopping."
            }
        }
    }

    @MainActor
    private enum LifecycleState: Equatable {
        case stopped
        case starting
        case running
        case stopping
    }

    @MainActor private var state: LifecycleState = .stopped
    @MainActor private var generation: UInt64 = 0
    @MainActor private var startTask: Task<Void, Never>?
    @MainActor private var stopTask: Task<Void, Never>?
    @MainActor private var packetStack: (any PacketStackAdapter)?
    @MainActor private var diagnostics: TunnelDiagnostics?
    @MainActor private var diagnosticsSource: (any TunnelDiagnosticsSource)?

    @MainActor
    func makeDependencies() async throws -> PacketTunnelDependencies {
        // A containing extension must assemble and validate every runtime dependency.
        throw IntegrationError.missingDependencies
    }

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let completion = ErrorCompletionOnce(completionHandler)
        Task { @MainActor [weak self] in
            guard let self else {
                completion.call(IntegrationError.missingDependencies)
                return
            }
            beginStart(completion: completion)
        }
    }

    @MainActor
    private func beginStart(completion: ErrorCompletionOnce) {
        guard state == .stopped, startTask == nil, stopTask == nil, packetStack == nil else {
            completion.call(IntegrationError.invalidLifecycleState)
            return
        }

        generation &+= 1
        let currentGeneration = generation
        state = .starting
        startTask = Task { @MainActor [weak self] in
            guard let self else {
                completion.call(IntegrationError.missingDependencies)
                return
            }
            var localStack: (any PacketStackAdapter)?
            do {
                try Task.checkCancellation()
                let dependencies = try await makeDependencies()
                try Task.checkCancellation()
                localStack = dependencies.packetStack
                guard generation == currentGeneration, state == .starting else {
                    throw CancellationError()
                }
                packetStack = dependencies.packetStack
                diagnostics = dependencies.diagnostics
                diagnosticsSource = dependencies.diagnosticsSource
                await dependencies.diagnostics.recordTunnelStarted()

                // No packet read may begin before these settings are active.
                do {
                    try await install(dependencies.networkSettings)
                } catch {
                    await dependencies.diagnostics.recordTerminalError(.networkSettings)
                    throw error
                }
                try Task.checkCancellation()
                guard generation == currentGeneration, state == .starting else {
                    throw CancellationError()
                }

                try await dependencies.packetStack.start(packetFlow: packetFlow)
                try Task.checkCancellation()
                guard generation == currentGeneration, state == .starting else {
                    throw CancellationError()
                }

                state = .running
                startTask = nil
                completion.call(nil)
            } catch {
                if let localStack { await localStack.stop() }
                if !(error is CancellationError), let diagnostics {
                    let current = await diagnostics.snapshot
                    if current.lastTerminalErrorCategory == nil {
                        await diagnostics.recordTerminalError(.providerStartup)
                    }
                }
                if generation == currentGeneration {
                    packetStack = nil
                    startTask = nil
                    if state != .stopping { state = .stopped }
                }
                completion.call(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        let completion = VoidCompletionOnce(completionHandler)
        Task { @MainActor [weak self] in
            guard let self else {
                completion.call()
                return
            }
            beginStop(completion: completion)
        }
    }

    @MainActor
    private func beginStop(completion: VoidCompletionOnce) {
        if state == .stopped {
            completion.call()
            return
        }
        if state == .stopping, let existing = stopTask {
            Task { @MainActor in
                await existing.value
                completion.call()
            }
            return
        }

        state = .stopping
        let currentGeneration = generation
        let pendingStart = startTask
        pendingStart?.cancel()

        let task = Task { @MainActor [weak self] in
            guard let self else {
                completion.call()
                return
            }
            if let pendingStart { await pendingStart.value }
            if let stack = packetStack { await stack.stop() }
            await diagnostics?.recordTunnelStopped()

            if generation == currentGeneration {
                packetStack = nil
                startTask = nil
                state = .stopped
                stopTask = nil
            }
            // Publish the terminal state before invoking external code.
            completion.call()
        }
        stopTask = task
    }

    @MainActor
    private func install(_ settings: NEPacketTunnelNetworkSettings) async throws {
        try await withCheckedThrowingContinuation { continuation in
            setTunnelNetworkSettings(settings) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        let completion = OptionalDataCompletionOnce(completionHandler)
        Task { @MainActor [weak self] in
            guard let self else {
                completion.call(Self.encodeProviderResponse(.failure(.unavailable)))
                return
            }
            let response: TunnelDiagnosticsResponse
            do {
                let request = try TunnelDiagnosticsMessageCodec.decodeRequest(messageData)
                guard let source = diagnosticsSource else {
                    response = .failure(.unavailable)
                    completion.call(Self.encodeProviderResponse(response))
                    return
                }
                switch request.operation {
                case .snapshot:
                    response = .success(await source.diagnosticsSnapshot())
                case .reset:
                    response = .success(await source.resetDiagnostics())
                }
            } catch TunnelDiagnosticsCodecError.messageTooLarge {
                response = .failure(.messageTooLarge)
            } catch TunnelDiagnosticsCodecError.unsupportedVersion {
                response = .failure(.unsupportedVersion)
            } catch {
                response = .failure(.invalidRequest)
            }
            completion.call(Self.encodeProviderResponse(response))
        }
    }

    private static func encodeProviderResponse(_ response: TunnelDiagnosticsResponse) -> Data {
        (try? TunnelDiagnosticsMessageCodec.encodeResponse(response))
            ?? Data(#"{"error":"encodingFailure","version":1}"#.utf8)
    }

    /// Conservative settings matching the core Fake IP defaults. Fake DNS is
    /// advertised only when a DNS packet service is actually installed.
    @MainActor
    static func defaultNetworkSettings(
        remoteAddress: String,
        installFakeDNS: Bool
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.254.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fd00:198:18:2::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        if installFakeDNS {
            let dns = NEDNSSettings(servers: ["198.18.0.2", "fd00:198:18:2::2"])
            dns.matchDomains = [""]
            settings.dnsSettings = dns
        }
        settings.mtu = 1_280
        return settings
    }
}

private final class OptionalDataCompletionOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Data?) -> Void)?

    init(_ completion: ((Data?) -> Void)?) { self.completion = completion }

    func call(_ data: Data?) {
        lock.lock()
        let value = completion
        completion = nil
        lock.unlock()
        value?(data)
    }
}

private final class ErrorCompletionOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Error?) -> Void)?

    init(_ completion: @escaping (Error?) -> Void) { self.completion = completion }

    func call(_ error: Error?) {
        lock.lock()
        let value = completion
        completion = nil
        lock.unlock()
        value?(error)
    }
}

private final class VoidCompletionOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: (() -> Void)?

    init(_ completion: @escaping () -> Void) { self.completion = completion }

    func call() {
        lock.lock()
        let value = completion
        completion = nil
        lock.unlock()
        value?()
    }
}
#endif
