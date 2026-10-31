#if canImport(Network)
@preconcurrency import Foundation
import IPadProxyCore
@preconcurrency import Network

public enum LocalSOCKS5UDPRelayError: Error, Equatable, Sendable {
    case invalidState
    case invalidControlEndpoint
    case listenerFailed
    case listenerStopped
    case invalidListenerPort
    case unexpectedEOF
}

/// Loopback-only SOCKS5 UDP relay shared by local UDP ASSOCIATE controls.
/// Invalid datagrams are dropped. Routing remains fixed for each target session.
@MainActor
public final class LocalSOCKS5UDPRelay {
    public typealias FatalErrorHandler = @MainActor @Sendable (LocalSOCKS5UDPRelayError) -> Void
    public static let maximumPeers = 256
    public static let maximumTargetSessions = 256
    public static let idleTimeoutNanoseconds: UInt64 = 60_000_000_000
    private static let sweepIntervalNanoseconds: UInt64 = 5_000_000_000

    public struct ControlAssociation: Equatable, Sendable {
        public let port: UInt16
        fileprivate let id: UUID
    }

    private enum State {
        case idle
        case starting
        case ready(UInt16)
        case stopping
        case stopped
    }

    private struct ControlState {
        let requestedClient: Address
        var boundSourcePort: UInt16?
    }

    private struct TargetKey: Hashable, Sendable {
        let kind: UInt8
        let value: String
        let port: UInt16

        init(_ address: Address) {
            switch address.kind {
            case .ipv4:
                kind = 1
                value = (address.ipBytes ?? []).map(String.init).joined(separator: ".")
            case .ipv6:
                kind = 4
                value = (address.ipBytes ?? []).map { String(format: "%02x", $0) }.joined()
            case .domain:
                kind = 3
                value = address.domain ?? ""
            }
            port = address.port
        }
    }

    private struct SessionKey: Hashable, Sendable {
        let peerID: UUID
        let target: TargetKey
    }

    private struct PeerState {
        let controlID: UUID
        let connection: NWConnection
        let task: Task<Void, Never>
        var lastActivity: UInt64
    }

    private struct TargetSession {
        let target: Address
        let association: ManagedUDPAssociation
        let responseTask: Task<Void, Never>
        var lastActivity: UInt64
    }

    private let coordinator: ManagedFlowCoordinator
    private let dnsService: DNSProxyService
    private let diagnostics: TunnelDiagnostics?
    private let fatalErrorHandler: FatalErrorHandler
    private let queue = DispatchQueue(label: "ipad-proxy.local-socks5-udp")
    private var state: State = .idle
    private var listener: NWListener?
    private var startTask: Task<UInt16, Error>?
    private var controls: [UUID: ControlState] = [:]
    private var hasPendingWildcardControl = false
    private var pendingControlPorts: Set<UInt16> = []
    private var peers: [UUID: PeerState] = [:]
    private var sessions: [SessionKey: TargetSession] = [:]
    private var pendingTargetSessions: Set<SessionKey> = []
    private var sweepTask: Task<Void, Never>?
    private var stopTask: Task<Void, Never>?
    private var didReportFatalError = false

    public init(
        coordinator: ManagedFlowCoordinator,
        dnsService: DNSProxyService,
        diagnostics: TunnelDiagnostics? = nil,
        fatalErrorHandler: @escaping FatalErrorHandler
    ) {
        self.coordinator = coordinator
        self.dnsService = dnsService
        self.diagnostics = diagnostics
        self.fatalErrorHandler = fatalErrorHandler
    }

    /// Creates one control-owned association while reusing one loopback listener.
    public func beginAssociation(requestedClient: Address) async throws -> ControlAssociation {
        guard Self.isValidControlEndpoint(requestedClient) else {
            await diagnostics?.recordRejectedFlow()
            throw LocalSOCKS5UDPRelayError.invalidControlEndpoint
        }
        let isWildcard = requestedClient.port == 0
        if isWildcard {
            guard !hasPendingWildcardControl,
                  !controls.values.contains(where: { $0.requestedClient.port == 0 })
            else {
                await diagnostics?.recordResourceRejection()
                throw LocalSOCKS5UDPRelayError.invalidState
            }
            hasPendingWildcardControl = true
        } else {
            guard !pendingControlPorts.contains(requestedClient.port),
                  !controls.values.contains(where: {
                      $0.requestedClient.port == requestedClient.port
                  })
            else {
                await diagnostics?.recordResourceRejection()
                throw LocalSOCKS5UDPRelayError.invalidState
            }
            pendingControlPorts.insert(requestedClient.port)
        }
        do {
            let port = try await start()
            try Task.checkCancellation()
            if isWildcard {
                hasPendingWildcardControl = false
            } else {
                pendingControlPorts.remove(requestedClient.port)
            }
            let id = UUID()
            controls[id] = ControlState(requestedClient: requestedClient, boundSourcePort: nil)
            return ControlAssociation(port: port, id: id)
        } catch {
            if isWildcard {
                hasPendingWildcardControl = false
            } else {
                pendingControlPorts.remove(requestedClient.port)
            }
            throw error
        }
    }

    /// Ends one UDP ASSOCIATE control and closes every peer and target it owns.
    public func endAssociation(_ association: ControlAssociation) async {
        guard controls.removeValue(forKey: association.id) != nil else { return }
        let peerIDs = peers.compactMap { id, peer in
            peer.controlID == association.id ? id : nil
        }
        for id in peerIDs { await removePeer(id) }
    }

    /// Starts once. Concurrent callers await the same listener startup operation.
    private func start() async throws -> UInt16 {
        if case let .ready(port) = state { return port }
        if let startTask { return try await startTask.value }
        guard case .idle = state else { throw LocalSOCKS5UDPRelayError.invalidState }

        let task = Task { @MainActor [weak self] () throws -> UInt16 in
            guard let self else { throw CancellationError() }
            return try await startListener()
        }
        startTask = task
        do {
            let port = try await task.value
            startTask = nil
            return port
        } catch {
            startTask = nil
            throw error
        }
    }

    private func startListener() async throws -> UInt16 {
        state = .starting
        let parameters = NWParameters.udp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let newListener: NWListener
        do {
            newListener = try NWListener(using: parameters, on: .any)
        } catch {
            state = .stopped
            throw LocalSOCKS5UDPRelayError.listenerFailed
        }
        listener = newListener
        newListener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in self?.accept(connection) }
        }

        do {
            let port: UInt16 = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let once = UDPRelayContinuationOnce<UInt16>(continuation)
                    newListener.stateUpdateHandler = { [weak self] listenerState in
                        switch listenerState {
                        case .ready:
                            guard let port = newListener.port?.rawValue, port != 0 else {
                                once.resume(throwing: LocalSOCKS5UDPRelayError.invalidListenerPort)
                                return
                            }
                            once.resume(returning: port)
                        case .failed:
                            if once.resume(throwing: LocalSOCKS5UDPRelayError.listenerFailed) {
                                return
                            }
                            Task { @MainActor in self?.listenerFailedAfterReady() }
                        case .cancelled:
                            if once.resume(throwing: LocalSOCKS5UDPRelayError.listenerStopped) {
                                return
                            }
                            Task { @MainActor in self?.listenerFailedAfterReady() }
                        default:
                            break
                        }
                    }
                    newListener.start(queue: queue)
                }
            } onCancel: {
                newListener.cancel()
            }
            try Task.checkCancellation()
            guard case .starting = state else { throw CancellationError() }
            state = .ready(port)
            startIdleSweep()
            return port
        } catch {
            newListener.stateUpdateHandler = nil
            newListener.newConnectionHandler = nil
            newListener.cancel()
            listener = nil
            state = .stopped
            throw error
        }
    }

    public func stop() async {
        if let stopTask {
            await stopTask.value
            return
        }
        if case .stopped = state { return }
        state = .stopping
        startTask?.cancel()
        let listener = listener
        self.listener = nil
        listener?.newConnectionHandler = nil
        listener?.stateUpdateHandler = nil
        listener?.cancel()
        sweepTask?.cancel()

        let peerStates = Array(peers.values)
        let targetSessions = Array(sessions.values)
        peerStates.forEach {
            $0.task.cancel()
            $0.connection.cancel()
        }
        targetSessions.forEach { $0.responseTask.cancel() }
        let coordinator = coordinator
        let task = Task { @MainActor in
            for peer in peerStates { await peer.task.value }
            for session in targetSessions {
                await session.association.close()
                await session.responseTask.value
            }
            await coordinator.closeAll()
        }
        stopTask = task
        await task.value
        controls.removeAll()
        hasPendingWildcardControl = false
        pendingControlPorts.removeAll()
        peers.removeAll()
        sessions.removeAll()
        pendingTargetSessions.removeAll()
        sweepTask = nil
        startTask = nil
        state = .stopped
        stopTask = nil
    }

    private func listenerFailedAfterReady() {
        guard case .ready = state, !didReportFatalError else { return }
        didReportFatalError = true
        let handler = fatalErrorHandler
        Task { @MainActor [weak self] in
            await self?.stop()
            handler(.listenerFailed)
        }
    }

    private func accept(_ connection: NWConnection) {
        guard case .ready = state else {
            connection.cancel()
            return
        }
        guard peers.count < Self.maximumPeers else {
            Task { await diagnostics?.recordResourceRejection() }
            connection.cancel()
            return
        }
        guard let controlID = matchingControl(for: connection.endpoint) else {
            Task { await diagnostics?.recordRejectedFlow() }
            connection.cancel()
            return
        }
        let id = UUID()
        let task = Task { @MainActor [weak self] in
            guard let self else {
                connection.cancel()
                return
            }
            await runPeer(id: id, connection: connection)
            await peerDidFinish(id: id)
        }
        peers[id] = PeerState(
            controlID: controlID,
            connection: connection,
            task: task,
            lastActivity: Self.now
        )
    }

    private func runPeer(id: UUID, connection: NWConnection) async {
        defer { connection.cancel() }
        do {
            try await start(connection)
            while !Task.isCancelled {
                guard let packet = try await receiveDatagram(from: connection) else { break }
                guard let datagram = try? SOCKS5UDPDatagramCodec.decode(packet) else {
                    await diagnostics?.recordRejectedFlow()
                    continue
                }
                touchPeer(id)
                if Self.isFakeDNS(datagram.target) {
                    do {
                        let response = try await dnsService.handleUDPQuery(datagram.payload)
                        let wire = try SOCKS5UDPDatagramCodec.encode(
                            SOCKS5UDPDatagram(target: datagram.target, payload: response)
                        )
                        try await send(wire, on: connection)
                        touchPeer(id)
                    } catch {
                        // DNS errors are local to this datagram. Never change action or target.
                    }
                    continue
                }

                let key = SessionKey(peerID: id, target: TargetKey(datagram.target))
                let association: ManagedUDPAssociation
                if var existing = sessions[key] {
                    existing.lastActivity = Self.now
                    sessions[key] = existing
                    association = existing.association
                } else {
                    guard sessions.count + pendingTargetSessions.count < Self.maximumTargetSessions,
                          pendingTargetSessions.insert(key).inserted
                    else {
                        await diagnostics?.recordResourceRejection()
                        continue
                    }
                    do {
                        association = try await coordinator.openUDP(to: datagram.target)
                    } catch {
                        pendingTargetSessions.remove(key)
                        continue
                    }
                    guard pendingTargetSessions.remove(key) != nil,
                          peers[id] != nil
                    else {
                        await association.close()
                        continue
                    }
                    let target = datagram.target
                    let responseTask = Task { @MainActor [weak self, weak connection] in
                        guard let self, let connection else { return }
                        await receiveResponses(
                            for: key,
                            target: target,
                            association: association,
                            connection: connection
                        )
                    }
                    sessions[key] = TargetSession(
                        target: target,
                        association: association,
                        responseTask: responseTask,
                        lastActivity: Self.now
                    )
                }
                do {
                    try await association.send(datagram.payload)
                    touch(key)
                } catch {
                    await removeSession(key)
                }
            }
        } catch {
            if !Task.isCancelled {
                await diagnostics?.recordTransportFailure()
            }
            // Peer errors are intentionally not logged because endpoint data is sensitive.
        }
    }

    private func receiveResponses(
        for key: SessionKey,
        target: Address,
        association: ManagedUDPAssociation,
        connection: NWConnection
    ) async {
        do {
            while let payload = try await association.receive() {
                let wire = try SOCKS5UDPDatagramCodec.encode(
                    SOCKS5UDPDatagram(target: target, payload: payload)
                )
                try await send(wire, on: connection)
                touch(key)
                touchPeer(key.peerID)
            }
        } catch {
            // Closing one target session must not affect other fixed-target sessions.
        }
        await removeSession(key, cancellingResponseTask: false)
    }

    private func peerDidFinish(id: UUID) async {
        guard let peer = peers.removeValue(forKey: id) else { return }
        peer.connection.cancel()
        let keys = sessions.keys.filter { $0.peerID == id }
        for key in keys { await removeSession(key) }
    }

    private func removePeer(_ id: UUID) async {
        guard let peer = peers.removeValue(forKey: id) else { return }
        peer.task.cancel()
        peer.connection.cancel()
        let keys = sessions.keys.filter { $0.peerID == id }
        for key in keys { await removeSession(key) }
        await peer.task.value
    }

    private func touchPeer(_ id: UUID) {
        guard var peer = peers[id] else { return }
        peer.lastActivity = Self.now
        peers[id] = peer
    }

    private func touch(_ key: SessionKey) {
        guard var session = sessions[key] else { return }
        session.lastActivity = Self.now
        sessions[key] = session
    }

    private func removeSession(_ key: SessionKey, cancellingResponseTask: Bool = true) async {
        guard let session = sessions.removeValue(forKey: key) else { return }
        if cancellingResponseTask { session.responseTask.cancel() }
        await session.association.close()
        if cancellingResponseTask { await session.responseTask.value }
    }

    private func startIdleSweep() {
        sweepTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.sweepIntervalNanoseconds)
                guard !Task.isCancelled, let self else { return }
                let now = Self.now
                let expiredPeers = peers.compactMap { id, peer in
                    now &- peer.lastActivity >= Self.idleTimeoutNanoseconds ? id : nil
                }
                for id in expiredPeers { await removePeer(id) }
                let expiredSessions = sessions.compactMap { key, session in
                    now &- session.lastActivity >= Self.idleTimeoutNanoseconds ? key : nil
                }
                for key in expiredSessions { await removeSession(key) }
            }
        }
    }

    private func matchingControl(for endpoint: NWEndpoint) -> UUID? {
        guard case let .hostPort(_, sourcePort) = endpoint else { return nil }
        let rawPort = sourcePort.rawValue

        // A declared source port takes precedence over the one allowed wildcard.
        if let id = controls.first(where: { id, control in
            control.requestedClient.port == rawPort
                && (control.boundSourcePort == nil || control.boundSourcePort == rawPort)
                && peerCount(for: id) == 0
        })?.key {
            controls[id]?.boundSourcePort = rawPort
            return id
        }

        guard let id = controls.first(where: { id, control in
            control.requestedClient.port == 0
                && control.boundSourcePort == nil
                && peerCount(for: id) == 0
        })?.key else { return nil }
        controls[id]?.boundSourcePort = rawPort
        return id
    }

    private func peerCount(for controlID: UUID) -> Int {
        peers.values.reduce(into: 0) { count, peer in
            if peer.controlID == controlID { count += 1 }
        }
    }

    private func start(_ connection: NWConnection) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = UDPRelayContinuationOnce<Void>(continuation)
                connection.stateUpdateHandler = { connectionState in
                    switch connectionState {
                    case .ready:
                        _ = once.resume(returning: ())
                    case .failed, .cancelled:
                        _ = once.resume(throwing: LocalSOCKS5UDPRelayError.listenerFailed)
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
        connection.stateUpdateHandler = nil
    }

    private func receiveDatagram(from connection: NWConnection) async throws -> Data? {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = UDPRelayContinuationOnce<Data?>(continuation)
                connection.receiveMessage { data, _, complete, error in
                    if let error { _ = once.resume(throwing: error) }
                    else if let data { _ = once.resume(returning: data) }
                    else if complete { _ = once.resume(returning: nil) }
                    else { _ = once.resume(throwing: LocalSOCKS5UDPRelayError.unexpectedEOF) }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private func send(_ data: Data, on connection: NWConnection) async throws {
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = UDPRelayContinuationOnce<Void>(continuation)
                connection.send(
                    content: data,
                    contentContext: .defaultMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if let error { _ = once.resume(throwing: error) }
                        else { _ = once.resume(returning: ()) }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func isValidControlEndpoint(_ address: Address) -> Bool {
        guard address.kind == .ipv4 || address.kind == .ipv6,
              let bytes = address.ipBytes
        else { return false }
        if address.port == 0 { return bytes.allSatisfy { $0 == 0 } }
        switch address.kind {
        case .ipv4:
            return bytes == [0, 0, 0, 0] || bytes == [127, 0, 0, 1]
        case .ipv6:
            // The relay is deliberately bound to IPv4 loopback, so only the
            // unspecified IPv6 form is accepted as a wildcard control request.
            return bytes.allSatisfy { $0 == 0 }
        case .domain:
            return false
        }
    }

    private static func isFakeDNS(_ address: Address) -> Bool {
        guard address.port == 53, let bytes = address.ipBytes else { return false }
        switch address.kind {
        case .ipv4:
            return bytes == [198, 18, 0, 2]
        case .ipv6:
            return bytes == [0xfd, 0x00, 0x01, 0x98, 0x00, 0x18, 0x00, 0x02,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        case .domain:
            return false
        }
    }

    private static var now: UInt64 { DispatchTime.now().uptimeNanoseconds }
}

private final class UDPRelayContinuationOnce<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    @discardableResult
    func resume(returning value: Value) -> Bool {
        guard let continuation = take() else { return false }
        continuation.resume(returning: value)
        return true
    }

    @discardableResult
    func resume(throwing error: Error) -> Bool {
        guard let continuation = take() else { return false }
        continuation.resume(throwing: error)
        return true
    }

    private func take() -> CheckedContinuation<Value, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let value = continuation
        continuation = nil
        return value
    }
}
#endif
