#if canImport(Network)
@preconcurrency import Foundation
import IPadProxyCore
@preconcurrency import Network

public enum LocalSOCKS5TCPBridgeError: Error, Sendable {
    case invalidState
    case listenerFailed
    case listenerStopped
    case invalidListenerPort
    case handshakeTooLarge
    case unexpectedEOF
    case protocolViolation
    case invalidDNSFrame
}

/// Loopback SOCKS5 bridge from Tun2SocksKit to the managed core.
/// CONNECT and UDP ASSOCIATE are dispatched without changing the selected action.
@MainActor
public final class LocalSOCKS5TCPBridge {
    public typealias FatalErrorHandler = @MainActor @Sendable (LocalSOCKS5TCPBridgeError) -> Void
    public static let pumpChunkBytes = 32 * 1_024
    public static let maximumSessions = 1_024

    private enum State {
        case idle
        case starting
        case ready(UInt16)
        case stopping
        case stopped
    }

    private let coordinator: ManagedFlowCoordinator
    private let dnsService: DNSProxyService
    private let udpRelay: LocalSOCKS5UDPRelay
    private let diagnostics: TunnelDiagnostics?
    private let fatalErrorHandler: FatalErrorHandler?
    private let queue = DispatchQueue(label: "ipad-proxy.local-socks5")
    private var state: State = .idle
    private var listener: NWListener?
    private var sessions: [UUID: Task<Void, Never>] = [:]
    private var connections: [UUID: NWConnection] = [:]
    private var stopTask: Task<Void, Never>?
    private var didReportFatalError = false

    public init(
        coordinator: ManagedFlowCoordinator,
        dnsService: DNSProxyService,
        udpRelay: LocalSOCKS5UDPRelay,
        diagnostics: TunnelDiagnostics? = nil,
        fatalErrorHandler: FatalErrorHandler? = nil
    ) {
        self.coordinator = coordinator
        self.dnsService = dnsService
        self.udpRelay = udpRelay
        self.diagnostics = diagnostics
        self.fatalErrorHandler = fatalErrorHandler
    }

    /// Starts a listener constrained to 127.0.0.1 and waits for Network.framework
    /// to publish its ephemeral port before returning.
    public func start() async throws -> UInt16 {
        switch state {
        case let .ready(port): return port
        case .idle: break
        case .starting, .stopping, .stopped: throw LocalSOCKS5TCPBridgeError.invalidState
        }
        state = .starting

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener: NWListener
        do {
            listener = try NWListener(using: parameters, on: .any)
        } catch {
            state = .stopped
            throw LocalSOCKS5TCPBridgeError.listenerFailed
        }
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in self?.accept(connection) }
        }

        do {
            let port: UInt16 = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let once = BridgeContinuationOnce<UInt16>(continuation)
                    listener.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            guard let rawPort = listener.port?.rawValue, rawPort != 0 else {
                                once.resume(throwing: LocalSOCKS5TCPBridgeError.invalidListenerPort)
                                return
                            }
                            once.resume(returning: rawPort)
                        case .failed:
                            once.resume(throwing: LocalSOCKS5TCPBridgeError.listenerFailed)
                        case .cancelled:
                            once.resume(throwing: LocalSOCKS5TCPBridgeError.listenerStopped)
                        default:
                            break
                        }
                    }
                    listener.start(queue: queue)
                }
            } onCancel: {
                listener.cancel()
            }
            try Task.checkCancellation()
            guard case .starting = state else { throw CancellationError() }
            state = .ready(port)
            listener.stateUpdateHandler = { [weak self] listenerState in
                switch listenerState {
                case .failed, .cancelled:
                    Task { @MainActor in await self?.listenerFailedAfterReady() }
                default:
                    break
                }
            }
            return port
        } catch {
            listener.stateUpdateHandler = nil
            listener.newConnectionHandler = nil
            listener.cancel()
            self.listener = nil
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
        let listener = listener
        self.listener = nil
        listener?.newConnectionHandler = nil
        listener?.stateUpdateHandler = nil
        listener?.cancel()

        let runningTasks = Array(sessions.values)
        let runningConnections = Array(connections.values)
        runningTasks.forEach { $0.cancel() }
        runningConnections.forEach { $0.cancel() }
        let udpRelay = udpRelay
        let coordinator = coordinator
        let task = Task { @MainActor in
            for task in runningTasks { await task.value }
            await udpRelay.stop()
            await coordinator.closeAll()
        }
        stopTask = task
        await task.value
        sessions.removeAll()
        connections.removeAll()
        state = .stopped
        stopTask = nil
    }

    private func listenerFailedAfterReady() async {
        guard case .ready = state, !didReportFatalError else { return }
        didReportFatalError = true
        await diagnostics?.recordTransportFailure()
        await diagnostics?.recordTerminalError(.bridge)
        let handler = fatalErrorHandler
        await stop()
        handler?(.listenerFailed)
    }

    private func accept(_ connection: NWConnection) {
        guard case .ready = state, sessions.count < Self.maximumSessions else {
            Task { await diagnostics?.recordResourceRejection() }
            connection.cancel()
            return
        }
        let id = UUID()
        connections[id] = connection
        let task = Task { @MainActor [weak self] in
            guard let self else {
                connection.cancel()
                return
            }
            await runSession(connection)
            sessionDidFinish(id: id)
        }
        sessions[id] = task
    }

    private func sessionDidFinish(id: UUID) {
        connections.removeValue(forKey: id)?.cancel()
        sessions.removeValue(forKey: id)
    }

    private func runSession(_ connection: NWConnection) async {
        var remote: ManagedTCPByteStream?
        defer { connection.cancel() }
        do {
            try await start(connection)
            var buffer = Data()
            do {
                let _: SOCKS5Greeting = try await readMessage(from: connection, buffer: &buffer) {
                    try SOCKS5Codec.parseGreeting($0)
                }
            } catch SOCKS5CodecError.noAuthenticationMethod {
                try? await send(SOCKS5Codec.encodeNoAcceptableMethodsSelection(), on: connection)
                return
            }
            try await send(SOCKS5Codec.encodeNoAuthenticationSelection(), on: connection)

            let request: SOCKS5Request
            do {
                request = try await readMessage(from: connection, buffer: &buffer) {
                    try SOCKS5Codec.parseRequest($0)
                }
            } catch let error as SOCKS5CodecError {
                try? await sendReply(SOCKS5Codec.replyCode(forRequestError: error), on: connection)
                return
            }

            switch request.command {
            case .udpAssociate:
                let association: LocalSOCKS5UDPRelay.ControlAssociation
                do {
                    association = try await udpRelay.beginAssociation(
                        requestedClient: request.destination
                    )
                } catch {
                    try? await sendReply(.generalFailure, on: connection)
                    return
                }
                do {
                    let bound = try Address.ipv4([127, 0, 0, 1], port: association.port)
                    try await sendReply(.succeeded, boundAddress: bound, on: connection)
                    buffer.removeAll(keepingCapacity: false)
                    try await waitForControlEOF(connection)
                    await udpRelay.endAssociation(association)
                } catch {
                    await udpRelay.endAssociation(association)
                    throw error
                }

            case .connect where Self.isFakeDNS(request.destination):
                try await sendReply(.succeeded, on: connection)
                try await runDNSTCP(connection: connection, buffer: &buffer)

            case .connect:
                do {
                    remote = try await coordinator.openTCP(to: request.destination)
                } catch {
                    try? await sendReply(Self.replyCode(for: error), on: connection)
                    return
                }
                guard let remote else { return }
                try await sendReply(.succeeded, on: connection)
                if !buffer.isEmpty {
                    try await remote.send(buffer)
                    buffer.removeAll(keepingCapacity: false)
                }
                try await pump(connection: connection, remote: remote)

            case .bind:
                try await sendReply(.commandNotSupported, on: connection)
            }
        } catch {
            // Session errors are local and never include target or QNAME in logs.
        }
        if let remote { await remote.close() }
    }

    private func waitForControlEOF(_ connection: NWConnection) async throws {
        while let _ = try await Self.receiveChunk(from: connection) {
            try Task.checkCancellation()
        }
    }

    private func runDNSTCP(connection: NWConnection, buffer: inout Data) async throws {
        while true {
            while buffer.count < 2 {
                guard let chunk = try await receive(maximum: Self.pumpChunkBytes, from: connection) else {
                    if buffer.isEmpty { return }
                    throw LocalSOCKS5TCPBridgeError.unexpectedEOF
                }
                buffer.append(chunk)
            }
            let prefix = [UInt8](buffer.prefix(2))
            let bodyLength = Int(prefix[0]) << 8 | Int(prefix[1])
            guard bodyLength > 0 else { throw LocalSOCKS5TCPBridgeError.invalidDNSFrame }
            let frameLength = bodyLength + 2
            while buffer.count < frameLength {
                guard let chunk = try await receive(
                    maximum: min(Self.pumpChunkBytes, frameLength - buffer.count),
                    from: connection
                ) else { throw LocalSOCKS5TCPBridgeError.unexpectedEOF }
                buffer.append(chunk)
            }
            let frame = Data(buffer.prefix(frameLength))
            buffer.removeFirst(frameLength)
            let response = try await dnsService.handleTCPFrame(frame)
            try await send(response, on: connection)
        }
    }

    private func readMessage<Value: Equatable & Sendable>(
        from connection: NWConnection,
        buffer: inout Data,
        parser: (Data) throws -> SOCKS5ParseResult<Value>
    ) async throws -> Value {
        while true {
            switch try parser(buffer) {
            case .incomplete:
                guard buffer.count < SOCKS5Codec.maximumControlMessageLength else {
                    throw LocalSOCKS5TCPBridgeError.handshakeTooLarge
                }
                let maximum = SOCKS5Codec.maximumControlMessageLength - buffer.count
                guard let chunk = try await receive(maximum: maximum, from: connection), !chunk.isEmpty else {
                    throw LocalSOCKS5TCPBridgeError.unexpectedEOF
                }
                buffer.append(chunk)
            case let .complete(value, remainder):
                buffer = remainder
                return value
            }
        }
    }

    private func pump(connection: NWConnection, remote: ManagedTCPByteStream) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                while let bytes = try await Self.receiveChunk(from: connection) {
                    try await remote.send(bytes)
                }
                try await remote.finishSending()
            }
            group.addTask {
                while let bytes = try await remote.receive(maxBytes: Self.pumpChunkBytes) {
                    try await Self.sendChunk(bytes, on: connection)
                }
                try await Self.finishSending(on: connection)
            }
            do {
                try await group.waitForAll()
            } catch {
                group.cancelAll()
                connection.cancel()
                await remote.close()
                throw error
            }
        }
    }

    private func start(_ connection: NWConnection) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = BridgeContinuationOnce<Void>(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.resume(returning: ())
                    case .failed, .cancelled:
                        once.resume(throwing: LocalSOCKS5TCPBridgeError.listenerFailed)
                    default: break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
        connection.stateUpdateHandler = nil
    }

    private func receive(maximum: Int, from connection: NWConnection) async throws -> Data? {
        try await Self.receive(maximum: maximum, from: connection)
    }

    private static func receiveChunk(from connection: NWConnection) async throws -> Data? {
        try await receive(maximum: pumpChunkBytes, from: connection)
    }

    private static func receive(maximum: Int, from connection: NWConnection) async throws -> Data? {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = BridgeContinuationOnce<Data?>(continuation)
                connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
                    data, _, complete, error in
                    if let error { once.resume(throwing: error) }
                    else if let data, !data.isEmpty { once.resume(returning: data) }
                    else if complete { once.resume(returning: nil) }
                    else { once.resume(throwing: LocalSOCKS5TCPBridgeError.unexpectedEOF) }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private func send(_ data: Data, on connection: NWConnection) async throws {
        try await Self.sendChunk(data, on: connection)
    }

    private static func sendChunk(_ data: Data, on connection: NWConnection) async throws {
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = BridgeContinuationOnce<Void>(continuation)
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error { once.resume(throwing: error) }
                    else { once.resume(returning: ()) }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func finishSending(on connection: NWConnection) async throws {
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = BridgeContinuationOnce<Void>(continuation)
                connection.send(
                    content: nil,
                    contentContext: .finalMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if let error { once.resume(throwing: error) }
                        else { once.resume(returning: ()) }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private func sendReply(_ code: SOCKS5ReplyCode, on connection: NWConnection) async throws {
        try await send(SOCKS5Codec.encodeUnspecifiedReply(code), on: connection)
    }

    private func sendReply(
        _ code: SOCKS5ReplyCode,
        boundAddress: Address,
        on connection: NWConnection
    ) async throws {
        let reply = try SOCKS5Reply(code: code, boundAddress: boundAddress)
        try await send(SOCKS5Codec.encodeReply(reply), on: connection)
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

    private static func replyCode(for error: Error) -> SOCKS5ReplyCode {
        switch error {
        case is FlowRouterError:
            .connectionNotAllowed
        case is ManagedFlowCoordinatorError:
            .hostUnreachable
        case is FlowLimiterError:
            .generalFailure
        case let networkError as NetworkTransportError:
            switch networkError {
            case .timedOut: .ttlExpired
            case .connectionFailed: .connectionRefused
            default: .generalFailure
            }
        default:
            .generalFailure
        }
    }
}

private final class BridgeContinuationOnce<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: Value) { take()?.resume(returning: value) }
    func resume(throwing error: Error) { take()?.resume(throwing: error) }

    private func take() -> CheckedContinuation<Value, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let value = continuation
        continuation = nil
        return value
    }
}
#endif
