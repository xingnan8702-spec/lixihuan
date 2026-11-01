#if canImport(Network) && canImport(Security)
import Foundation
import IPadProxyCore
import Network
import Security

public enum NetworkTransportError: Error, Sendable {
    case connectionFailed
    case timedOut
    case unexpectedEOF
    case invalidFrame
    case invalidNegotiatedProtocol
    case relayRejected(ResponseStatus)
}

/// Production PROXY transport for Apple targets. It uses TLS 1.3, system trust,
/// hostname validation, and ALPN ipad-proxy/1. It does not install a custom verifier.
public final class NetworkFrameworkTLSTransport: TunnelTransport, @unchecked Sendable {
    private let relayHost: NWEndpoint.Host
    private let relayPort: NWEndpoint.Port
    private let credentials: any CredentialStore
    private let timeout: TimeInterval
    private let queue = DispatchQueue(label: "ipad-proxy.tls-transport")

    public init(
        hostname: String,
        port: UInt16,
        credentials: any CredentialStore,
        timeout: TimeInterval = 10
    ) throws {
        guard let port = NWEndpoint.Port(rawValue: port),
              timeout.isFinite, (0...300).contains(timeout), timeout > 0
        else {
            throw NetworkTransportError.connectionFailed
        }
        relayHost = NWEndpoint.Host(hostname)
        relayPort = port
        self.credentials = credentials
        self.timeout = timeout
    }

    public func openTCP(to target: Address) async throws -> any TCPByteStream {
        let stream = try await connect()
        do {
            let token = try await credentials.loadAuthenticationToken()
            let response = try await withNetworkTimeout(seconds: timeout) {
                try await stream.send(try Request.tcpConnect(token: token, target: target).encodedFrame())
                return try Response.decodeBody(try await stream.receiveFrame())
            }
            guard response.status == .ok else {
                throw NetworkTransportError.relayRejected(response.status)
            }
            return stream
        } catch {
            await stream.close()
            throw error
        }
    }

    public func openUDP(to target: Address) async throws -> any UDPDatagramAssociation {
        let stream = try await connect()
        do {
            let token = try await credentials.loadAuthenticationToken()
            let response = try await withNetworkTimeout(seconds: timeout) {
                try await stream.send(try Request.udpAssociate(token: token).encodedFrame())
                return try Response.decodeBody(try await stream.receiveFrame())
            }
            guard response.status == .ok else {
                throw NetworkTransportError.relayRejected(response.status)
            }
            return NetworkUDPAssociation(stream: stream, target: target)
        } catch {
            await stream.close()
            throw error
        }
    }

    private func connect() async throws -> NetworkTCPByteStream {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "ipad-proxy/1")
        // No verify block is installed: Network.framework performs normal system trust
        // and hostname validation against relayHost.
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(host: relayHost, port: relayPort, using: parameters)
        let stream = NetworkTCPByteStream(connection: connection, queue: queue)
        try await withNetworkTimeout(seconds: timeout) {
            try await stream.start()
        }
        guard await stream.negotiatedApplicationProtocol() == "ipad-proxy/1" else {
            await stream.close()
            throw NetworkTransportError.invalidNegotiatedProtocol
        }
        return stream
    }
}

public actor NetworkTCPByteStream: TCPByteStream {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var closed = false

    init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    func start() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let gate = ContinuationGate(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: gate.resume()
                    case .failed, .cancelled: gate.resume(throwing: NetworkTransportError.connectionFailed)
                    default: break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func send(_ bytes: Data) async throws {
        guard !closed else { throw TransportError.closed }
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(content: bytes, completion: .contentProcessed { error in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume() }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func receive(maxBytes: Int) async throws -> Data? {
        guard maxBytes > 0 else { throw TransportError.invalidReceiveLimit }
        guard !closed else { return nil }
        return try await receiveChunk(minimum: 1, maximum: maxBytes)
    }

    public func finishSending() async throws {
        guard !closed else { throw TransportError.closed }
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                completion: .contentProcessed { error in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume() }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func negotiatedApplicationProtocol() -> String? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata,
              let value = sec_protocol_metadata_get_negotiated_protocol(
                metadata.securityProtocolMetadata
              )
        else { return nil }
        return String(cString: value)
    }

    public func close() async {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    func receiveFrame() async throws -> Data {
        let prefix = try await receiveExactly(4)
        let b = [UInt8](prefix)
        let length = Int(UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3]))
        guard (1...FrameCodec.maximumBodyLength).contains(length) else {
            throw NetworkTransportError.invalidFrame
        }
        return try await receiveExactly(length)
    }

    private func receiveExactly(_ count: Int) async throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            try Task.checkCancellation()
            guard let chunk = try await receiveChunk(
                minimum: 1,
                maximum: count - result.count
            ), !chunk.isEmpty else { throw NetworkTransportError.unexpectedEOF }
            result.append(chunk)
        }
        return result
    }

    private func receiveChunk(minimum: Int, maximum: Int) async throws -> Data? {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: minimum, maximumLength: maximum) {
                    data, _, isComplete, error in
                    if let error { continuation.resume(throwing: error) }
                    else if let data, !data.isEmpty { continuation.resume(returning: data) }
                    else if isComplete { continuation.resume(returning: nil) }
                    else { continuation.resume(throwing: NetworkTransportError.unexpectedEOF) }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }
}

public actor NetworkUDPAssociation: UDPDatagramAssociation {
    private let stream: NetworkTCPByteStream
    private let target: Address

    init(stream: NetworkTCPByteStream, target: Address) {
        self.stream = stream
        self.target = target
    }

    public func send(_ payload: Data) async throws {
        try await stream.send(try Datagram(target: target, payload: payload).encodedFrame())
    }

    public func receive() async throws -> Data? {
        do {
            let datagram = try Datagram.decodeBody(try await stream.receiveFrame())
            guard datagram.target == target else { throw NetworkTransportError.invalidFrame }
            return datagram.payload
        } catch NetworkTransportError.unexpectedEOF {
            return nil
        }
    }

    public func close() async { await stream.close() }
}

func withNetworkTimeout<T: Sendable>(
    seconds: TimeInterval,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            let nanoseconds = UInt64(seconds * 1_000_000_000)
            try await Task.sleep(nanoseconds: nanoseconds)
            throw NetworkTransportError.timedOut
        }
        defer { group.cancelAll() }
        guard let first = try await group.next() else {
            throw NetworkTransportError.connectionFailed
        }
        return first
    }
}

private final class ContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?

    init(_ continuation: CheckedContinuation<Void, Error>) { self.continuation = continuation }

    func resume() {
        take()?.resume()
    }

    func resume(throwing error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Void, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let value = continuation
        continuation = nil
        return value
    }
}
#endif
