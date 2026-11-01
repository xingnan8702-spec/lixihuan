#if canImport(Network) && canImport(Security)
import Foundation
import IPadProxyCore
import Network
import Security

/// DIRECT backend for reconstructed TCP and UDP flows. Each UDP association is
/// connected to one fixed target, matching the user-space IP stack's five-tuple.
public final class NetworkFrameworkDirectTransport: TunnelTransport, @unchecked Sendable {
    private let timeout: TimeInterval
    private let queue = DispatchQueue(label: "ipad-proxy.direct-transport")

    public init(timeout: TimeInterval = 10) throws {
        guard timeout.isFinite, (0...300).contains(timeout), timeout > 0 else { throw NetworkTransportError.connectionFailed }
        self.timeout = timeout
    }

    public func openTCP(to target: Address) async throws -> any TCPByteStream {
        let endpoint = try target.networkEndpoint()
        let connection = NWConnection(host: endpoint.host, port: endpoint.port, using: .tcp)
        let stream = NetworkTCPByteStream(connection: connection, queue: queue)
        try await withNetworkTimeout(seconds: timeout) {
            try await stream.start()
        }
        return stream
    }

    public func openUDP(to target: Address) async throws -> any UDPDatagramAssociation {
        let endpoint = try target.networkEndpoint()
        let connection = NWConnection(host: endpoint.host, port: endpoint.port, using: .udp)
        let association = NetworkDirectUDPAssociation(connection: connection, queue: queue)
        try await withNetworkTimeout(seconds: timeout) {
            try await association.start()
        }
        return association
    }
}

public actor NetworkDirectUDPAssociation: UDPDatagramAssociation {
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
                let gate = DirectContinuationGate(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        gate.resume()
                    case .failed, .cancelled:
                        gate.resume(throwing: NetworkTransportError.connectionFailed)
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func send(_ payload: Data) async throws {
        guard !closed else { throw TransportError.closed }
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(
                    content: payload,
                    contentContext: .defaultMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if let error { continuation.resume(throwing: error) }
                        else { continuation.resume() }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func receive() async throws -> Data? {
        guard !closed else { return nil }
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.receiveMessage { data, _, isComplete, error in
                    if let error { continuation.resume(throwing: error) }
                    else if let data { continuation.resume(returning: data) }
                    else if isComplete { continuation.resume(returning: nil) }
                    else { continuation.resume(throwing: NetworkTransportError.unexpectedEOF) }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func close() async {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
}

private extension Address {
    func networkEndpoint() throws -> (host: NWEndpoint.Host, port: NWEndpoint.Port) {
        guard let networkPort = NWEndpoint.Port(rawValue: port), port != 0 else {
            throw NetworkTransportError.connectionFailed
        }
        switch kind {
        case .domain:
            guard let domain else { throw NetworkTransportError.connectionFailed }
            return (NWEndpoint.Host(domain), networkPort)
        case .ipv4:
            guard let bytes = ipBytes, bytes.count == 4 else {
                throw NetworkTransportError.connectionFailed
            }
            return (NWEndpoint.Host(bytes.map(String.init).joined(separator: ".")), networkPort)
        case .ipv6:
            guard let bytes = ipBytes, bytes.count == 16 else {
                throw NetworkTransportError.connectionFailed
            }
            let groups = stride(from: 0, to: 16, by: 2).map {
                String(UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]), radix: 16)
            }
            return (NWEndpoint.Host(groups.joined(separator: ":")), networkPort)
        }
    }
}

private final class DirectContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?

    init(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func resume() { take()?.resume() }
    func resume(throwing error: Error) { take()?.resume(throwing: error) }

    private func take() -> CheckedContinuation<Void, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let value = continuation
        continuation = nil
        return value
    }
}
#endif
