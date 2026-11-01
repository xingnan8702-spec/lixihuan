#if canImport(Network)
import Foundation
import IPadProxyCore

public enum TransportDNSUpstreamResolverError: Error, Equatable, Sendable {
    case invalidServer
    case invalidQueryLength(Int)
    case responseTooLarge(Int)
    case unexpectedEOF
}

/// DNS upstream adapter over one preselected DIRECT or PROXY transport.
/// It never changes routing action and never falls back to another transport.
public final class TransportDNSUpstreamResolver: DNSUpstreamResolver, @unchecked Sendable {
    public static let maximumResponseLength = Int(UInt16.max)

    private let transport: any TunnelTransport
    private let server: Address

    public init(transport: any TunnelTransport, server: Address) throws {
        guard server.port == 53 else { throw TransportDNSUpstreamResolverError.invalidServer }
        self.transport = transport
        self.server = server
    }

    public func resolve(_ query: Data, transport upstreamTransport: DNSUpstreamTransport) async throws -> Data {
        guard !query.isEmpty, query.count <= Int(UInt16.max) else {
            throw TransportDNSUpstreamResolverError.invalidQueryLength(query.count)
        }
        switch upstreamTransport {
        case .udp:
            return try await resolveUDP(query)
        case .tcp:
            return try await resolveTCP(query)
        }
    }

    private func resolveUDP(_ query: Data) async throws -> Data {
        let association = try await transport.openUDP(to: server)
        do {
            try Task.checkCancellation()
            try await association.send(query)
            guard let response = try await association.receive() else {
                throw TransportDNSUpstreamResolverError.unexpectedEOF
            }
            guard response.count <= Self.maximumResponseLength else {
                throw TransportDNSUpstreamResolverError.responseTooLarge(response.count)
            }
            await association.close()
            return response
        } catch {
            await association.close()
            throw error
        }
    }

    private func resolveTCP(_ query: Data) async throws -> Data {
        let stream = try await transport.openTCP(to: server)
        do {
            let frame = try DNSProxyCore.encodeTCPFrame(query)
            try Task.checkCancellation()
            try await stream.send(frame)
            let prefix = try await receiveExactly(2, from: stream)
            let bytes = [UInt8](prefix)
            let length = Int(bytes[0]) << 8 | Int(bytes[1])
            guard length > 0 else {
                throw TransportDNSUpstreamResolverError.unexpectedEOF
            }
            let response = try await receiveExactly(length, from: stream)
            guard response.count <= Self.maximumResponseLength else {
                throw TransportDNSUpstreamResolverError.responseTooLarge(response.count)
            }
            await stream.close()
            return response
        } catch {
            await stream.close()
            throw error
        }
    }

    private func receiveExactly(_ count: Int, from stream: any TCPByteStream) async throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            try Task.checkCancellation()
            guard let chunk = try await stream.receive(maxBytes: count - result.count),
                  !chunk.isEmpty
            else { throw TransportDNSUpstreamResolverError.unexpectedEOF }
            guard result.count + chunk.count <= count else {
                throw TransportDNSUpstreamResolverError.responseTooLarge(result.count + chunk.count)
            }
            result.append(chunk)
        }
        return result
    }
}
#endif
