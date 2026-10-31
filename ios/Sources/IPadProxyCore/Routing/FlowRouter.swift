import Foundation

public enum FlowRouterError: Error, Equatable, Sendable {
    case rejected
}

/// Explicitly dispatches each flow to its selected backend. Backend failures are
/// propagated to the caller and are never retried through DIRECT.
public struct FlowRouter: Sendable {
    private let engine: RuleEngine
    private let directTransport: any TunnelTransport
    private let proxyTransport: any TunnelTransport

    public init(
        engine: RuleEngine,
        directTransport: any TunnelTransport,
        proxyTransport: any TunnelTransport
    ) {
        self.engine = engine
        self.directTransport = directTransport
        self.proxyTransport = proxyTransport
    }

    public func routeTCP(
        destination: RoutingDestination,
        target: Address
    ) async throws -> any TCPByteStream {
        switch engine.action(for: destination) {
        case .direct:
            return try await directTransport.openTCP(to: target)
        case .proxy:
            return try await proxyTransport.openTCP(to: target)
        case .reject:
            throw FlowRouterError.rejected
        }
    }

    public func routeUDP(
        destination: RoutingDestination,
        target: Address
    ) async throws -> any UDPDatagramAssociation {
        switch engine.action(for: destination) {
        case .direct:
            return try await directTransport.openUDP(to: target)
        case .proxy:
            return try await proxyTransport.openUDP(to: target)
        case .reject:
            throw FlowRouterError.rejected
        }
    }
}
