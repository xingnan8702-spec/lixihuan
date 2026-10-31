import Foundation

public enum DNSUpstreamTransport: Equatable, Sendable {
    case udp
    case tcp
}

/// Resolves one unframed DNS wire message over the requested transport.
/// TCP framing remains the responsibility of `DNSProxyService`.
///
/// Implementations must observe task cancellation promptly. The service
/// cancels an in-flight resolver task when its configured timeout wins and
/// keeps the query permit until the cancelled task has exited.
public protocol DNSUpstreamResolver: Sendable {
    func resolve(_ query: Data, transport: DNSUpstreamTransport) async throws -> Data
}

/// Injectable timeout clock used to make resolver races deterministic in tests.
public protocol DNSUpstreamSleeper: Sendable {
    func sleep(for interval: TimeInterval) async throws
}

public struct SystemDNSUpstreamSleeper: DNSUpstreamSleeper {
    public init() {}

    public func sleep(for interval: TimeInterval) async throws {
        try await Task.sleep(for: .seconds(interval))
    }
}

public enum DNSProxyServiceError: Error, Equatable, Sendable {
    /// `DNSProxyCore` must turn REJECT into a local response. Forwarding one is
    /// an invalid decision and is rejected without contacting an upstream.
    case rejectedForwardDecision
    case invalidConfiguration
    case maximumInflightReached
    case upstreamTimedOut
    case truncatedTCPResponse
}

public struct DNSProxyServiceSnapshot: Equatable, Sendable {
    public let inflight: Int
    public let highWaterInflight: Int
    public let rejectedInflight: UInt64

    public init(inflight: Int, highWaterInflight: Int, rejectedInflight: UInt64) {
        self.inflight = inflight
        self.highWaterInflight = highWaterInflight
        self.rejectedInflight = rejectedInflight
    }
}

/// Executes action-preserving upstream DNS forwarding around DNSProxyCore.
/// DIRECT and PROXY resolvers are injected separately and are never used as
/// fallback paths for one another.
public actor DNSProxyService {
    public struct Configuration: Equatable, Sendable {
        public let upstreamTimeout: TimeInterval
        public let maximumInflight: Int

        public init(
            upstreamTimeout: TimeInterval = 5,
            maximumInflight: Int = 256
        ) throws {
            guard upstreamTimeout.isFinite,
                  upstreamTimeout > 0,
                  maximumInflight > 0
            else { throw DNSProxyServiceError.invalidConfiguration }
            self.upstreamTimeout = upstreamTimeout
            self.maximumInflight = maximumInflight
        }
    }

    private let core: DNSProxyCore
    private let directResolver: any DNSUpstreamResolver
    private let proxyResolver: any DNSUpstreamResolver
    private let configuration: Configuration
    private let sleeper: any DNSUpstreamSleeper
    private var inflight = 0
    private var highWaterInflight = 0
    private var rejectedInflight: UInt64 = 0

    public init(
        core: DNSProxyCore,
        directResolver: any DNSUpstreamResolver,
        proxyResolver: any DNSUpstreamResolver,
        configuration: Configuration = try! Configuration(),
        sleeper: any DNSUpstreamSleeper = SystemDNSUpstreamSleeper()
    ) {
        self.core = core
        self.directResolver = directResolver
        self.proxyResolver = proxyResolver
        self.configuration = configuration
        self.sleeper = sleeper
    }

    public func handleUDPQuery(_ query: Data) async throws -> Data {
        switch try await core.handleQuery(query) {
        case let .respond(response):
            return response
        case let .forward(forwardedQuery, action):
            let resolver = try resolver(for: action)
            try acquireInflightPermit()
            do {
                let udpResponse = try await resolve(
                    forwardedQuery,
                    using: resolver,
                    transport: .udp
                )
                let isTruncated = try DNSProxyCore.validateUpstreamResponse(
                    udpResponse,
                    for: forwardedQuery
                )
                guard isTruncated else {
                    releaseInflightPermit()
                    return udpResponse
                }

                let tcpResponse = try await resolve(
                    forwardedQuery,
                    using: resolver,
                    transport: .tcp
                )
                let tcpIsTruncated = try DNSProxyCore.validateUpstreamResponse(
                    tcpResponse,
                    for: forwardedQuery
                )
                guard !tcpIsTruncated else {
                    throw DNSProxyServiceError.truncatedTCPResponse
                }
                releaseInflightPermit()
                return tcpResponse
            } catch {
                releaseInflightPermit()
                throw error
            }
        }
    }

    public func handleTCPFrame(_ frame: Data) async throws -> Data {
        switch try await core.handleTCPFrame(frame) {
        case let .respond(responseFrame):
            return responseFrame
        case let .forward(forwardedFrame, action):
            let query = try DNSProxyCore.decodeTCPFrame(forwardedFrame)
            let resolver = try resolver(for: action)
            try acquireInflightPermit()
            do {
                let response = try await resolve(query, using: resolver, transport: .tcp)
                let isTruncated = try DNSProxyCore.validateUpstreamResponse(response, for: query)
                guard !isTruncated else {
                    throw DNSProxyServiceError.truncatedTCPResponse
                }
                let frame = try DNSProxyCore.encodeTCPFrame(response)
                releaseInflightPermit()
                return frame
            } catch {
                releaseInflightPermit()
                throw error
            }
        }
    }

    public var snapshot: DNSProxyServiceSnapshot {
        DNSProxyServiceSnapshot(
            inflight: inflight,
            highWaterInflight: highWaterInflight,
            rejectedInflight: rejectedInflight
        )
    }

    private func resolver(for action: RoutingAction) throws -> any DNSUpstreamResolver {
        switch action {
        case .direct:
            return directResolver
        case .proxy:
            return proxyResolver
        case .reject:
            throw DNSProxyServiceError.rejectedForwardDecision
        }
    }

    private func acquireInflightPermit() throws {
        guard inflight < configuration.maximumInflight else {
            if rejectedInflight < UInt64.max { rejectedInflight += 1 }
            throw DNSProxyServiceError.maximumInflightReached
        }
        inflight += 1
        highWaterInflight = max(highWaterInflight, inflight)
    }

    private func releaseInflightPermit() {
        precondition(inflight > 0)
        inflight -= 1
    }

    private func resolve(
        _ query: Data,
        using resolver: any DNSUpstreamResolver,
        transport: DNSUpstreamTransport
    ) async throws -> Data {
        let timeout = configuration.upstreamTimeout
        let sleeper = sleeper
        return try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await resolver.resolve(query, transport: transport)
            }
            group.addTask {
                try await sleeper.sleep(for: timeout)
                throw DNSProxyServiceError.upstreamTimedOut
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else {
                throw CancellationError()
            }
            return first
        }
    }
}
