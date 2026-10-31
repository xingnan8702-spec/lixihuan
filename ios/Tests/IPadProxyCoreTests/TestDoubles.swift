import Foundation
@testable import IPadProxyCore

enum TestTransportFailure: Error, Equatable, Sendable {
    case openFailed
    case bufferFull
}

actor ManualFakeIPClock: FakeIPClock {
    private var value: TimeInterval

    init(_ value: TimeInterval = 0) { self.value = value }
    func now() async -> TimeInterval { value }
    func advance(by interval: TimeInterval) { value += interval }
}

actor TestTCPByteStream: TCPByteStream {
    private let byteLimit: Int
    private(set) var sent: [Data] = []
    private(set) var didFinishSending = false
    private(set) var isClosed = false

    init(byteLimit: Int = 65_600) { self.byteLimit = byteLimit }

    func send(_ bytes: Data) async throws {
        guard !isClosed else { throw TransportError.closed }
        guard sent.reduce(0, { $0 + $1.count }) + bytes.count <= byteLimit else {
            throw TestTransportFailure.bufferFull
        }
        sent.append(bytes)
    }

    func receive(maxBytes: Int) async throws -> Data? {
        guard maxBytes > 0 else { throw TransportError.invalidReceiveLimit }
        return nil
    }

    func finishSending() async throws {
        guard !isClosed else { throw TransportError.closed }
        didFinishSending = true
    }

    func close() async { isClosed = true }
    func sentValues() -> [Data] { sent }
}

actor TestUDPAssociation: UDPDatagramAssociation {
    private let datagramLimit: Int
    private(set) var sent: [Data] = []
    private(set) var isClosed = false

    init(datagramLimit: Int = 16) { self.datagramLimit = datagramLimit }

    func send(_ payload: Data) async throws {
        guard !isClosed else { throw TransportError.closed }
        guard sent.count < datagramLimit else { throw TestTransportFailure.bufferFull }
        sent.append(payload)
    }

    func receive() async throws -> Data? { nil }
    func close() async { isClosed = true }
}

actor RecordingTransport: TunnelTransport {
    enum Behavior: Sendable { case succeed, fail }
    private let behavior: Behavior
    private(set) var tcpTargets: [Address] = []
    private(set) var udpOpenCount = 0

    init(_ behavior: Behavior = .succeed) { self.behavior = behavior }

    func openTCP(to target: Address) async throws -> any TCPByteStream {
        tcpTargets.append(target)
        if behavior == .fail { throw TestTransportFailure.openFailed }
        return TestTCPByteStream()
    }

    func openUDP(to target: Address) async throws -> any UDPDatagramAssociation {
        udpOpenCount += 1
        if behavior == .fail { throw TestTransportFailure.openFailed }
        return TestUDPAssociation()
    }

    func counts() -> (tcp: Int, udp: Int) { (tcpTargets.count, udpOpenCount) }
}

actor InMemoryCredentialStore: CredentialStore {
    private var token: AuthenticationToken?

    func loadAuthenticationToken() async throws -> AuthenticationToken {
        guard let token else { throw CredentialStoreError.notFound }
        return token
    }

    func saveAuthenticationToken(_ token: AuthenticationToken) async throws { self.token = token }
    func deleteAuthenticationToken() async throws { token = nil }
}
