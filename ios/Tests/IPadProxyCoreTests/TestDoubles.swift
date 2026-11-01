import Foundation
import XCTest
@testable import IPadProxyCore

enum TestTransportFailure: Error, Equatable, Sendable {
    case openFailed
    case bufferFull
    case resolverFailed
}

actor ManualFakeIPClock: FakeIPClock {
    private var value: TimeInterval

    init(_ value: TimeInterval = 0) { self.value = value }
    func now() async -> TimeInterval { value }
    func advance(by interval: TimeInterval) { value += interval }
}

actor TestTCPByteStream: TCPByteStream {
    private let byteLimit: Int
    private var receiveValues: [Data?]
    private let failSend: Bool
    private let failReceive: Bool
    private let failFinishSending: Bool
    private(set) var sent: [Data] = []
    private(set) var didFinishSending = false
    private(set) var isClosed = false
    private(set) var closeCount = 0

    init(
        byteLimit: Int = 65_600,
        receiveValues: [Data?] = [],
        failSend: Bool = false,
        failReceive: Bool = false,
        failFinishSending: Bool = false
    ) {
        self.byteLimit = byteLimit
        self.receiveValues = receiveValues
        self.failSend = failSend
        self.failReceive = failReceive
        self.failFinishSending = failFinishSending
    }

    func send(_ bytes: Data) async throws {
        guard !isClosed else { throw TransportError.closed }
        if failSend { throw TestTransportFailure.bufferFull }
        guard sent.reduce(0, { $0 + $1.count }) + bytes.count <= byteLimit else {
            throw TestTransportFailure.bufferFull
        }
        sent.append(bytes)
    }

    func receive(maxBytes: Int) async throws -> Data? {
        guard maxBytes > 0 else { throw TransportError.invalidReceiveLimit }
        guard !isClosed else { return nil }
        if failReceive { throw TestTransportFailure.bufferFull }
        guard !receiveValues.isEmpty else { return nil }
        return receiveValues.removeFirst()
    }

    func finishSending() async throws {
        guard !isClosed else { throw TransportError.closed }
        if failFinishSending { throw TestTransportFailure.bufferFull }
        didFinishSending = true
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        closeCount += 1
    }

    func sentValues() -> [Data] { sent }
}

actor TestUDPAssociation: UDPDatagramAssociation {
    private let datagramLimit: Int
    private var receiveValues: [Data?]
    private let failSend: Bool
    private let failReceive: Bool
    private(set) var sent: [Data] = []
    private(set) var isClosed = false
    private(set) var closeCount = 0

    init(
        datagramLimit: Int = 16,
        receiveValues: [Data?] = [],
        failSend: Bool = false,
        failReceive: Bool = false
    ) {
        self.datagramLimit = datagramLimit
        self.receiveValues = receiveValues
        self.failSend = failSend
        self.failReceive = failReceive
    }

    func send(_ payload: Data) async throws {
        guard !isClosed else { throw TransportError.closed }
        if failSend { throw TestTransportFailure.bufferFull }
        guard sent.count < datagramLimit else { throw TestTransportFailure.bufferFull }
        sent.append(payload)
    }

    func receive() async throws -> Data? {
        guard !isClosed else { return nil }
        if failReceive { throw TestTransportFailure.bufferFull }
        guard !receiveValues.isEmpty else { return nil }
        return receiveValues.removeFirst()
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        closeCount += 1
    }
}

actor RecordingTransport: TunnelTransport {
    enum Behavior: Sendable { case succeed, fail }
    private let behavior: Behavior
    private let tcpReceiveValues: [Data?]
    private let udpReceiveValues: [Data?]
    private let failTCPSend: Bool
    private let failTCPReceive: Bool
    private let failTCPFinishSending: Bool
    private let failUDPSend: Bool
    private let failUDPReceive: Bool
    private(set) var tcpTargets: [Address] = []
    private(set) var udpTargets: [Address] = []
    private(set) var tcpStreams: [TestTCPByteStream] = []
    private(set) var udpAssociations: [TestUDPAssociation] = []

    init(
        _ behavior: Behavior = .succeed,
        tcpReceiveValues: [Data?] = [],
        udpReceiveValues: [Data?] = [],
        failTCPSend: Bool = false,
        failTCPReceive: Bool = false,
        failTCPFinishSending: Bool = false,
        failUDPSend: Bool = false,
        failUDPReceive: Bool = false
    ) {
        self.behavior = behavior
        self.tcpReceiveValues = tcpReceiveValues
        self.udpReceiveValues = udpReceiveValues
        self.failTCPSend = failTCPSend
        self.failTCPReceive = failTCPReceive
        self.failTCPFinishSending = failTCPFinishSending
        self.failUDPSend = failUDPSend
        self.failUDPReceive = failUDPReceive
    }

    func openTCP(to target: Address) async throws -> any TCPByteStream {
        tcpTargets.append(target)
        if behavior == .fail { throw TestTransportFailure.openFailed }
        let stream = TestTCPByteStream(
            receiveValues: tcpReceiveValues,
            failSend: failTCPSend,
            failReceive: failTCPReceive,
            failFinishSending: failTCPFinishSending
        )
        tcpStreams.append(stream)
        return stream
    }

    func openUDP(to target: Address) async throws -> any UDPDatagramAssociation {
        udpTargets.append(target)
        if behavior == .fail { throw TestTransportFailure.openFailed }
        let association = TestUDPAssociation(
            receiveValues: udpReceiveValues,
            failSend: failUDPSend,
            failReceive: failUDPReceive
        )
        udpAssociations.append(association)
        return association
    }

    func counts() -> (tcp: Int, udp: Int) { (tcpTargets.count, udpTargets.count) }
    func lastTCPStream() -> TestTCPByteStream? { tcpStreams.last }
    func lastUDPAssociation() -> TestUDPAssociation? { udpAssociations.last }
    func recordedTCPTargets() -> [Address] { tcpTargets }
    func recordedUDPTargets() -> [Address] { udpTargets }
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

func XCTAssertEqualAsync<T: Equatable>(
    _ expression: @autoclosure () async throws -> T,
    _ expected: T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        let actual = try await expression()
        XCTAssertEqual(actual, expected, file: file, line: line)
    } catch {
        XCTFail("unexpected error: \(error)", file: file, line: line)
    }
}

func XCTAssertTrueAsync(
    _ expression: @autoclosure () async throws -> Bool,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        let actual = try await expression()
        XCTAssertTrue(actual, file: file, line: line)
    } catch {
        XCTFail("unexpected error: \(error)", file: file, line: line)
    }
}

func XCTAssertFalseAsync(
    _ expression: @autoclosure () async throws -> Bool,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        let actual = try await expression()
        XCTAssertFalse(actual, file: file, line: line)
    } catch {
        XCTFail("unexpected error: \(error)", file: file, line: line)
    }
}

func XCTAssertNilAsync<T>(
    _ expression: @autoclosure () async throws -> T?,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        let actual = try await expression()
        XCTAssertNil(actual, file: file, line: line)
    } catch {
        XCTFail("unexpected error: \(error)", file: file, line: line)
    }
}

func XCTUnwrapAsync<T>(
    _ expression: @autoclosure () async throws -> T?,
    file: StaticString = #filePath,
    line: UInt = #line
) async throws -> T {
    let actual = try await expression()
    return try XCTUnwrap(actual, file: file, line: line)
}
