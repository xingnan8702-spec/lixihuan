import Foundation
import XCTest
@testable import IPadProxyCore

private final class DiagnosticsTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var wall: Date
    private var uptime: UInt64

    init(wall: Date = Date(timeIntervalSince1970: 1_700_000_000), uptime: UInt64 = 1_000) {
        self.wall = wall
        self.uptime = uptime
    }

    func wallNow() -> Date {
        lock.withLock { wall }
    }

    func uptimeNow() -> UInt64 {
        lock.withLock { uptime }
    }

    func advance(nanoseconds: UInt64) {
        lock.withLock {
            uptime = uptime.addingReportingOverflow(nanoseconds).overflow
                ? UInt64.max
                : uptime + nanoseconds
        }
    }
}

final class TunnelDiagnosticsTests: XCTestCase, @unchecked Sendable {
    func testAggregateCountersAndActiveUnderflowProtection() async {
        let clock = DiagnosticsTestClock()
        let diagnostics = TunnelDiagnostics(
            wallClock: { clock.wallNow() },
            uptimeClock: { clock.uptimeNow() }
        )
        await diagnostics.recordFlowClosed(.tcp, count: 10)
        await diagnostics.recordFlowActivated(.tcp, count: 2)
        await diagnostics.recordFlowActivated(.udp, count: 3)
        await diagnostics.recordFlowClosed(.tcp)
        await diagnostics.recordTraffic(.upload, bytes: 12, packets: 2)
        await diagnostics.recordTraffic(.download, bytes: 34, packets: 3)
        await diagnostics.recordDNSQuery(count: 5)
        await diagnostics.recordDNSFailure(count: 2)
        await diagnostics.recordRejectedFlow(count: 4)
        await diagnostics.recordResourceRejection(count: 6)
        await diagnostics.recordTransportFailure(count: 7)
        await diagnostics.recordTerminalError(.hevRuntimeExit)
        clock.advance(nanoseconds: 2_000_000_000)

        let snapshot = await diagnostics.snapshot
        XCTAssertEqual(snapshot.timestamp, clock.wallNow())
        XCTAssertEqual(snapshot.uptime, 2)
        XCTAssertEqual(snapshot.activeTCP, 1)
        XCTAssertEqual(snapshot.highWaterTCP, 2)
        XCTAssertEqual(snapshot.activeUDP, 3)
        XCTAssertEqual(snapshot.highWaterUDP, 3)
        XCTAssertEqual(snapshot.bytesUp, 12)
        XCTAssertEqual(snapshot.bytesDown, 34)
        XCTAssertEqual(snapshot.packetsUp, 2)
        XCTAssertEqual(snapshot.packetsDown, 3)
        XCTAssertEqual(snapshot.dnsTotal, 5)
        XCTAssertEqual(snapshot.dnsFailures, 2)
        XCTAssertEqual(snapshot.rejectedFlows, 4)
        XCTAssertEqual(snapshot.resourceRejections, 6)
        XCTAssertEqual(snapshot.transportFailures, 7)
        XCTAssertEqual(snapshot.lastTerminalErrorCategory, .hevRuntimeExit)
    }

    func testEveryCounterSaturates() async {
        let diagnostics = TunnelDiagnostics()
        await diagnostics.recordFlowActivated(.tcp, count: .max)
        await diagnostics.recordFlowActivated(.tcp)
        await diagnostics.recordFlowActivated(.udp, count: .max)
        await diagnostics.recordFlowActivated(.udp)
        await diagnostics.recordTraffic(.upload, bytes: .max, packets: .max)
        await diagnostics.recordTraffic(.upload, bytes: 1, packets: 1)
        await diagnostics.recordTraffic(.download, bytes: .max, packets: .max)
        await diagnostics.recordTraffic(.download, bytes: 1, packets: 1)
        await diagnostics.recordDNSQuery(count: .max)
        await diagnostics.recordDNSQuery()
        await diagnostics.recordDNSFailure(count: .max)
        await diagnostics.recordDNSFailure()
        await diagnostics.recordRejectedFlow(count: .max)
        await diagnostics.recordRejectedFlow()
        await diagnostics.recordResourceRejection(count: .max)
        await diagnostics.recordResourceRejection()
        await diagnostics.recordTransportFailure(count: .max)
        await diagnostics.recordTransportFailure()

        let snapshot = await diagnostics.snapshot
        XCTAssertEqual(snapshot.activeTCP, .max)
        XCTAssertEqual(snapshot.highWaterTCP, .max)
        XCTAssertEqual(snapshot.activeUDP, .max)
        XCTAssertEqual(snapshot.highWaterUDP, .max)
        XCTAssertEqual(snapshot.bytesUp, .max)
        XCTAssertEqual(snapshot.bytesDown, .max)
        XCTAssertEqual(snapshot.packetsUp, .max)
        XCTAssertEqual(snapshot.packetsDown, .max)
        XCTAssertEqual(snapshot.dnsTotal, .max)
        XCTAssertEqual(snapshot.dnsFailures, .max)
        XCTAssertEqual(snapshot.rejectedFlows, .max)
        XCTAssertEqual(snapshot.resourceRejections, .max)
        XCTAssertEqual(snapshot.transportFailures, .max)
    }

    func testConcurrentEventsRemainExact() async {
        let diagnostics = TunnelDiagnostics()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<1_000 {
                group.addTask {
                    await diagnostics.recordFlowActivated(.tcp)
                    await diagnostics.recordTraffic(.upload, bytes: 3)
                    await diagnostics.recordTraffic(.download, bytes: 5)
                    await diagnostics.recordDNSQuery()
                    await diagnostics.recordDNSFailure()
                    await diagnostics.recordFlowClosed(.tcp)
                }
            }
        }

        let snapshot = await diagnostics.snapshot
        XCTAssertEqual(snapshot.activeTCP, 0)
        XCTAssertGreaterThan(snapshot.highWaterTCP, 0)
        XCTAssertEqual(snapshot.bytesUp, 3_000)
        XCTAssertEqual(snapshot.bytesDown, 5_000)
        XCTAssertEqual(snapshot.packetsUp, 1_000)
        XCTAssertEqual(snapshot.packetsDown, 1_000)
        XCTAssertEqual(snapshot.dnsTotal, 1_000)
        XCTAssertEqual(snapshot.dnsFailures, 1_000)
    }

    func testResetPreservesActiveAndClearsCumulativeValues() async {
        let clock = DiagnosticsTestClock()
        let diagnostics = TunnelDiagnostics(
            wallClock: { clock.wallNow() },
            uptimeClock: { clock.uptimeNow() }
        )
        await diagnostics.recordFlowActivated(.tcp, count: 3)
        await diagnostics.recordFlowClosed(.tcp)
        await diagnostics.recordFlowActivated(.udp, count: 2)
        await diagnostics.recordTraffic(.upload, bytes: 10)
        await diagnostics.recordTraffic(.download, bytes: 20)
        await diagnostics.recordDNSQuery()
        await diagnostics.recordDNSFailure()
        await diagnostics.recordRejectedFlow()
        await diagnostics.recordResourceRejection()
        await diagnostics.recordTransportFailure()
        await diagnostics.recordTerminalError(.bridge)
        clock.advance(nanoseconds: 9_000_000_000)

        let reset = await diagnostics.resetDiagnostics()
        XCTAssertEqual(reset.uptime, 0)
        XCTAssertEqual(reset.activeTCP, 2)
        XCTAssertEqual(reset.highWaterTCP, 2)
        XCTAssertEqual(reset.activeUDP, 2)
        XCTAssertEqual(reset.highWaterUDP, 2)
        XCTAssertEqual(reset.bytesUp, 0)
        XCTAssertEqual(reset.bytesDown, 0)
        XCTAssertEqual(reset.packetsUp, 0)
        XCTAssertEqual(reset.packetsDown, 0)
        XCTAssertEqual(reset.dnsTotal, 0)
        XCTAssertEqual(reset.dnsFailures, 0)
        XCTAssertEqual(reset.rejectedFlows, 0)
        XCTAssertEqual(reset.resourceRejections, 0)
        XCTAssertEqual(reset.transportFailures, 0)
        XCTAssertNil(reset.lastTerminalErrorCategory)
    }

    func testRequestAndResponseCodecRoundTrip() async throws {
        for operation in [TunnelDiagnosticsOperation.snapshot, .reset] {
            let request = TunnelDiagnosticsRequest(operation: operation)
            XCTAssertEqual(
                try TunnelDiagnosticsMessageCodec.decodeRequest(
                    TunnelDiagnosticsMessageCodec.encodeRequest(request)
                ),
                request
            )
        }

        let diagnostics = TunnelDiagnostics()
        await diagnostics.recordDNSQuery()
        let response = TunnelDiagnosticsResponse.success(await diagnostics.snapshot)
        XCTAssertEqual(
            try TunnelDiagnosticsMessageCodec.decodeResponse(
                TunnelDiagnosticsMessageCodec.encodeResponse(response)
            ),
            response
        )
        let failure = TunnelDiagnosticsResponse.failure(.unavailable)
        XCTAssertEqual(
            try TunnelDiagnosticsMessageCodec.decodeResponse(
                TunnelDiagnosticsMessageCodec.encodeResponse(failure)
            ),
            failure
        )
    }

    func testCodecRejectsUnknownMalformedOversizedAndUnsupportedMessages() throws {
        XCTAssertThrowsError(
            try TunnelDiagnosticsMessageCodec.decodeRequest(Data())
        ) { XCTAssertEqual($0 as? TunnelDiagnosticsCodecError, .emptyMessage) }
        XCTAssertThrowsError(
            try TunnelDiagnosticsMessageCodec.decodeRequest(
                Data(repeating: 0x20, count: TunnelDiagnosticsMessageCodec.maximumMessageBytes + 1)
            )
        ) { XCTAssertEqual($0 as? TunnelDiagnosticsCodecError, .messageTooLarge) }

        let invalidRequests = [
            #"{"version":1,"operation":"snapshot","unknown":true}"#,
            #"{"version":1,"operation":"other"}"#,
            #"{"version":1,"operation":"snapshot"} trailing"#,
        ]
        for value in invalidRequests {
            XCTAssertThrowsError(
                try TunnelDiagnosticsMessageCodec.decodeRequest(Data(value.utf8))
            ) { XCTAssertEqual($0 as? TunnelDiagnosticsCodecError, .invalidMessage) }
        }
        XCTAssertThrowsError(
            try TunnelDiagnosticsMessageCodec.decodeRequest(
                Data(#"{"version":2,"operation":"snapshot"}"#.utf8)
            )
        ) { XCTAssertEqual($0 as? TunnelDiagnosticsCodecError, .unsupportedVersion) }

        let invalidResponses = [
            #"{"version":1,"snapshot":null,"error":null}"#,
            #"{"version":1,"error":"unavailable","unknown":0}"#,
            #"{"version":1,"snapshot":{},"error":"unavailable"}"#,
        ]
        for value in invalidResponses {
            XCTAssertThrowsError(
                try TunnelDiagnosticsMessageCodec.decodeResponse(Data(value.utf8))
            ) { XCTAssertEqual($0 as? TunnelDiagnosticsCodecError, .invalidMessage) }
        }
    }

    func testEncodedSnapshotContainsNoSensitiveCanaryOrSensitiveFieldNames() async throws {
        let canaries = [
            "private.example.invalid",
            "203.0.113.77",
            "65535",
            "token-canary-4f1d",
            "/private/var/mobile/canary",
            "payload-canary-b7a2",
            "underlying-description-canary",
        ]
        let forbiddenFieldNames = [
            "domain", "address", "ip", "port", "token", "path", "payload", "description",
        ]
        let data = try TunnelDiagnosticsMessageCodec.encodeResponse(
            .success(await TunnelDiagnostics().snapshot)
        )
        let encoded = try XCTUnwrap(String(data: data, encoding: .utf8)?.lowercased())
        for canary in canaries {
            XCTAssertFalse(encoded.contains(canary.lowercased()))
        }
        for field in forbiddenFieldNames {
            XCTAssertFalse(encoded.contains("\"\(field)\""))
        }
    }
}
