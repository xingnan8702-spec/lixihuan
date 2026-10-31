import Foundation
import XCTest
@testable import IPadProxyCore

private actor ScriptedDNSResolver: DNSUpstreamResolver {
    enum Outcome: Sendable {
        case response(Data)
        case failure(TestTransportFailure)
    }

    private var outcomes: [Outcome]
    private var calls: [(Data, DNSUpstreamTransport)] = []

    init(_ outcomes: [Outcome]) {
        self.outcomes = outcomes
    }

    func resolve(_ query: Data, transport: DNSUpstreamTransport) async throws -> Data {
        calls.append((query, transport))
        guard !outcomes.isEmpty else { throw TestTransportFailure.resolverFailed }
        switch outcomes.removeFirst() {
        case let .response(response):
            return response
        case let .failure(error):
            throw error
        }
    }

    func callCount() -> Int { calls.count }
    func transports() -> [DNSUpstreamTransport] { calls.map(\.1) }
    func queries() -> [Data] { calls.map(\.0) }
}

private struct ImmediateDNSUpstreamSleeper: DNSUpstreamSleeper {
    func sleep(for interval: TimeInterval) async throws {}
}

private struct YieldingDNSUpstreamSleeper: DNSUpstreamSleeper {
    func sleep(for interval: TimeInterval) async throws {
        while true {
            try Task.checkCancellation()
            await Task.yield()
        }
    }
}

private actor ControllableDNSResolver: DNSUpstreamResolver {
    private var calls: [(Data, DNSUpstreamTransport)] = []
    private var response: Data?
    private var observedCancellations = 0

    func resolve(_ query: Data, transport: DNSUpstreamTransport) async throws -> Data {
        calls.append((query, transport))
        while response == nil {
            do {
                try Task.checkCancellation()
            } catch {
                observedCancellations += 1
                throw error
            }
            await Task.yield()
        }
        return response!
    }

    func complete(with response: Data) {
        self.response = response
    }

    func callCount() -> Int { calls.count }
    func cancellationCount() -> Int { observedCancellations }
}

final class DNSProxyServiceTests: XCTestCase, @unchecked Sendable {
    func testDirectAndProxyUseOnlyTheirSelectedResolvers() async throws {
        let directQuery = dnsQuery(name: "direct.example", type: 1)
        let proxyQuery = dnsQuery(name: "proxy.example", type: 65)
        let direct = ScriptedDNSResolver([.response(dnsResponse(for: directQuery))])
        let proxy = ScriptedDNSResolver([.response(dnsResponse(for: proxyQuery))])
        let rule = try RoutingRule(type: .domain, value: "direct.example", action: .direct)
        let service = try makeService(rules: [rule], final: .proxy, direct: direct, proxy: proxy)

        await XCTAssertEqualAsync(try await service.handleUDPQuery(directQuery), dnsResponse(for: directQuery))
        await XCTAssertEqualAsync(try await service.handleUDPQuery(proxyQuery), dnsResponse(for: proxyQuery))
        await XCTAssertEqualAsync(await direct.callCount(), 1)
        await XCTAssertEqualAsync(await proxy.callCount(), 1)
    }

    func testResolverFailureIsPropagatedWithoutFallback() async throws {
        let query = dnsQuery(name: "failure.example", type: 65)
        let direct = ScriptedDNSResolver([])
        let proxy = ScriptedDNSResolver([.failure(.resolverFailed)])
        let service = try makeService(final: .proxy, direct: direct, proxy: proxy)

        do {
            _ = try await service.handleUDPQuery(query)
            XCTFail("expected resolver failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .resolverFailed)
        }
        await XCTAssertEqualAsync(await proxy.callCount(), 1)
        await XCTAssertEqualAsync(await direct.callCount(), 0)
    }

    func testProxyAAndAAAASynthesisNeverCallsUpstream() async throws {
        let direct = ScriptedDNSResolver([])
        let proxy = ScriptedDNSResolver([])
        let service = try makeService(final: .proxy, direct: direct, proxy: proxy)

        for type in [UInt16(1), UInt16(28)] {
            let response = try await service.handleUDPQuery(
                dnsQuery(name: "synth.example", type: type)
            )
            XCTAssertEqual([UInt8](response)[2] & 0x80, 0x80)
        }
        await XCTAssertEqualAsync(await direct.callCount(), 0)
        await XCTAssertEqualAsync(await proxy.callCount(), 0)
    }

    func testHTTPSQueryForwardsUsingItsProxyAction() async throws {
        let query = dnsQuery(name: "https.example", type: 65)
        let expected = dnsResponse(for: query)
        let direct = ScriptedDNSResolver([])
        let proxy = ScriptedDNSResolver([.response(expected)])
        let service = try makeService(final: .proxy, direct: direct, proxy: proxy)

        await XCTAssertEqualAsync(try await service.handleUDPQuery(query), expected)
        await XCTAssertEqualAsync(await proxy.transports(), [.udp])
        await XCTAssertEqualAsync(await direct.callCount(), 0)
    }

    func testUDPTruncationRetriesOnceOverTCPOnSameAction() async throws {
        let query = dnsQuery(name: "truncated.example", type: 65)
        let truncated = dnsResponse(for: query, truncated: true)
        let complete = dnsResponse(for: query)
        let direct = ScriptedDNSResolver([])
        let proxy = ScriptedDNSResolver([.response(truncated), .response(complete)])
        let service = try makeService(final: .proxy, direct: direct, proxy: proxy)

        await XCTAssertEqualAsync(try await service.handleUDPQuery(query), complete)
        await XCTAssertEqualAsync(await proxy.transports(), [.udp, .tcp])
        await XCTAssertEqualAsync(await proxy.queries(), [query, query])
        await XCTAssertEqualAsync(await direct.callCount(), 0)
    }

    func testTCPEntryAlwaysUsesTCPAndReturnsCorrectFrame() async throws {
        let query = dnsQuery(name: "tcp.example", type: 1)
        let response = dnsResponse(for: query)
        let direct = ScriptedDNSResolver([.response(response)])
        let proxy = ScriptedDNSResolver([])
        let service = try makeService(final: .direct, direct: direct, proxy: proxy)

        let output = try await service.handleTCPFrame(DNSProxyCore.encodeTCPFrame(query))
        XCTAssertEqual(try DNSProxyCore.decodeTCPFrame(output), response)
        await XCTAssertEqualAsync(await direct.transports(), [.tcp])
        await XCTAssertEqualAsync(await direct.queries(), [query])
    }

    func testMismatchedAndMalformedResponsesAreTypedErrors() async throws {
        let query = dnsQuery(name: "private-name.example", type: 65, id: 0x1234)
        var wrongID = dnsResponse(for: query)
        wrongID[1] ^= 1
        var wrongQuestion = dnsResponse(for: query)
        wrongQuestion[13] = UInt8(ascii: "x")
        var wrongOpcode = dnsResponse(for: query)
        wrongOpcode[2] |= 0x08
        var missingQR = dnsResponse(for: query)
        missingQR[2] &= 0x7f

        let cases: [(Data, DNSUpstreamValidationError)] = [
            (wrongID, .transactionIDMismatch),
            (wrongQuestion, .questionMismatch),
            (wrongOpcode, .opcodeMismatch),
            (missingQR, .responseFlagMissing),
            (Data([0, 1]), .malformedResponse),
        ]

        for (response, expectedError) in cases {
            let direct = ScriptedDNSResolver([.response(response)])
            let service = try makeService(
                final: .direct,
                direct: direct,
                proxy: ScriptedDNSResolver([])
            )
            do {
                _ = try await service.handleUDPQuery(query)
                XCTFail("expected validation failure")
            } catch {
                XCTAssertEqual(error as? DNSUpstreamValidationError, expectedError)
                XCTAssertFalse(String(describing: error).contains("private-name.example"))
            }
        }
    }

    func testTruncatedRetryResponseIsValidatedAgain() async throws {
        let query = dnsQuery(name: "retry.example", type: 65)
        var wrongID = dnsResponse(for: query)
        wrongID[0] ^= 1
        let direct = ScriptedDNSResolver([
            .response(dnsResponse(for: query, truncated: true)),
            .response(wrongID),
        ])
        let service = try makeService(
            final: .direct,
            direct: direct,
            proxy: ScriptedDNSResolver([])
        )

        do {
            _ = try await service.handleUDPQuery(query)
            XCTFail("expected retry validation failure")
        } catch {
            XCTAssertEqual(error as? DNSUpstreamValidationError, .transactionIDMismatch)
        }
        await XCTAssertEqualAsync(await direct.transports(), [.udp, .tcp])
    }

    func testConfigurationRequiresPositiveFiniteTimeoutAndInflightLimit() throws {
        XCTAssertThrowsError(try DNSProxyService.Configuration(upstreamTimeout: 0)) {
            XCTAssertEqual($0 as? DNSProxyServiceError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try DNSProxyService.Configuration(upstreamTimeout: .infinity)) {
            XCTAssertEqual($0 as? DNSProxyServiceError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try DNSProxyService.Configuration(upstreamTimeout: .nan)) {
            XCTAssertEqual($0 as? DNSProxyServiceError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try DNSProxyService.Configuration(maximumInflight: 0)) {
            XCTAssertEqual($0 as? DNSProxyServiceError, .invalidConfiguration)
        }
        XCTAssertEqual(
            try DNSProxyService.Configuration(),
            try DNSProxyService.Configuration(upstreamTimeout: 5, maximumInflight: 256)
        )
    }

    func testTimeoutCancelsResolverReturnsPermitAndDoesNotFallback() async throws {
        let query = dnsQuery(name: "timeout-private.example", type: 65)
        let direct = ScriptedDNSResolver([])
        let proxy = ControllableDNSResolver()
        let service = try makeService(
            final: .proxy,
            direct: direct,
            proxy: proxy,
            configuration: .init(upstreamTimeout: 1, maximumInflight: 1),
            sleeper: ImmediateDNSUpstreamSleeper()
        )

        do {
            _ = try await service.handleUDPQuery(query)
            XCTFail("expected timeout")
        } catch {
            XCTAssertEqual(error as? DNSProxyServiceError, .upstreamTimedOut)
            XCTAssertFalse(String(describing: error).contains("timeout-private.example"))
        }
        await XCTAssertEqualAsync(await proxy.callCount(), 1)
        await XCTAssertEqualAsync(await proxy.cancellationCount(), 1)
        await XCTAssertEqualAsync(await direct.callCount(), 0)
        await XCTAssertEqualAsync(await service.snapshot.inflight, 0)
    }

    func testInflightCapRejectsWithoutCallingResolverAndPermitReturnsAfterSuccess() async throws {
        let firstQuery = dnsQuery(name: "first.example", type: 65)
        let secondQuery = dnsQuery(name: "second.example", type: 65)
        let resolver = ControllableDNSResolver()
        let service = try makeService(
            final: .direct,
            direct: resolver,
            proxy: ScriptedDNSResolver([]),
            configuration: .init(upstreamTimeout: 10, maximumInflight: 1),
            sleeper: YieldingDNSUpstreamSleeper()
        )

        let firstTask = Task { try await service.handleUDPQuery(firstQuery) }
        while await resolver.callCount() == 0 { await Task.yield() }

        do {
            _ = try await service.handleUDPQuery(secondQuery)
            XCTFail("expected inflight rejection")
        } catch {
            XCTAssertEqual(error as? DNSProxyServiceError, .maximumInflightReached)
        }
        await XCTAssertEqualAsync(await resolver.callCount(), 1)
        await XCTAssertEqualAsync(
            await service.snapshot,
            DNSProxyServiceSnapshot(inflight: 1, highWaterInflight: 1, rejectedInflight: 1)
        )

        let firstResponse = dnsResponse(for: firstQuery)
        await resolver.complete(with: firstResponse)
        let actual = try await firstTask.value
        XCTAssertEqual(actual, firstResponse)
        await XCTAssertEqualAsync(
            await service.snapshot,
            DNSProxyServiceSnapshot(inflight: 0, highWaterInflight: 1, rejectedInflight: 1)
        )
    }

    func testResolverFailureReturnsInflightPermit() async throws {
        let query = dnsQuery(name: "failure-permit.example", type: 65)
        let resolver = ScriptedDNSResolver([.failure(.resolverFailed)])
        let service = try makeService(
            final: .direct,
            direct: resolver,
            proxy: ScriptedDNSResolver([]),
            configuration: .init(maximumInflight: 1)
        )

        do {
            _ = try await service.handleUDPQuery(query)
            XCTFail("expected resolver failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .resolverFailed)
        }
        await XCTAssertEqualAsync(await service.snapshot.inflight, 0)
    }

    func testUDPRepeatedTCPTruncationIsTypedErrorWithoutFallback() async throws {
        let query = dnsQuery(name: "repeated-tc.example", type: 65)
        let truncated = dnsResponse(for: query, truncated: true)
        let direct = ScriptedDNSResolver([])
        let proxy = ScriptedDNSResolver([.response(truncated), .response(truncated)])
        let service = try makeService(final: .proxy, direct: direct, proxy: proxy)

        do {
            _ = try await service.handleUDPQuery(query)
            XCTFail("expected repeated truncation rejection")
        } catch {
            XCTAssertEqual(error as? DNSProxyServiceError, .truncatedTCPResponse)
        }
        await XCTAssertEqualAsync(await proxy.transports(), [.udp, .tcp])
        await XCTAssertEqualAsync(await direct.callCount(), 0)
        await XCTAssertEqualAsync(await service.snapshot.inflight, 0)
    }

    func testTCPEntryRejectsTruncatedResponseAfterBindingValidation() async throws {
        let query = dnsQuery(name: "tcp-tc.example", type: 65)
        let truncated = dnsResponse(for: query, truncated: true)
        let direct = ScriptedDNSResolver([.response(truncated)])
        let service = try makeService(
            final: .direct,
            direct: direct,
            proxy: ScriptedDNSResolver([])
        )

        do {
            _ = try await service.handleTCPFrame(DNSProxyCore.encodeTCPFrame(query))
            XCTFail("expected TCP truncation rejection")
        } catch {
            XCTAssertEqual(error as? DNSProxyServiceError, .truncatedTCPResponse)
        }
        await XCTAssertEqualAsync(await direct.transports(), [.tcp])
        await XCTAssertEqualAsync(await service.snapshot.inflight, 0)
    }

    func testRejectRespondsLocallyAndNeverCallsUpstream() async throws {
        let direct = ScriptedDNSResolver([])
        let proxy = ScriptedDNSResolver([])
        let service = try makeService(final: .reject, direct: direct, proxy: proxy)
        let query = dnsQuery(name: "blocked.example", type: 65)

        let response = try await service.handleUDPQuery(query)
        XCTAssertEqual([UInt8](response)[3] & 0x0f, 5)
        await XCTAssertEqualAsync(await direct.callCount(), 0)
        await XCTAssertEqualAsync(await proxy.callCount(), 0)
    }

    private func makeService(
        rules: [RoutingRule] = [],
        final: RoutingAction,
        direct: any DNSUpstreamResolver,
        proxy: any DNSUpstreamResolver,
        configuration: DNSProxyService.Configuration = try! .init(),
        sleeper: any DNSUpstreamSleeper = SystemDNSUpstreamSleeper()
    ) throws -> DNSProxyService {
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: final))
        let core = DNSProxyCore(ruleEngine: engine, fakeIPStore: FakeIPStore())
        return DNSProxyService(
            core: core,
            directResolver: direct,
            proxyResolver: proxy,
            configuration: configuration,
            sleeper: sleeper
        )
    }

    private func dnsQuery(
        name: String,
        type: UInt16,
        id: UInt16 = 0xabcd
    ) -> Data {
        var bytes: [UInt8] = [
            UInt8(id >> 8), UInt8(id & 0xff), 1, 0,
            0, 1, 0, 0, 0, 0, 0, 0,
        ]
        for label in name.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: label.utf8)
        }
        bytes.append(0)
        bytes.append(UInt8(type >> 8))
        bytes.append(UInt8(type & 0xff))
        bytes.append(contentsOf: [0, 1])
        return Data(bytes)
    }

    private func dnsResponse(for query: Data, truncated: Bool = false) -> Data {
        var response = query
        response[2] |= 0x80
        if truncated { response[2] |= 0x02 }
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }
}
