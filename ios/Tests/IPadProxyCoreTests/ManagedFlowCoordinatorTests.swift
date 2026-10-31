import Foundation
import XCTest
@testable import IPadProxyCore

final class ManagedFlowCoordinatorTests: XCTestCase, @unchecked Sendable {
    func testOrdinaryDirectAndProxyTCPFlowsUseOnlySelectedBackend() async throws {
        let direct = RecordingTransport()
        let proxy = RecordingTransport()
        let rules = [try RoutingRule(type: .port, value: "80", action: .direct)]
        let coordinator = try makeCoordinator(
            rules: rules,
            final: .proxy,
            direct: direct,
            proxy: proxy
        ).coordinator

        let directFlow = try await coordinator.openTCP(to: Address.domain("direct.example", port: 80))
        let proxyFlow = try await coordinator.openTCP(to: Address.domain("proxy.example", port: 443))
        await XCTAssertEqualAsync(await direct.counts().tcp, 1)
        await XCTAssertEqualAsync(await proxy.counts().tcp, 1)
        await directFlow.close()
        await proxyFlow.close()
    }

    func testFakeIPAddressRestoresDomainAndOriginalPortBeforeRouting() async throws {
        let direct = RecordingTransport()
        let proxy = RecordingTransport()
        let rule = try RoutingRule(type: .domain, value: "proxied.example", action: .proxy)
        let setup = try makeCoordinator(rules: [rule], final: .direct, direct: direct, proxy: proxy)
        let fakeAddress = try await setup.store.address(for: "Proxied.Example", family: .ipv4)
        let target = try Address.ipv4(fakeAddress.rawBytes, port: 8443)

        let flow = try await setup.coordinator.openTCP(to: target)
        let proxyTargets = await proxy.recordedTCPTargets()
        XCTAssertEqual(proxyTargets, [try Address.domain("proxied.example", port: 8443)])
        await XCTAssertEqualAsync(await direct.counts().tcp, 0)
        await XCTAssertEqualAsync(await setup.store.activeLeaseCount, 1)

        await flow.close()
        await XCTAssertEqualAsync(await setup.store.activeLeaseCount, 0)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
    }

    func testUnknownFakeIPAddressFailsClosedWithoutOpeningBackend() async throws {
        let direct = RecordingTransport()
        let proxy = RecordingTransport()
        let setup = try makeCoordinator(final: .direct, direct: direct, proxy: proxy)
        let address = try IPAddress("198.18.0.99")

        do {
            _ = try await setup.coordinator.openTCP(
                to: Address.ipv4(address.rawBytes, port: 443)
            )
            XCTFail("expected unknown Fake IP failure")
        } catch {
            XCTAssertEqual(
                error as? ManagedFlowCoordinatorError,
                .unknownFakeIPAddress(address)
            )
        }
        await XCTAssertEqualAsync(await direct.counts().tcp, 0)
        await XCTAssertEqualAsync(await proxy.counts().tcp, 0)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.opening, 0)
    }

    func testBackendOpenFailureReleasesOpeningPermitAndFakeIPLeaseWithoutFallback() async throws {
        let direct = RecordingTransport()
        let proxy = RecordingTransport(.fail)
        let store = FakeIPStore()
        let rule = try RoutingRule(type: .domain, value: "failure.example", action: .proxy)
        let setup = try makeCoordinator(
            rules: [rule],
            final: .direct,
            direct: direct,
            proxy: proxy,
            store: store
        )
        let fakeAddress = try await store.address(for: "failure.example", family: .ipv4)

        do {
            _ = try await setup.coordinator.openTCP(
                to: Address.ipv4(fakeAddress.rawBytes, port: 443)
            )
            XCTFail("expected backend error")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .openFailed)
        }
        await XCTAssertEqualAsync(await direct.counts().tcp, 0)
        await XCTAssertEqualAsync(await proxy.counts().tcp, 1)
        await XCTAssertEqualAsync(await store.activeLeaseCount, 0)
        let snapshot = await setup.limiter.snapshot
        XCTAssertEqual(snapshot.opening, 0)
        XCTAssertEqual(snapshot.active, 0)
    }

    func testActivationFailureClosesOpenedStreamAndReleasesLeaseAndPermit() async throws {
        let direct = RecordingTransport()
        let limiter = FlowLimiter(configuration: try .init(
            maximumActive: 1,
            maximumOpening: 2,
            maximumUDP: 1
        ))
        let store = FakeIPStore()
        let setup = try makeCoordinator(
            final: .direct,
            direct: direct,
            proxy: RecordingTransport(),
            limiter: limiter,
            store: store
        )
        let first = try await setup.coordinator.openTCP(to: Address.domain("one.example", port: 1))
        let fakeAddress = try await store.address(for: "two.example", family: .ipv4)

        do {
            _ = try await setup.coordinator.openTCP(
                to: Address.ipv4(fakeAddress.rawBytes, port: 2)
            )
            XCTFail("expected active limit")
        } catch {
            XCTAssertEqual(error as? FlowLimiterError, .activeLimitReached)
        }
        let secondStream = try await XCTUnwrapAsync(await direct.lastTCPStream())
        await XCTAssertTrueAsync(await secondStream.isClosed)
        await XCTAssertEqualAsync(await secondStream.closeCount, 1)
        await XCTAssertEqualAsync(await store.activeLeaseCount, 0)
        let during = await limiter.snapshot
        XCTAssertEqual(during.opening, 0)
        XCTAssertEqual(during.active, 1)

        await first.close()
        await XCTAssertEqualAsync(await limiter.snapshot.active, 0)
    }

    func testTCPEOFAndRepeatedCloseCleanUpExactlyOnce() async throws {
        let direct = RecordingTransport(tcpReceiveValues: [nil])
        let setup = try makeCoordinator(final: .direct, direct: direct, proxy: RecordingTransport())
        let flow = try await setup.coordinator.openTCP(to: Address.domain("eof.example", port: 443))
        let stream = try await XCTUnwrapAsync(await direct.lastTCPStream())

        await XCTAssertNilAsync(try await flow.receive(maxBytes: 1_024))
        await flow.close()
        await flow.close()
        await XCTAssertEqualAsync(await stream.closeCount, 1)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
    }

    func testFinishSendingDoesNotReleaseUntilClose() async throws {
        let direct = RecordingTransport()
        let setup = try makeCoordinator(final: .direct, direct: direct, proxy: RecordingTransport())
        let flow = try await setup.coordinator.openTCP(to: Address.domain("half.example", port: 443))
        let stream = try await XCTUnwrapAsync(await direct.lastTCPStream())

        try await flow.finishSending()
        await XCTAssertTrueAsync(await stream.didFinishSending)
        await XCTAssertFalseAsync(await stream.isClosed)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 1)

        await flow.close()
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
    }

    func testUDPUsesManagedCleanupAndEOFRelease() async throws {
        let proxy = RecordingTransport(udpReceiveValues: [nil])
        let setup = try makeCoordinator(final: .proxy, direct: RecordingTransport(), proxy: proxy)
        let association = try await setup.coordinator.openUDP(
            to: Address.domain("udp.example", port: 53)
        )
        await XCTAssertEqualAsync(await setup.limiter.snapshot.activeUDP, 1)
        await XCTAssertNilAsync(try await association.receive())
        await association.close()

        let underlying = try await XCTUnwrapAsync(await proxy.lastUDPAssociation())
        await XCTAssertEqualAsync(await underlying.closeCount, 1)
        let final = await setup.limiter.snapshot
        XCTAssertEqual(final.active, 0)
        XCTAssertEqual(final.activeUDP, 0)
    }

    func testTCPUnderlyingSendErrorCleansLeasePermitAndRegistryBeforeRethrow() async throws {
        let direct = RecordingTransport(failTCPSend: true)
        let setup = try makeCoordinator(final: .direct, direct: direct, proxy: RecordingTransport())
        let fakeAddress = try await setup.store.address(for: "send-error.example", family: .ipv4)
        let flow = try await setup.coordinator.openTCP(
            to: Address.ipv4(fakeAddress.rawBytes, port: 443)
        )
        let stream = try await XCTUnwrapAsync(await direct.lastTCPStream())

        do {
            try await flow.send(Data([1]))
            XCTFail("expected send failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .bufferFull)
        }
        await XCTAssertEqualAsync(await stream.closeCount, 1)
        await XCTAssertEqualAsync(await setup.store.activeLeaseCount, 0)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
        await XCTAssertEqualAsync(await setup.coordinator.snapshot.active, 0)
    }

    func testTCPUnderlyingReceiveAndFinishErrorsCleanUpBeforeRethrow() async throws {
        let receiveTransport = RecordingTransport(failTCPReceive: true)
        let receiveSetup = try makeCoordinator(
            final: .direct,
            direct: receiveTransport,
            proxy: RecordingTransport()
        )
        let receiveFlow = try await receiveSetup.coordinator.openTCP(
            to: Address.domain("receive-error.example", port: 443)
        )
        do {
            _ = try await receiveFlow.receive(maxBytes: 1)
            XCTFail("expected receive failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .bufferFull)
        }
        let receiveStream = try await XCTUnwrapAsync(await receiveTransport.lastTCPStream())
        await XCTAssertEqualAsync(await receiveStream.closeCount, 1)
        await XCTAssertEqualAsync(await receiveSetup.limiter.snapshot.active, 0)
        await XCTAssertEqualAsync(await receiveSetup.coordinator.snapshot.active, 0)

        let finishTransport = RecordingTransport(failTCPFinishSending: true)
        let finishSetup = try makeCoordinator(
            final: .direct,
            direct: finishTransport,
            proxy: RecordingTransport()
        )
        let finishFlow = try await finishSetup.coordinator.openTCP(
            to: Address.domain("finish-error.example", port: 443)
        )
        do {
            try await finishFlow.finishSending()
            XCTFail("expected finish failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .bufferFull)
        }
        let finishStream = try await XCTUnwrapAsync(await finishTransport.lastTCPStream())
        await XCTAssertEqualAsync(await finishStream.closeCount, 1)
        await XCTAssertEqualAsync(await finishSetup.limiter.snapshot.active, 0)
        await XCTAssertEqualAsync(await finishSetup.coordinator.snapshot.active, 0)
    }

    func testUDPUnderlyingSendAndReceiveErrorsCleanUpBeforeRethrow() async throws {
        let sendTransport = RecordingTransport(failUDPSend: true)
        let sendSetup = try makeCoordinator(
            final: .direct,
            direct: sendTransport,
            proxy: RecordingTransport()
        )
        let sendFlow = try await sendSetup.coordinator.openUDP(
            to: Address.domain("udp-send-error.example", port: 53)
        )
        do {
            try await sendFlow.send(Data([1]))
            XCTFail("expected UDP send failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .bufferFull)
        }
        let sendAssociation = try await XCTUnwrapAsync(await sendTransport.lastUDPAssociation())
        await XCTAssertEqualAsync(await sendAssociation.closeCount, 1)
        await XCTAssertEqualAsync(await sendSetup.limiter.snapshot.activeUDP, 0)
        await XCTAssertEqualAsync(await sendSetup.coordinator.snapshot.active, 0)

        let receiveTransport = RecordingTransport(failUDPReceive: true)
        let receiveSetup = try makeCoordinator(
            final: .direct,
            direct: receiveTransport,
            proxy: RecordingTransport()
        )
        let receiveFlow = try await receiveSetup.coordinator.openUDP(
            to: Address.domain("udp-receive-error.example", port: 53)
        )
        do {
            _ = try await receiveFlow.receive()
            XCTFail("expected UDP receive failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .bufferFull)
        }
        let receiveAssociation = try await XCTUnwrapAsync(
            await receiveTransport.lastUDPAssociation()
        )
        await XCTAssertEqualAsync(await receiveAssociation.closeCount, 1)
        await XCTAssertEqualAsync(await receiveSetup.limiter.snapshot.activeUDP, 0)
        await XCTAssertEqualAsync(await receiveSetup.coordinator.snapshot.active, 0)
    }

    func testRegistryTracksCloseAndHighWater() async throws {
        let setup = try makeCoordinator(
            final: .direct,
            direct: RecordingTransport(),
            proxy: RecordingTransport()
        )
        let first = try await setup.coordinator.openTCP(
            to: Address.domain("registry-one.example", port: 443)
        )
        _ = try await setup.coordinator.openUDP(
            to: Address.domain("registry-two.example", port: 53)
        )
        await XCTAssertEqualAsync(
            await setup.coordinator.snapshot,
            ManagedFlowRegistrySnapshot(active: 2, highWaterActive: 2)
        )

        await first.close()
        await XCTAssertEqualAsync(
            await setup.coordinator.snapshot,
            ManagedFlowRegistrySnapshot(active: 1, highWaterActive: 2)
        )
        await setup.coordinator.closeAll()
        await XCTAssertEqualAsync(
            await setup.coordinator.snapshot,
            ManagedFlowRegistrySnapshot(active: 0, highWaterActive: 2)
        )
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
    }

    func testConcurrentCloseAllCloseAndEOFReleaseExactlyOnce() async throws {
        let direct = RecordingTransport(tcpReceiveValues: [nil])
        let setup = try makeCoordinator(final: .direct, direct: direct, proxy: RecordingTransport())
        let flow = try await setup.coordinator.openTCP(
            to: Address.domain("concurrent-close.example", port: 443)
        )
        let stream = try await XCTUnwrapAsync(await direct.lastTCPStream())

        await withTaskGroup(of: Void.self) { group in
            group.addTask { await setup.coordinator.closeAll() }
            group.addTask { await setup.coordinator.closeAll() }
            group.addTask { await flow.close() }
            group.addTask { _ = try? await flow.receive(maxBytes: 1) }
        }

        await XCTAssertEqualAsync(await stream.closeCount, 1)
        await XCTAssertEqualAsync(await setup.coordinator.snapshot.active, 0)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
    }

    func testRegistryRetainsForgottenOwnerUntilCloseAllBreaksCycle() async throws {
        let direct = RecordingTransport()
        let setup = try makeCoordinator(final: .direct, direct: direct, proxy: RecordingTransport())
        var flow: ManagedTCPByteStream? = try await setup.coordinator.openTCP(
            to: Address.domain("forgotten.example", port: 443)
        )
        weak let forgottenFlow = flow
        flow = nil

        XCTAssertNotNil(forgottenFlow)
        await XCTAssertEqualAsync(await setup.coordinator.snapshot.active, 1)
        await setup.coordinator.closeAll()
        await Task.yield()

        XCTAssertNil(forgottenFlow)
        let stream = try await XCTUnwrapAsync(await direct.lastTCPStream())
        await XCTAssertEqualAsync(await stream.closeCount, 1)
        await XCTAssertEqualAsync(await setup.limiter.snapshot.active, 0)
        await XCTAssertEqualAsync(await setup.coordinator.snapshot.active, 0)
    }

    func testConcurrentOpensNeverExceedLimiterActiveCap() async throws {
        let limiter = FlowLimiter(configuration: try .init(
            maximumActive: 4,
            maximumOpening: 32,
            maximumUDP: 2
        ))
        let setup = try makeCoordinator(
            final: .direct,
            direct: RecordingTransport(),
            proxy: RecordingTransport(),
            limiter: limiter
        )

        let flows = await withTaskGroup(of: ManagedTCPByteStream?.self, returning: [ManagedTCPByteStream].self) { group in
            for index in 0..<20 {
                group.addTask {
                    try? await setup.coordinator.openTCP(
                        to: Address.domain("flow-\(index).example", port: 443)
                    )
                }
            }
            var opened: [ManagedTCPByteStream] = []
            for await flow in group {
                if let flow { opened.append(flow) }
            }
            return opened
        }

        XCTAssertEqual(flows.count, 4)
        await XCTAssertEqualAsync(await limiter.snapshot.highWaterActive, 4)
        for flow in flows { await flow.close() }
        let final = await limiter.snapshot
        XCTAssertEqual(final.opening, 0)
        XCTAssertEqual(final.active, 0)
    }

    private typealias Setup = (
        coordinator: ManagedFlowCoordinator,
        limiter: FlowLimiter,
        store: FakeIPStore
    )

    private func makeCoordinator(
        rules: [RoutingRule] = [],
        final: RoutingAction,
        direct: RecordingTransport,
        proxy: RecordingTransport,
        limiter: FlowLimiter = FlowLimiter(),
        store: FakeIPStore = FakeIPStore()
    ) throws -> Setup {
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: final))
        let router = FlowRouter(engine: engine, directTransport: direct, proxyTransport: proxy)
        return (
            ManagedFlowCoordinator(router: router, limiter: limiter, fakeIPStore: store),
            limiter,
            store
        )
    }
}
