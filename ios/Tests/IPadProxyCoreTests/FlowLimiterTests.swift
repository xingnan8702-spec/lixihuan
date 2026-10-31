import XCTest
@testable import IPadProxyCore

final class FlowLimiterTests: XCTestCase, @unchecked Sendable {
    func testOpeningActiveAndUDPCaps() async throws {
        let configuration = try FlowLimiter.Configuration(
            maximumActive: 2,
            maximumOpening: 2,
            maximumUDP: 1
        )
        let limiter = FlowLimiter(configuration: configuration)
        let firstUDP = try await limiter.beginOpening(.udp)
        let tcp = try await limiter.beginOpening(.tcp)

        do {
            _ = try await limiter.beginOpening(.tcp)
            XCTFail("expected opening cap")
        } catch {
            XCTAssertEqual(error as? FlowLimiterError, .openingLimitReached)
        }

        try await limiter.activate(firstUDP)
        let secondUDP = try await limiter.beginOpening(.udp)
        do {
            try await limiter.activate(secondUDP)
            XCTFail("expected UDP cap")
        } catch {
            XCTAssertEqual(error as? FlowLimiterError, .udpLimitReached)
        }
        try await limiter.activate(tcp)

        let extraTCP = try await limiter.beginOpening(.tcp)
        do {
            try await limiter.activate(extraTCP)
            XCTFail("expected active cap")
        } catch {
            XCTAssertEqual(error as? FlowLimiterError, .activeLimitReached)
        }

        let snapshot = await limiter.snapshot
        XCTAssertEqual(snapshot.opening, 2)
        XCTAssertEqual(snapshot.active, 2)
        XCTAssertEqual(snapshot.activeUDP, 1)
        XCTAssertEqual(snapshot.rejectedOpening, 1)
        XCTAssertEqual(snapshot.rejectedActivation, 2)

        _ = await limiter.release(firstUDP)
        _ = await limiter.release(tcp)
        _ = await limiter.release(secondUDP)
        _ = await limiter.release(extraTCP)
    }

    func testTransitionAndRepeatedReleaseAreSafe() async throws {
        let limiter = FlowLimiter()
        let permit = try await limiter.beginOpening(.tcp)
        try await limiter.activate(permit)

        do {
            try await limiter.activate(permit)
            XCTFail("expected repeated transition rejection")
        } catch {
            XCTAssertEqual(error as? FlowLimiterError, .permitAlreadyActivated)
        }
        let firstRelease = await limiter.release(permit)
        let secondRelease = await limiter.release(permit)
        XCTAssertTrue(firstRelease)
        XCTAssertFalse(secondRelease)
        let snapshot = await limiter.snapshot
        XCTAssertEqual(snapshot.opening, 0)
        XCTAssertEqual(snapshot.active, 0)
    }

    func testForeignPermitCannotChangeAnotherLimiter() async throws {
        let first = FlowLimiter()
        let second = FlowLimiter()
        let permit = try await first.beginOpening(.udp)

        do {
            try await second.activate(permit)
            XCTFail("expected foreign permit rejection")
        } catch {
            XCTAssertEqual(error as? FlowLimiterError, .invalidPermit)
        }
        let foreignRelease = await second.release(permit)
        XCTAssertFalse(foreignRelease)
        let firstSnapshot = await first.snapshot
        let secondSnapshot = await second.snapshot
        XCTAssertEqual(firstSnapshot.opening, 1)
        XCTAssertEqual(secondSnapshot.opening, 0)
        _ = await first.release(permit)
    }

    func testConcurrentAdmissionNeverExceedsCaps() async throws {
        let configuration = try FlowLimiter.Configuration(
            maximumActive: 4,
            maximumOpening: 64,
            maximumUDP: 2
        )
        let limiter = FlowLimiter(configuration: configuration)

        await withTaskGroup(of: Void.self) { group in
            for index in 0..<200 {
                group.addTask {
                    let kind: FlowLimiter.FlowKind = index.isMultiple(of: 2) ? .udp : .tcp
                    guard let permit = try? await limiter.beginOpening(kind) else { return }
                    if (try? await limiter.activate(permit)) != nil {
                        let snapshot = await limiter.snapshot
                        XCTAssertLessThanOrEqual(snapshot.active, 4)
                        XCTAssertLessThanOrEqual(snapshot.activeUDP, 2)
                    }
                    _ = await limiter.release(permit)
                }
            }
        }

        let final = await limiter.snapshot
        XCTAssertEqual(final.opening, 0)
        XCTAssertEqual(final.active, 0)
        XCTAssertEqual(final.activeUDP, 0)
        XCTAssertLessThanOrEqual(final.highWaterOpening, 64)
        XCTAssertLessThanOrEqual(final.highWaterActive, 4)
        XCTAssertLessThanOrEqual(final.highWaterUDP, 2)
    }

    func testConfigurationValidation() throws {
        XCTAssertThrowsError(try FlowLimiter.Configuration(maximumActive: 0))
        XCTAssertThrowsError(try FlowLimiter.Configuration(maximumOpening: 0))
        XCTAssertThrowsError(try FlowLimiter.Configuration(maximumActive: 1, maximumUDP: 2))
    }
}
