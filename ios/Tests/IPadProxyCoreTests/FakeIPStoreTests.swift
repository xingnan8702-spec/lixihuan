import Foundation
import XCTest
@testable import IPadProxyCore

final class FakeIPStoreTests: XCTestCase, @unchecked Sendable {
    func testStableNormalizedDualStackMappingsAndReverseLookup() async throws {
        let clock = ManualFakeIPClock()
        let store = FakeIPStore(clock: clock)
        let ipv4 = try await store.address(for: "Example.COM.", family: .ipv4)
        let sameIPv4 = try await store.address(for: "example.com", family: .ipv4)
        let ipv6 = try await store.address(for: "example.com", family: .ipv6)

        XCTAssertEqual(ipv4, sameIPv4)
        XCTAssertEqual(ipv4.description, "198.18.0.3")
        XCTAssertEqual(ipv6.description, "fd00:198:18:2:0:0:0:3")
        let reverseIPv4 = await store.domain(for: ipv4)
        let reverseIPv6 = await store.domain(for: ipv6)
        XCTAssertEqual(reverseIPv4, "example.com")
        XCTAssertEqual(reverseIPv6, "example.com")
    }

    func testTTLExpiryRemovesForwardAndReverseMapping() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 10)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let address = try await store.address(for: "expire.example", family: .ipv4)
        await clock.advance(by: 11)
        await store.removeExpiredMappings()
        let count = await store.mappingCount
        let reverse = await store.domain(for: address)
        XCTAssertEqual(count, 0)
        XCTAssertNil(reverse)
    }

    func testCapacityNeverEvictsLiveMappings() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 100, capacityPerFamily: 2)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let first = try await store.address(for: "first.example", family: .ipv4)
        let second = try await store.address(for: "second.example", family: .ipv4)

        do {
            _ = try await store.address(for: "third.example", family: .ipv4)
            XCTFail("expected capacity exhaustion")
        } catch {
            XCTAssertEqual(error as? FakeIPStoreError, .poolExhausted(.ipv4))
        }
        let retainedFirst = try await store.existingAddress(for: "first.example", family: .ipv4)
        let retainedSecond = try await store.existingAddress(for: "second.example", family: .ipv4)
        XCTAssertEqual(retainedFirst, first)
        XCTAssertEqual(retainedSecond, second)
    }

    func testLookupDoesNotExtendAuthoritativeTTL() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 10)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let address = try await store.address(for: "fixed-ttl.example", family: .ipv4)
        await clock.advance(by: 6)
        _ = try await store.existingAddress(for: "fixed-ttl.example", family: .ipv4)
        _ = await store.domain(for: address)
        await clock.advance(by: 5)
        let expiredForward = try await store.existingAddress(for: "fixed-ttl.example", family: .ipv4)
        let expiredReverse = await store.domain(for: address)
        XCTAssertNil(expiredForward)
        XCTAssertNil(expiredReverse)
    }

    func testPoolExhaustionIsExplicit() async throws {
        let configuration = try FakeIPStore.Configuration(
            ipv4Network: [192, 0, 2, 0],
            ipv4PrefixLength: 30,
            capacityPerFamily: 8
        )
        let store = FakeIPStore(configuration: configuration)
        do {
            _ = try await store.address(for: "none.example", family: .ipv4)
            XCTFail("expected pool exhaustion")
        } catch {
            XCTAssertEqual(error as? FakeIPStoreError, .poolExhausted(.ipv4))
        }
    }

    func testExpiredAddressIsReclaimedWithoutScanningPool() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(
            ipv4Network: [192, 0, 2, 0],
            ipv4PrefixLength: 29,
            ttl: 1,
            capacityPerFamily: 8
        )
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let old = try await store.address(for: "old.example", family: .ipv4)
        await clock.advance(by: 2)
        let new = try await store.address(for: "new.example", family: .ipv4)
        XCTAssertEqual(old, new)
    }
}
