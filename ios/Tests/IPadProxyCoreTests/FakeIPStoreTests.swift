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

    func testConfigurationDefaultsAndStrictValidation() throws {
        let configuration = try FakeIPStore.Configuration()
        XCTAssertEqual(configuration.correlationGrace, 60)
        XCTAssertEqual(configuration.reuseQuarantine, 60)
        XCTAssertThrowsError(try FakeIPStore.Configuration(correlationGrace: -.infinity))
        XCTAssertThrowsError(try FakeIPStore.Configuration(correlationGrace: -.leastNonzeroMagnitude))
        XCTAssertThrowsError(try FakeIPStore.Configuration(reuseQuarantine: .nan))
        XCTAssertThrowsError(try FakeIPStore.Configuration(reuseQuarantine: -1))
    }

    func testTTLAndGraceExpiryRemoveUnleasedMapping() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 10, correlationGrace: 5, reuseQuarantine: 10)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let address = try await store.address(for: "expire.example", family: .ipv4)

        await clock.advance(by: 11)
        await store.removeExpiredMappings()
        let inGraceCount = await store.mappingCount
        let inGraceDomain = await store.domain(for: address)
        XCTAssertEqual(inGraceCount, 1)
        XCTAssertEqual(inGraceDomain, "expire.example")

        await clock.advance(by: 4)
        await store.removeExpiredMappings()
        let expiredCount = await store.mappingCount
        let expiredDomain = await store.domain(for: address)
        let quarantineCount = await store.quarantineCount
        XCTAssertEqual(expiredCount, 0)
        XCTAssertNil(expiredDomain)
        XCTAssertEqual(quarantineCount, 1)
    }

    func testLeaseCanBeAcquiredDuringGraceButNotAfterGrace() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 10, correlationGrace: 5, reuseQuarantine: 10)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let address = try await store.address(for: "Lease.Example.", family: .ipv4)

        await clock.advance(by: 11)
        let acquired = await store.acquireLease(for: address)
        let lease = try XCTUnwrap(acquired)
        XCTAssertEqual(lease.domain, "lease.example")
        XCTAssertEqual(lease.address, address)
        XCTAssertEqual(lease.family, .ipv4)
        let leasedCount = await store.activeLeaseCount
        XCTAssertEqual(leasedCount, 1)

        await clock.advance(by: 5)
        let tooLate = await store.acquireLease(for: address)
        let pinnedCount = await store.mappingCount
        XCTAssertNil(tooLate)
        XCTAssertEqual(pinnedCount, 1, "an existing lease must pin the mapping")

        await store.release(lease)
        let releasedCount = await store.mappingCount
        let quarantineCount = await store.quarantineCount
        XCTAssertEqual(releasedCount, 0)
        XCTAssertEqual(quarantineCount, 1)
    }

    func testRepeatedReleaseIsIdempotent() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 1, correlationGrace: 0, reuseQuarantine: 1)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let address = try await store.address(for: "repeat.example", family: .ipv4)
        let acquired = await store.acquireLease(for: address)
        let lease = try XCTUnwrap(acquired)

        await clock.advance(by: 2)
        await store.release(lease)
        await store.release(lease)
        let leaseCount = await store.activeLeaseCount
        let quarantineCount = await store.quarantineCount
        XCTAssertEqual(leaseCount, 0)
        XCTAssertEqual(quarantineCount, 1)
    }

    func testLateOldLeaseReleaseCannotAffectReusedAddress() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(
            ipv4Network: [192, 0, 2, 0], ipv4PrefixLength: 29,
            ttl: 1, correlationGrace: 0, reuseQuarantine: 1, capacityPerFamily: 1
        )
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let oldAddress = try await store.address(for: "old.example", family: .ipv4)
        let oldLeaseValue = await awaitLease(from: store, address: oldAddress)
        let oldLease = try XCTUnwrap(oldLeaseValue)

        await clock.advance(by: 2)
        await store.release(oldLease)
        await clock.advance(by: 2)
        let newAddress = try await store.address(for: "new.example", family: .ipv4)
        XCTAssertEqual(newAddress, oldAddress)
        let newLeaseValue = await awaitLease(from: store, address: newAddress)
        let newLease = try XCTUnwrap(newLeaseValue)

        await store.release(oldLease)
        let activeAfterOldRelease = await store.activeLeaseCount
        let newDomain = await store.domain(for: newAddress)
        XCTAssertEqual(activeAfterOldRelease, 1)
        XCTAssertEqual(newDomain, "new.example")
        await store.release(newLease)
        let finalLeaseCount = await store.activeLeaseCount
        XCTAssertEqual(finalLeaseCount, 0)
    }

    func testNewDNSQueryRenewsSameAddressWithFixedTTL() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 10, correlationGrace: 5, reuseQuarantine: 0)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let first = try await store.address(for: "renew.example", family: .ipv4)

        await clock.advance(by: 11)
        let renewed = try await store.address(for: "renew.example", family: .ipv4)
        XCTAssertEqual(renewed, first)

        await clock.advance(by: 11)
        let leaseValue = await awaitLease(from: store, address: first)
        let lease = try XCTUnwrap(leaseValue)
        XCTAssertEqual(lease.domain, "renew.example")
        await store.release(lease)
    }

    func testDiagnosticAndOrdinaryLookupsDoNotExtendTTL() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(ttl: 10, correlationGrace: 2, reuseQuarantine: 0)
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let address = try await store.address(for: "fixed-ttl.example", family: .ipv4)
        await clock.advance(by: 6)
        _ = try await store.existingAddress(for: "fixed-ttl.example", family: .ipv4)
        _ = await store.domain(for: address)
        let leaseValue = await awaitLease(from: store, address: address)
        let lease = try XCTUnwrap(leaseValue)
        await store.release(lease)

        await clock.advance(by: 6)
        let forward = try await store.existingAddress(for: "fixed-ttl.example", family: .ipv4)
        let reverse = await store.domain(for: address)
        XCTAssertNil(forward)
        XCTAssertNil(reverse)
    }

    func testQuarantineDelaysAddressReuse() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(
            ipv4Network: [192, 0, 2, 0], ipv4PrefixLength: 29,
            ttl: 1, correlationGrace: 0, reuseQuarantine: 10, capacityPerFamily: 2
        )
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let old = try await store.address(for: "old.example", family: .ipv4)
        await clock.advance(by: 2)
        let whileQuarantined = try await store.address(for: "other.example", family: .ipv4)
        XCTAssertNotEqual(old, whileQuarantined)

        await clock.advance(by: 10)
        let afterQuarantine = try await store.address(for: "reused.example", family: .ipv4)
        XCTAssertEqual(afterQuarantine, old)
    }

    func testCapacityNeverEvictsLiveOrLeasedMappings() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(
            ttl: 1, correlationGrace: 0, reuseQuarantine: 0, capacityPerFamily: 2
        )
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let first = try await store.address(for: "first.example", family: .ipv4)
        _ = try await store.address(for: "second.example", family: .ipv4)
        let leaseValue = await awaitLease(from: store, address: first)
        let lease = try XCTUnwrap(leaseValue)
        await clock.advance(by: 2)

        _ = try await store.address(for: "third.example", family: .ipv4)
        let count = await store.mappingCount
        let firstDomain = await store.domain(for: first)
        XCTAssertEqual(count, 2)
        XCTAssertEqual(firstDomain, "first.example")
        await store.release(lease)
    }

    func testPoolExhaustionIsExplicit() async throws {
        let configuration = try FakeIPStore.Configuration(
            ipv4Network: [192, 0, 2, 0], ipv4PrefixLength: 30, capacityPerFamily: 8
        )
        let store = FakeIPStore(configuration: configuration)
        do {
            _ = try await store.address(for: "none.example", family: .ipv4)
            XCTFail("expected pool exhaustion")
        } catch {
            XCTAssertEqual(error as? FakeIPStoreError, .poolExhausted(.ipv4))
        }
    }

    func testExpiredAddressIsReclaimedWithoutScanningPoolWhenDelaysAreDisabled() async throws {
        let clock = ManualFakeIPClock()
        let configuration = try FakeIPStore.Configuration(
            ipv4Network: [192, 0, 2, 0], ipv4PrefixLength: 29,
            ttl: 1, correlationGrace: 0, reuseQuarantine: 0, capacityPerFamily: 8
        )
        let store = FakeIPStore(configuration: configuration, clock: clock)
        let old = try await store.address(for: "old.example", family: .ipv4)
        await clock.advance(by: 2)
        let new = try await store.address(for: "new.example", family: .ipv4)
        XCTAssertEqual(old, new)
    }

    func testConcurrentLeaseAcquisitionAndReleaseRemainBalanced() async throws {
        let store = FakeIPStore()
        let address = try await store.address(for: "concurrent.example", family: .ipv6)
        let leases = await withTaskGroup(of: FakeIPLease?.self, returning: [FakeIPLease].self) { group in
            for _ in 0..<100 { group.addTask { await store.acquireLease(for: address) } }
            var values: [FakeIPLease] = []
            for await lease in group { if let lease { values.append(lease) } }
            return values
        }
        XCTAssertEqual(leases.count, 100)
        let acquiredCount = await store.activeLeaseCount
        XCTAssertEqual(acquiredCount, 100)

        await withTaskGroup(of: Void.self) { group in
            for lease in leases {
                group.addTask {
                    await store.release(lease)
                    await store.release(lease)
                }
            }
        }
        let finalCount = await store.activeLeaseCount
        XCTAssertEqual(finalCount, 0)
    }

    private func awaitLease(from store: FakeIPStore, address: IPAddress) async -> FakeIPLease? {
        await store.acquireLease(for: address)
    }
}
