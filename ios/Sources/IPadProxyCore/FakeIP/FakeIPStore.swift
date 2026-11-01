import Foundation

public protocol FakeIPClock: Sendable {
    func now() async -> TimeInterval
}

public struct SystemFakeIPClock: FakeIPClock {
    public init() {}

    public func now() async -> TimeInterval {
        Date.timeIntervalSinceReferenceDate
    }
}

public enum FakeIPStoreError: Error, Equatable, Sendable {
    case invalidConfiguration
    case poolExhausted(IPAddressFamily)
    case unsupportedAddressFamily
}

/// A capability proving that a flow acquired a particular Fake IP mapping.
///
/// Callers can inspect the normalized domain and address, but only
/// `FakeIPStore` can construct a lease. Release the lease
/// when the flow finishes. Copies are safe: repeated releases are idempotent.
public struct FakeIPLease: Sendable {
    public let normalizedDomain: String
    public var domain: String { normalizedDomain }
    public let address: IPAddress
    public let family: IPAddressFamily

    fileprivate let storeIdentity: UUID
    fileprivate let entryIdentity: UUID
    fileprivate let leaseIdentity: UUID

    fileprivate init(
        domain: String,
        address: IPAddress,
        storeIdentity: UUID,
        entryIdentity: UUID,
        leaseIdentity: UUID
    ) {
        self.normalizedDomain = domain
        self.address = address
        family = address.family
        self.storeIdentity = storeIdentity
        self.entryIdentity = entryIdentity
        self.leaseIdentity = leaseIdentity
    }
}

public enum FakeIPLeaseAcquisition: Sendable {
    /// The address is outside both configured Fake IP pools.
    case notManaged
    /// The address belongs to a Fake IP pool but has no leasable mapping.
    case unknownManagedAddress
    case acquired(FakeIPLease)
}

/// A bounded, dual-stack Fake IP allocator.
///
/// The default IPv4 pool is 198.18.0.0/15. The default IPv6 pool is
/// fd00:198:18:2::/64. Host identifiers 0, 1, and 2 are reserved for the
/// network, gateway, and DNS service. IPv4 also reserves the subnet broadcast.
public actor FakeIPStore {
    public struct Configuration: Sendable, Equatable {
        public static let defaultIPv4Network: [UInt8] = [198, 18, 0, 0]
        public static let defaultIPv6Network: [UInt8] = [0xfd, 0x00, 0x01, 0x98, 0x00, 0x18, 0x00, 0x02,
                                                          0, 0, 0, 0, 0, 0, 0, 0]

        public let ipv4Network: [UInt8]
        public let ipv4PrefixLength: Int
        public let ipv6Network: [UInt8]
        public let ipv6PrefixLength: Int
        public let ttl: TimeInterval
        public let correlationGrace: TimeInterval
        public let reuseQuarantine: TimeInterval
        public let capacityPerFamily: Int

        public init(
            ipv4Network: [UInt8] = Self.defaultIPv4Network,
            ipv4PrefixLength: Int = 15,
            ipv6Network: [UInt8] = Self.defaultIPv6Network,
            ipv6PrefixLength: Int = 64,
            ttl: TimeInterval = 300,
            correlationGrace: TimeInterval = 60,
            reuseQuarantine: TimeInterval = 60,
            capacityPerFamily: Int = 4_096
        ) throws {
            guard ipv4Network.count == 4,
                  (1...30).contains(ipv4PrefixLength),
                  ipv6Network.count == 16,
                  (1...64).contains(ipv6PrefixLength),
                  ttl.isFinite, ttl > 0,
                  correlationGrace.isFinite, correlationGrace >= 0,
                  reuseQuarantine.isFinite, reuseQuarantine >= 0,
                  capacityPerFamily > 0
            else { throw FakeIPStoreError.invalidConfiguration }

            self.ipv4Network = Self.mask(ipv4Network, prefixLength: ipv4PrefixLength)
            self.ipv4PrefixLength = ipv4PrefixLength
            self.ipv6Network = Self.mask(ipv6Network, prefixLength: ipv6PrefixLength)
            self.ipv6PrefixLength = ipv6PrefixLength
            self.ttl = ttl
            self.correlationGrace = correlationGrace
            self.reuseQuarantine = reuseQuarantine
            self.capacityPerFamily = capacityPerFamily
        }

        private static func mask(_ bytes: [UInt8], prefixLength: Int) -> [UInt8] {
            bytes.enumerated().map { index, byte in
                let remaining = prefixLength - index * 8
                if remaining >= 8 { return byte }
                if remaining <= 0 { return 0 }
                return byte & (UInt8.max << UInt8(8 - remaining))
            }
        }
    }

    private struct MappingKey: Hashable, Sendable {
        let domain: String
        let family: IPAddressFamily
    }

    private struct AddressKey: Hashable, Sendable {
        let family: IPAddressFamily
        let bytes: [UInt8]
    }

    private struct Entry: Sendable {
        let identity: UUID
        let address: IPAddress
        var expiresAt: TimeInterval
        var expiryEventIdentity: UUID
        var leaseIdentities: Set<UUID>
    }

    private struct ExpiryItem: Sendable {
        let value: TimeInterval
        let sequence: UInt64
        let eventIdentity: UUID
        let key: MappingKey
    }

    private struct QuarantineRecord: Sendable {
        let releaseAt: TimeInterval
        let eventIdentity: UUID
    }

    private struct QuarantineItem: Sendable {
        let value: TimeInterval
        let sequence: UInt64
        let eventIdentity: UUID
        let address: AddressKey
    }

    private struct PoolState: Sendable {
        let network: [UInt8]
        let prefixLength: Int
        var nextHost: UInt64 = 3
        var exhaustedSequentialRange = false
        var recycled: [[UInt8]] = []
        var recycledSet: Set<[UInt8]> = []

        var maximumHost: UInt64 {
            let hostBits = network.count * 8 - prefixLength
            return hostBits == 64 ? UInt64.max : (UInt64(1) << UInt64(hostBits)) - 1
        }

        mutating func allocate(family: IPAddressFamily) -> [UInt8]? {
            if let address = recycled.popLast() {
                recycledSet.remove(address)
                return address
            }
            guard !exhaustedSequentialRange else { return nil }

            let host = nextHost
            if family == .ipv4, host >= maximumHost {
                exhaustedSequentialRange = true
                return nil
            }
            guard host <= maximumHost else {
                exhaustedSequentialRange = true
                return nil
            }

            if host == UInt64.max {
                // The /64 IPv6 pool contains this host exactly once. A separate
                // exhaustion bit prevents UInt64.max from being returned forever.
                exhaustedSequentialRange = true
            } else {
                nextHost = host + 1
            }
            return address(host: host)
        }

        mutating func recycle(_ bytes: [UInt8]) {
            guard recycledSet.insert(bytes).inserted else { return }
            recycled.append(bytes)
        }

        private func address(host: UInt64) -> [UInt8] {
            var result = network
            for offset in 0..<min(8, result.count) {
                let index = result.count - 1 - offset
                result[index] |= UInt8((host >> UInt64(offset * 8)) & 0xff)
            }
            return result
        }
    }

    private let configuration: Configuration
    private let clock: any FakeIPClock
    private let storeIdentity = UUID()
    private var entries: [MappingKey: Entry] = [:]
    private var reverse: [AddressKey: MappingKey] = [:]
    private var quarantined: [AddressKey: QuarantineRecord] = [:]
    private var expiryHeap: [ExpiryItem] = []
    private var quarantineHeap: [QuarantineItem] = []
    private var heapSequence: UInt64 = 0
    private var familyCounts: [IPAddressFamily: Int] = [.ipv4: 0, .ipv6: 0]
    private var ipv4Pool: PoolState
    private var ipv6Pool: PoolState

    public init(
        configuration: Configuration = try! Configuration(),
        clock: any FakeIPClock = SystemFakeIPClock()
    ) {
        self.configuration = configuration
        self.clock = clock
        ipv4Pool = PoolState(network: configuration.ipv4Network, prefixLength: configuration.ipv4PrefixLength)
        ipv6Pool = PoolState(network: configuration.ipv6Network, prefixLength: configuration.ipv6PrefixLength)
    }

    /// Allocates or renews a mapping for a DNS answer.
    ///
    /// A repeated DNS query renews the same address for one new fixed TTL while
    /// that mapping still exists. Diagnostic lookup and lease acquisition do
    /// not renew the TTL.
    public func address(for domain: String, family: IPAddressFamily) async throws -> IPAddress {
        let normalized = try DomainNormalizer.normalizeRuleDomain(domain)
        let now = await clock.now()
        removeExpired(at: now)
        let key = MappingKey(domain: normalized, family: family)
        if var existing = entries[key] {
            scheduleExpiry(for: &existing, key: key, expiresAt: deadline(after: configuration.ttl, from: now))
            entries[key] = existing
            return existing.address
        }

        guard count(for: family) < configuration.capacityPerFamily else {
            throw FakeIPStoreError.poolExhausted(family)
        }

        let bytes: [UInt8]?
        switch family {
        case .ipv4:
            bytes = ipv4Pool.allocate(family: family)
        case .ipv6:
            bytes = ipv6Pool.allocate(family: family)
        }
        guard let bytes else { throw FakeIPStoreError.poolExhausted(family) }

        let address = IPAddress.validated(family: family, bytes: bytes)
        var entry = Entry(
            identity: UUID(),
            address: address,
            expiresAt: 0,
            expiryEventIdentity: UUID(),
            leaseIdentities: []
        )
        scheduleExpiry(for: &entry, key: key, expiresAt: deadline(after: configuration.ttl, from: now))
        entries[key] = entry
        familyCounts[family, default: 0] += 1
        reverse[AddressKey(family: family, bytes: bytes)] = key
        compactHeapsIfNeeded()
        return address
    }

    /// Returns a current mapping without renewing its authoritative DNS TTL.
    public func existingAddress(for domain: String, family: IPAddressFamily) async throws -> IPAddress? {
        let normalized = try DomainNormalizer.normalizeRuleDomain(domain)
        let now = await clock.now()
        removeExpired(at: now)
        return entries[MappingKey(domain: normalized, family: family)]?.address
    }

    /// Diagnostic reverse lookup only. This method does not hold the mapping or
    /// extend its TTL. Production flow setup must use `acquireLease(forFlow:)`
    /// and retain the returned lease until the flow closes.
    public func domain(for address: IPAddress) async -> String? {
        let now = await clock.now()
        removeExpired(at: now)
        let addressKey = AddressKey(family: address.family, bytes: address.rawBytes)
        guard let key = reverse[addressKey], entries[key] != nil else { return nil }
        return key.domain
    }

    /// Atomically classifies an address, reverse-resolves it, and pins the exact
    /// mapping when it belongs to a configured Fake IP pool. Pool addresses
    /// without a live mapping are distinguished from ordinary Internet targets
    /// so callers can fail closed.
    public func acquireLease(forFlow address: IPAddress) async -> FakeIPLeaseAcquisition {
        let now = await clock.now()
        removeExpired(at: now)
        let addressKey = AddressKey(family: address.family, bytes: address.rawBytes)
        guard isInManagedPool(address) else { return .notManaged }
        guard let key = reverse[addressKey], var entry = entries[key] else {
            return .unknownManagedAddress
        }
        let graceDeadline = deadline(after: configuration.correlationGrace, from: entry.expiresAt)
        guard now < graceDeadline else { return .unknownManagedAddress }

        let leaseIdentity = UUID()
        entry.leaseIdentities.insert(leaseIdentity)
        entries[key] = entry
        return .acquired(FakeIPLease(
            domain: key.domain,
            address: entry.address,
            storeIdentity: storeIdentity,
            entryIdentity: entry.identity,
            leaseIdentity: leaseIdentity
        ))
    }

    /// Atomically reverse-resolves an address and pins that exact mapping.
    /// Acquisition is allowed through the correlation grace interval, but not
    /// at or after its deadline. This compatibility API returns nil both for an
    /// ordinary address and for an unknown address in a managed pool; flow setup
    /// should use `acquireLease(forFlow:)` to preserve fail-closed behavior.
    public func acquireLease(for address: IPAddress) async -> FakeIPLease? {
        guard case let .acquired(lease) = await acquireLease(forFlow: address) else {
            return nil
        }
        return lease
    }

    /// Releases a lease once. Foreign, stale, copied, or already released
    /// leases have no effect on the current mapping.
    public func release(_ lease: FakeIPLease) async {
        guard lease.storeIdentity == storeIdentity else { return }
        let now = await clock.now()
        removeExpired(at: now)
        let key = MappingKey(domain: lease.domain, family: lease.family)
        guard var entry = entries[key],
              entry.identity == lease.entryIdentity,
              entry.address == lease.address,
              entry.leaseIdentities.remove(lease.leaseIdentity) != nil
        else { return }

        entries[key] = entry
        let graceDeadline = deadline(after: configuration.correlationGrace, from: entry.expiresAt)
        if entry.leaseIdentities.isEmpty, now >= graceDeadline {
            moveToQuarantine(key, entry: entry, at: now)
        }
    }

    public func removeExpiredMappings() async {
        removeExpired(at: await clock.now())
    }

    public var mappingCount: Int { entries.count }
    public var quarantineCount: Int { quarantined.count }
    public var activeLeaseCount: Int {
        entries.values.reduce(0) { $0 + $1.leaseIdentities.count }
    }

    private func isInManagedPool(_ address: IPAddress) -> Bool {
        let network: [UInt8]
        let prefixLength: Int
        switch address.family {
        case .ipv4:
            network = configuration.ipv4Network
            prefixLength = configuration.ipv4PrefixLength
        case .ipv6:
            network = configuration.ipv6Network
            prefixLength = configuration.ipv6PrefixLength
        }

        return address.rawBytes.enumerated().allSatisfy { index, byte in
            let remaining = prefixLength - index * 8
            if remaining >= 8 { return byte == network[index] }
            if remaining <= 0 { return true }
            let mask = UInt8.max << UInt8(8 - remaining)
            return byte & mask == network[index] & mask
        }
    }

    private func count(for family: IPAddressFamily) -> Int {
        familyCounts[family, default: 0]
    }

    private func scheduleExpiry(for entry: inout Entry, key: MappingKey, expiresAt: TimeInterval) {
        entry.expiresAt = expiresAt
        entry.expiryEventIdentity = UUID()
        let graceDeadline = deadline(after: configuration.correlationGrace, from: expiresAt)
        push(
            ExpiryItem(
                value: graceDeadline,
                sequence: nextHeapSequence(),
                eventIdentity: entry.expiryEventIdentity,
                key: key
            ),
            into: &expiryHeap,
            less: expiryLess
        )
    }

    private func removeExpired(at now: TimeInterval) {
        releaseQuarantinedAddresses(at: now)
        while let first = expiryHeap.first, first.value <= now {
            _ = pop(from: &expiryHeap, less: expiryLess)
            guard let entry = entries[first.key],
                  entry.expiryEventIdentity == first.eventIdentity,
                  deadline(after: configuration.correlationGrace, from: entry.expiresAt) <= now,
                  entry.leaseIdentities.isEmpty
            else { continue }
            moveToQuarantine(first.key, entry: entry, at: first.value)
        }
        releaseQuarantinedAddresses(at: now)
        compactHeapsIfNeeded()
    }

    private func moveToQuarantine(_ key: MappingKey, entry: Entry, at now: TimeInterval) {
        guard entries[key]?.identity == entry.identity else { return }
        entries.removeValue(forKey: key)
        familyCounts[key.family, default: 0] -= 1
        let addressKey = AddressKey(family: entry.address.family, bytes: entry.address.rawBytes)
        reverse.removeValue(forKey: addressKey)

        let eventIdentity = UUID()
        let releaseAt = deadline(after: configuration.reuseQuarantine, from: now)
        quarantined[addressKey] = QuarantineRecord(releaseAt: releaseAt, eventIdentity: eventIdentity)
        push(
            QuarantineItem(
                value: releaseAt,
                sequence: nextHeapSequence(),
                eventIdentity: eventIdentity,
                address: addressKey
            ),
            into: &quarantineHeap,
            less: quarantineLess
        )
    }

    private func releaseQuarantinedAddresses(at now: TimeInterval) {
        while let first = quarantineHeap.first, first.value <= now {
            _ = pop(from: &quarantineHeap, less: quarantineLess)
            guard let record = quarantined[first.address],
                  record.eventIdentity == first.eventIdentity,
                  record.releaseAt <= now
            else { continue }
            quarantined.removeValue(forKey: first.address)
            switch first.address.family {
            case .ipv4: ipv4Pool.recycle(first.address.bytes)
            case .ipv6: ipv6Pool.recycle(first.address.bytes)
            }
        }
    }

    private func compactHeapsIfNeeded() {
        let expiryThreshold = entries.count * 4 + 64
        if expiryHeap.count > expiryThreshold {
            expiryHeap = entries.map { key, entry in
                ExpiryItem(
                    value: deadline(after: configuration.correlationGrace, from: entry.expiresAt),
                    sequence: nextHeapSequence(),
                    eventIdentity: entry.expiryEventIdentity,
                    key: key
                )
            }
            heapify(&expiryHeap, less: expiryLess)
        }

        let quarantineThreshold = quarantined.count * 4 + 64
        if quarantineHeap.count > quarantineThreshold {
            quarantineHeap = quarantined.map { address, record in
                QuarantineItem(
                    value: record.releaseAt,
                    sequence: nextHeapSequence(),
                    eventIdentity: record.eventIdentity,
                    address: address
                )
            }
            heapify(&quarantineHeap, less: quarantineLess)
        }
    }

    private func deadline(after interval: TimeInterval, from start: TimeInterval) -> TimeInterval {
        let value = start + interval
        return value.isFinite ? value : .greatestFiniteMagnitude
    }

    private func nextHeapSequence() -> UInt64 {
        if heapSequence < UInt64.max { heapSequence += 1 }
        return heapSequence
    }

    private func expiryLess(_ lhs: ExpiryItem, _ rhs: ExpiryItem) -> Bool {
        lhs.value == rhs.value ? lhs.sequence < rhs.sequence : lhs.value < rhs.value
    }

    private func quarantineLess(_ lhs: QuarantineItem, _ rhs: QuarantineItem) -> Bool {
        lhs.value == rhs.value ? lhs.sequence < rhs.sequence : lhs.value < rhs.value
    }

    private func push<Item>(
        _ item: Item,
        into heap: inout [Item],
        less: (Item, Item) -> Bool
    ) {
        heap.append(item)
        var child = heap.count - 1
        while child > 0 {
            let parent = (child - 1) / 2
            guard less(heap[child], heap[parent]) else { break }
            heap.swapAt(child, parent)
            child = parent
        }
    }

    private func pop<Item>(from heap: inout [Item], less: (Item, Item) -> Bool) -> Item? {
        guard !heap.isEmpty else { return nil }
        if heap.count == 1 { return heap.removeLast() }
        let result = heap[0]
        heap[0] = heap.removeLast()
        var parent = 0
        while true {
            let left = parent * 2 + 1
            guard left < heap.count else { break }
            let right = left + 1
            let child = right < heap.count && less(heap[right], heap[left]) ? right : left
            guard less(heap[child], heap[parent]) else { break }
            heap.swapAt(child, parent)
            parent = child
        }
        return result
    }

    private func heapify<Item>(_ heap: inout [Item], less: (Item, Item) -> Bool) {
        guard heap.count > 1 else { return }
        for index in stride(from: heap.count / 2 - 1, through: 0, by: -1) {
            var parent = index
            while true {
                let left = parent * 2 + 1
                guard left < heap.count else { break }
                let right = left + 1
                let child = right < heap.count && less(heap[right], heap[left]) ? right : left
                guard less(heap[child], heap[parent]) else { break }
                heap.swapAt(child, parent)
                parent = child
            }
        }
    }
}
