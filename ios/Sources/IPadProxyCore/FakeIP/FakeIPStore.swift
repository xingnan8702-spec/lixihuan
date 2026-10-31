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
        public let capacityPerFamily: Int

        public init(
            ipv4Network: [UInt8] = Self.defaultIPv4Network,
            ipv4PrefixLength: Int = 15,
            ipv6Network: [UInt8] = Self.defaultIPv6Network,
            ipv6PrefixLength: Int = 64,
            ttl: TimeInterval = 300,
            capacityPerFamily: Int = 4_096
        ) throws {
            guard ipv4Network.count == 4,
                  (1...30).contains(ipv4PrefixLength),
                  ipv6Network.count == 16,
                  (1...64).contains(ipv6PrefixLength),
                  ttl.isFinite, ttl > 0,
                  capacityPerFamily > 0
            else { throw FakeIPStoreError.invalidConfiguration }

            self.ipv4Network = Self.mask(ipv4Network, prefixLength: ipv4PrefixLength)
            self.ipv4PrefixLength = ipv4PrefixLength
            self.ipv6Network = Self.mask(ipv6Network, prefixLength: ipv6PrefixLength)
            self.ipv6PrefixLength = ipv6PrefixLength
            self.ttl = ttl
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
        let address: IPAddress
        var expiresAt: TimeInterval
        var generation: UInt64
    }

    private struct HeapItem: Sendable {
        let value: TimeInterval
        let generation: UInt64
        let key: MappingKey
    }

    private struct PoolState: Sendable {
        let network: [UInt8]
        let prefixLength: Int
        var nextHost: UInt64 = 3
        var recycled: [[UInt8]] = []

        var maximumHost: UInt64 {
            let hostBits = network.count * 8 - prefixLength
            return hostBits == 64 ? UInt64.max : (UInt64(1) << UInt64(hostBits)) - 1
        }

        mutating func allocate(family: IPAddressFamily) -> [UInt8]? {
            if let address = recycled.popLast() { return address }
            while nextHost <= maximumHost {
                let host = nextHost
                if nextHost == UInt64.max {
                    nextHost = UInt64.max
                } else {
                    nextHost += 1
                }
                if family == .ipv4, host == maximumHost { return nil }
                return address(host: host)
            }
            return nil
        }

        mutating func recycle(_ bytes: [UInt8]) {
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
    private var entries: [MappingKey: Entry] = [:]
    private var reverse: [AddressKey: MappingKey] = [:]
    private var expiryHeap: [HeapItem] = []
    private var generation: UInt64 = 0
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

    public func address(for domain: String, family: IPAddressFamily) async throws -> IPAddress {
        let normalized = try DomainNormalizer.normalizeRuleDomain(domain)
        let now = await clock.now()
        removeExpired(at: now)
        let key = MappingKey(domain: normalized, family: family)
        if var existing = entries[key] {
            touch(&existing, key: key)
            entries[key] = existing
            return existing.address
        }

        guard count(for: family) < configuration.capacityPerFamily else {
            // Never evict a live mapping: a flow may still be using its Fake IP.
            // Expired mappings were removed above; callers can retry after expiry.
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

        generation &+= 1
        let address = IPAddress.validated(family: family, bytes: bytes)
        let entry = Entry(address: address, expiresAt: now + configuration.ttl, generation: generation)
        entries[key] = entry
        familyCounts[family, default: 0] += 1
        reverse[AddressKey(family: family, bytes: bytes)] = key
        push(HeapItem(value: entry.expiresAt, generation: generation, key: key), into: &expiryHeap)
        compactHeapIfNeeded()
        return address
    }

    public func existingAddress(for domain: String, family: IPAddressFamily) async throws -> IPAddress? {
        let normalized = try DomainNormalizer.normalizeRuleDomain(domain)
        let now = await clock.now()
        removeExpired(at: now)
        return entries[MappingKey(domain: normalized, family: family)]?.address
    }

    public func domain(for address: IPAddress) async -> String? {
        let now = await clock.now()
        removeExpired(at: now)
        let addressKey = AddressKey(family: address.family, bytes: address.rawBytes)
        guard let key = reverse[addressKey], var entry = entries[key] else { return nil }
        touch(&entry, key: key)
        entries[key] = entry
        return key.domain
    }

    public func removeExpiredMappings() async {
        removeExpired(at: await clock.now())
    }

    public var mappingCount: Int { entries.count }

    private func count(for family: IPAddressFamily) -> Int {
        familyCounts[family, default: 0]
    }

    private func touch(_ entry: inout Entry, key: MappingKey) {
        generation &+= 1
        // Access does not extend DNS TTL. It only refreshes the heap generation
        // so stale heap records cannot remove a currently referenced entry early.
        entry.generation = generation
        push(HeapItem(value: entry.expiresAt, generation: generation, key: key), into: &expiryHeap)
        compactHeapIfNeeded()
    }

    private func removeExpired(at now: TimeInterval) {
        while let first = expiryHeap.first, first.value <= now {
            _ = pop(from: &expiryHeap)
            guard let entry = entries[first.key],
                  entry.generation == first.generation,
                  entry.expiresAt <= now
            else { continue }
            remove(first.key, entry: entry)
        }
    }

    private func remove(_ key: MappingKey, entry: Entry) {
        entries.removeValue(forKey: key)
        familyCounts[key.family, default: 0] -= 1
        reverse.removeValue(forKey: AddressKey(family: entry.address.family, bytes: entry.address.rawBytes))
        switch entry.address.family {
        case .ipv4: ipv4Pool.recycle(entry.address.rawBytes)
        case .ipv6: ipv6Pool.recycle(entry.address.rawBytes)
        }
    }

    private func compactHeapIfNeeded() {
        let threshold = entries.count * 4 + 64
        guard expiryHeap.count > threshold else { return }
        expiryHeap = entries.map {
            HeapItem(value: $0.value.expiresAt, generation: $0.value.generation, key: $0.key)
        }
        heapify(&expiryHeap)
    }

    private func push(_ item: HeapItem, into heap: inout [HeapItem]) {
        heap.append(item)
        var child = heap.count - 1
        while child > 0 {
            let parent = (child - 1) / 2
            guard less(heap[child], heap[parent]) else { break }
            heap.swapAt(child, parent)
            child = parent
        }
    }

    private func pop(from heap: inout [HeapItem]) -> HeapItem? {
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

    private func heapify(_ heap: inout [HeapItem]) {
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

    private func less(_ lhs: HeapItem, _ rhs: HeapItem) -> Bool {
        if lhs.value != rhs.value { return lhs.value < rhs.value }
        return lhs.generation < rhs.generation
    }
}
