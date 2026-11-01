import Foundation

public enum FlowLimiterError: Error, Equatable, Sendable {
    case invalidConfiguration
    case openingLimitReached
    case activeLimitReached
    case udpLimitReached
    case invalidPermit
    case permitAlreadyActivated
}

public struct FlowLimiterSnapshot: Equatable, Sendable {
    public let opening: Int
    public let active: Int
    public let activeUDP: Int
    public let highWaterOpening: Int
    public let highWaterActive: Int
    public let highWaterUDP: Int
    public let rejectedOpening: UInt64
    public let rejectedActivation: UInt64

    public init(
        opening: Int,
        active: Int,
        activeUDP: Int,
        highWaterOpening: Int,
        highWaterActive: Int,
        highWaterUDP: Int,
        rejectedOpening: UInt64,
        rejectedActivation: UInt64
    ) {
        self.opening = opening
        self.active = active
        self.activeUDP = activeUDP
        self.highWaterOpening = highWaterOpening
        self.highWaterActive = highWaterActive
        self.highWaterUDP = highWaterUDP
        self.rejectedOpening = rejectedOpening
        self.rejectedActivation = rejectedActivation
    }
}

/// An unforgeable capability for one flow's opening or active reservation.
/// Only `FlowLimiter` can create a permit. Copies are harmless because state
/// transitions and release are validated by identity inside the limiter actor.
public struct FlowPermit: Sendable {
    public let kind: FlowLimiter.FlowKind
    fileprivate let limiterIdentity: UUID
    fileprivate let identity: UUID

    fileprivate init(kind: FlowLimiter.FlowKind, limiterIdentity: UUID, identity: UUID) {
        self.kind = kind
        self.limiterIdentity = limiterIdentity
        self.identity = identity
    }
}

/// Enforces separate opening, total-active, and active-UDP flow limits.
public actor FlowLimiter {
    public enum FlowKind: Sendable {
        case tcp
        case udp
    }

    public struct Configuration: Equatable, Sendable {
        public let maximumActive: Int
        public let maximumOpening: Int
        public let maximumUDP: Int

        public init(
            maximumActive: Int = 1_024,
            maximumOpening: Int = 128,
            maximumUDP: Int = 256
        ) throws {
            guard maximumActive > 0,
                  maximumOpening > 0,
                  maximumUDP > 0,
                  maximumUDP <= maximumActive
            else { throw FlowLimiterError.invalidConfiguration }
            self.maximumActive = maximumActive
            self.maximumOpening = maximumOpening
            self.maximumUDP = maximumUDP
        }
    }

    private enum PermitState: Sendable {
        case opening
        case active
    }

    private struct Record: Sendable {
        let kind: FlowKind
        var state: PermitState
    }

    private let configuration: Configuration
    private let limiterIdentity = UUID()
    private var records: [UUID: Record] = [:]
    private var opening = 0
    private var active = 0
    private var activeUDP = 0
    private var highWaterOpening = 0
    private var highWaterActive = 0
    private var highWaterUDP = 0
    private var rejectedOpening: UInt64 = 0
    private var rejectedActivation: UInt64 = 0

    public init(configuration: Configuration = try! Configuration()) {
        self.configuration = configuration
    }

    /// Reserves one opening slot without waiting.
    public func beginOpening(_ kind: FlowKind) throws -> FlowPermit {
        guard opening < configuration.maximumOpening else {
            increment(&rejectedOpening)
            throw FlowLimiterError.openingLimitReached
        }
        let identity = UUID()
        records[identity] = Record(kind: kind, state: .opening)
        opening += 1
        highWaterOpening = max(highWaterOpening, opening)
        return FlowPermit(kind: kind, limiterIdentity: limiterIdentity, identity: identity)
    }

    /// Converts an opening reservation into an active reservation atomically.
    public func activate(_ permit: FlowPermit) throws {
        guard permit.limiterIdentity == limiterIdentity,
              var record = records[permit.identity],
              record.kind == permit.kind
        else {
            increment(&rejectedActivation)
            throw FlowLimiterError.invalidPermit
        }
        guard record.state == .opening else {
            increment(&rejectedActivation)
            throw FlowLimiterError.permitAlreadyActivated
        }
        guard active < configuration.maximumActive else {
            increment(&rejectedActivation)
            throw FlowLimiterError.activeLimitReached
        }
        if record.kind == .udp, activeUDP >= configuration.maximumUDP {
            increment(&rejectedActivation)
            throw FlowLimiterError.udpLimitReached
        }

        record.state = .active
        records[permit.identity] = record
        opening -= 1
        active += 1
        if record.kind == .udp { activeUDP += 1 }
        highWaterActive = max(highWaterActive, active)
        highWaterUDP = max(highWaterUDP, activeUDP)
    }

    /// Releases either an opening or active permit. Returns false for foreign,
    /// invalid, or already released permits and never changes unrelated counts.
    @discardableResult
    public func release(_ permit: FlowPermit) -> Bool {
        guard permit.limiterIdentity == limiterIdentity,
              let record = records.removeValue(forKey: permit.identity),
              record.kind == permit.kind
        else { return false }

        switch record.state {
        case .opening:
            opening -= 1
        case .active:
            active -= 1
            if record.kind == .udp { activeUDP -= 1 }
        }
        return true
    }

    public var snapshot: FlowLimiterSnapshot {
        FlowLimiterSnapshot(
            opening: opening,
            active: active,
            activeUDP: activeUDP,
            highWaterOpening: highWaterOpening,
            highWaterActive: highWaterActive,
            highWaterUDP: highWaterUDP,
            rejectedOpening: rejectedOpening,
            rejectedActivation: rejectedActivation
        )
    }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }
}
