import Foundation

public enum TunnelFlowKind: String, Codable, Equatable, Sendable {
    case tcp
    case udp
}

public enum TunnelTrafficDirection: String, Codable, Equatable, Sendable {
    case upload
    case download
}

/// Stable, privacy-preserving categories. Never add an associated value or an
/// underlying error description to this wire type.
public enum TunnelTerminalErrorCategory: String, Codable, Equatable, Sendable {
    case providerStartup
    case networkSettings
    case bridge
    case udpRelay
    case dns
    case transport
    case hevImmediateExit
    case hevRuntimeExit
    case hevStopTimeout
}

/// Aggregate-only diagnostics. This type intentionally has no destination,
/// domain, address, port, token, path, packet, or error-description field.
public struct TunnelDiagnosticsSnapshot: Codable, Equatable, Sendable {
    public let timestamp: Date
    public let uptime: TimeInterval
    public let activeTCP: UInt64
    public let highWaterTCP: UInt64
    public let activeUDP: UInt64
    public let highWaterUDP: UInt64
    public let bytesUp: UInt64
    public let bytesDown: UInt64
    public let packetsUp: UInt64
    public let packetsDown: UInt64
    public let dnsTotal: UInt64
    public let dnsFailures: UInt64
    public let rejectedFlows: UInt64
    public let resourceRejections: UInt64
    public let transportFailures: UInt64
    public let lastTerminalErrorCategory: TunnelTerminalErrorCategory?

    public init(
        timestamp: Date,
        uptime: TimeInterval,
        activeTCP: UInt64,
        highWaterTCP: UInt64,
        activeUDP: UInt64,
        highWaterUDP: UInt64,
        bytesUp: UInt64,
        bytesDown: UInt64,
        packetsUp: UInt64,
        packetsDown: UInt64,
        dnsTotal: UInt64,
        dnsFailures: UInt64,
        rejectedFlows: UInt64,
        resourceRejections: UInt64,
        transportFailures: UInt64,
        lastTerminalErrorCategory: TunnelTerminalErrorCategory?
    ) {
        self.timestamp = timestamp
        self.uptime = uptime
        self.activeTCP = activeTCP
        self.highWaterTCP = highWaterTCP
        self.activeUDP = activeUDP
        self.highWaterUDP = highWaterUDP
        self.bytesUp = bytesUp
        self.bytesDown = bytesDown
        self.packetsUp = packetsUp
        self.packetsDown = packetsDown
        self.dnsTotal = dnsTotal
        self.dnsFailures = dnsFailures
        self.rejectedFlows = rejectedFlows
        self.resourceRejections = resourceRejections
        self.transportFailures = transportFailures
        self.lastTerminalErrorCategory = lastTerminalErrorCategory
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case timestamp
        case uptime
        case activeTCP
        case highWaterTCP
        case activeUDP
        case highWaterUDP
        case bytesUp
        case bytesDown
        case packetsUp
        case packetsDown
        case dnsTotal
        case dnsFailures
        case rejectedFlows
        case resourceRejections
        case transportFailures
        case lastTerminalErrorCategory
    }

    public init(from decoder: Decoder) throws {
        try Self.rejectUnknownKeys(decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        uptime = try container.decode(TimeInterval.self, forKey: .uptime)
        guard uptime.isFinite, uptime >= 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .uptime,
                in: container,
                debugDescription: "Invalid uptime"
            )
        }
        activeTCP = try container.decode(UInt64.self, forKey: .activeTCP)
        highWaterTCP = try container.decode(UInt64.self, forKey: .highWaterTCP)
        activeUDP = try container.decode(UInt64.self, forKey: .activeUDP)
        highWaterUDP = try container.decode(UInt64.self, forKey: .highWaterUDP)
        bytesUp = try container.decode(UInt64.self, forKey: .bytesUp)
        bytesDown = try container.decode(UInt64.self, forKey: .bytesDown)
        packetsUp = try container.decode(UInt64.self, forKey: .packetsUp)
        packetsDown = try container.decode(UInt64.self, forKey: .packetsDown)
        dnsTotal = try container.decode(UInt64.self, forKey: .dnsTotal)
        dnsFailures = try container.decode(UInt64.self, forKey: .dnsFailures)
        rejectedFlows = try container.decode(UInt64.self, forKey: .rejectedFlows)
        resourceRejections = try container.decode(UInt64.self, forKey: .resourceRejections)
        transportFailures = try container.decode(UInt64.self, forKey: .transportFailures)
        lastTerminalErrorCategory = try container.decodeIfPresent(
            TunnelTerminalErrorCategory.self,
            forKey: .lastTerminalErrorCategory
        )
        guard highWaterTCP >= activeTCP, highWaterUDP >= activeUDP else {
            throw DecodingError.dataCorruptedError(
                forKey: .highWaterTCP,
                in: container,
                debugDescription: "High-water mark is below active count"
            )
        }
    }

    private static func rejectUnknownKeys(_ decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: TunnelDiagnosticsAnyCodingKey.self)
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        if let unknown = dynamic.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(
                forKey: unknown,
                in: dynamic,
                debugDescription: "Unknown field"
            )
        }
    }
}

public protocol TunnelDiagnosticsSource: Sendable {
    func diagnosticsSnapshot() async -> TunnelDiagnosticsSnapshot
    func resetDiagnostics() async -> TunnelDiagnosticsSnapshot
}

/// Actor-isolated, saturating aggregate counters for one tunnel generation.
public actor TunnelDiagnostics: TunnelDiagnosticsSource {
    private let wallClock: @Sendable () -> Date
    private let uptimeClock: @Sendable () -> UInt64
    private var startedAt: UInt64
    private var activeTCP: UInt64 = 0
    private var highWaterTCP: UInt64 = 0
    private var activeUDP: UInt64 = 0
    private var highWaterUDP: UInt64 = 0
    private var bytesUp: UInt64 = 0
    private var bytesDown: UInt64 = 0
    private var packetsUp: UInt64 = 0
    private var packetsDown: UInt64 = 0
    private var dnsTotal: UInt64 = 0
    private var dnsFailures: UInt64 = 0
    private var rejectedFlows: UInt64 = 0
    private var resourceRejections: UInt64 = 0
    private var transportFailures: UInt64 = 0
    private var lastTerminalErrorCategory: TunnelTerminalErrorCategory?

    public init() {
        wallClock = { Date() }
        uptimeClock = { DispatchTime.now().uptimeNanoseconds }
        startedAt = DispatchTime.now().uptimeNanoseconds
    }

    init(
        wallClock: @escaping @Sendable () -> Date,
        uptimeClock: @escaping @Sendable () -> UInt64
    ) {
        self.wallClock = wallClock
        self.uptimeClock = uptimeClock
        startedAt = uptimeClock()
    }

    public func recordTunnelStarted() {
        startedAt = uptimeClock()
    }

    public func recordTunnelStopped() {
        // Deliberately no cumulative lifecycle field in the public snapshot.
    }

    public func recordFlowActivated(_ kind: TunnelFlowKind, count: UInt64 = 1) {
        switch kind {
        case .tcp:
            activeTCP = Self.add(activeTCP, count)
            highWaterTCP = max(highWaterTCP, activeTCP)
        case .udp:
            activeUDP = Self.add(activeUDP, count)
            highWaterUDP = max(highWaterUDP, activeUDP)
        }
    }

    public func recordFlowClosed(_ kind: TunnelFlowKind, count: UInt64 = 1) {
        switch kind {
        case .tcp: activeTCP = Self.subtract(activeTCP, count)
        case .udp: activeUDP = Self.subtract(activeUDP, count)
        }
    }

    public func recordTraffic(
        _ direction: TunnelTrafficDirection,
        bytes: UInt64,
        packets: UInt64 = 1
    ) {
        switch direction {
        case .upload:
            bytesUp = Self.add(bytesUp, bytes)
            packetsUp = Self.add(packetsUp, packets)
        case .download:
            bytesDown = Self.add(bytesDown, bytes)
            packetsDown = Self.add(packetsDown, packets)
        }
    }

    public func recordDNSQuery(count: UInt64 = 1) {
        dnsTotal = Self.add(dnsTotal, count)
    }

    public func recordDNSFailure(count: UInt64 = 1) {
        dnsFailures = Self.add(dnsFailures, count)
    }

    public func recordRejectedFlow(count: UInt64 = 1) {
        rejectedFlows = Self.add(rejectedFlows, count)
    }

    public func recordResourceRejection(count: UInt64 = 1) {
        resourceRejections = Self.add(resourceRejections, count)
    }

    public func recordTransportFailure(count: UInt64 = 1) {
        transportFailures = Self.add(transportFailures, count)
    }

    public func recordTerminalError(_ category: TunnelTerminalErrorCategory) {
        lastTerminalErrorCategory = category
    }

    public func diagnosticsSnapshot() -> TunnelDiagnosticsSnapshot {
        snapshotValue()
    }

    public func resetDiagnostics() -> TunnelDiagnosticsSnapshot {
        highWaterTCP = activeTCP
        highWaterUDP = activeUDP
        bytesUp = 0
        bytesDown = 0
        packetsUp = 0
        packetsDown = 0
        dnsTotal = 0
        dnsFailures = 0
        rejectedFlows = 0
        resourceRejections = 0
        transportFailures = 0
        lastTerminalErrorCategory = nil
        startedAt = uptimeClock()
        return snapshotValue()
    }

    public var snapshot: TunnelDiagnosticsSnapshot { snapshotValue() }

    private func snapshotValue() -> TunnelDiagnosticsSnapshot {
        let now = uptimeClock()
        let elapsed = now >= startedAt ? now - startedAt : 0
        let wallNow = wallClock()
        let timestampMilliseconds = floor(wallNow.timeIntervalSince1970 * 1_000)
        let timestamp = Date(timeIntervalSince1970: timestampMilliseconds / 1_000)
        return TunnelDiagnosticsSnapshot(
            timestamp: timestamp,
            uptime: TimeInterval(elapsed) / 1_000_000_000,
            activeTCP: activeTCP,
            highWaterTCP: highWaterTCP,
            activeUDP: activeUDP,
            highWaterUDP: highWaterUDP,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            packetsUp: packetsUp,
            packetsDown: packetsDown,
            dnsTotal: dnsTotal,
            dnsFailures: dnsFailures,
            rejectedFlows: rejectedFlows,
            resourceRejections: resourceRejections,
            transportFailures: transportFailures,
            lastTerminalErrorCategory: lastTerminalErrorCategory
        )
    }

    private static func add(_ value: UInt64, _ amount: UInt64) -> UInt64 {
        let (result, overflow) = value.addingReportingOverflow(amount)
        return overflow ? UInt64.max : result
    }

    private static func subtract(_ value: UInt64, _ amount: UInt64) -> UInt64 {
        value >= amount ? value - amount : 0
    }
}

public enum TunnelDiagnosticsOperation: String, Codable, Equatable, Sendable {
    case snapshot
    case reset
}

public struct TunnelDiagnosticsRequest: Codable, Equatable, Sendable {
    public static let schemaVersion = 1
    public let version: Int
    public let operation: TunnelDiagnosticsOperation

    public init(operation: TunnelDiagnosticsOperation, version: Int = schemaVersion) {
        self.version = version
        self.operation = operation
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case operation
    }

    public init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: TunnelDiagnosticsAnyCodingKey.self)
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        if let unknown = dynamic.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(
                forKey: unknown,
                in: dynamic,
                debugDescription: "Unknown field"
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        operation = try container.decode(TunnelDiagnosticsOperation.self, forKey: .operation)
    }
}

public enum TunnelDiagnosticsResponseError: String, Codable, Equatable, Sendable {
    case invalidRequest
    case messageTooLarge
    case unsupportedVersion
    case unavailable
    case encodingFailure
}

public struct TunnelDiagnosticsResponse: Codable, Equatable, Sendable {
    public static let schemaVersion = 1
    public let version: Int
    public let snapshot: TunnelDiagnosticsSnapshot?
    public let error: TunnelDiagnosticsResponseError?

    public static func success(_ snapshot: TunnelDiagnosticsSnapshot) -> Self {
        Self(version: schemaVersion, snapshot: snapshot, error: nil)
    }

    public static func failure(_ error: TunnelDiagnosticsResponseError) -> Self {
        Self(version: schemaVersion, snapshot: nil, error: error)
    }

    private init(
        version: Int,
        snapshot: TunnelDiagnosticsSnapshot?,
        error: TunnelDiagnosticsResponseError?
    ) {
        self.version = version
        self.snapshot = snapshot
        self.error = error
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case snapshot
        case error
    }

    public init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: TunnelDiagnosticsAnyCodingKey.self)
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        if let unknown = dynamic.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(
                forKey: unknown,
                in: dynamic,
                debugDescription: "Unknown field"
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        snapshot = try container.decodeIfPresent(TunnelDiagnosticsSnapshot.self, forKey: .snapshot)
        error = try container.decodeIfPresent(TunnelDiagnosticsResponseError.self, forKey: .error)
        guard (snapshot != nil) != (error != nil) else {
            throw DecodingError.dataCorruptedError(
                forKey: .snapshot,
                in: container,
                debugDescription: "Response must contain exactly one result"
            )
        }
    }
}

public enum TunnelDiagnosticsCodecError: Error, Equatable, Sendable {
    case emptyMessage
    case messageTooLarge
    case invalidMessage
    case unsupportedVersion
}

public enum TunnelDiagnosticsMessageCodec {
    public static let maximumMessageBytes = 64 * 1_024

    public static func encodeRequest(_ request: TunnelDiagnosticsRequest) throws -> Data {
        try encode(request)
    }

    public static func decodeRequest(_ data: Data) throws -> TunnelDiagnosticsRequest {
        let request: TunnelDiagnosticsRequest = try decode(data)
        guard request.version == TunnelDiagnosticsRequest.schemaVersion else {
            throw TunnelDiagnosticsCodecError.unsupportedVersion
        }
        return request
    }

    public static func encodeResponse(_ response: TunnelDiagnosticsResponse) throws -> Data {
        try encode(response)
    }

    public static func decodeResponse(_ data: Data) throws -> TunnelDiagnosticsResponse {
        let response: TunnelDiagnosticsResponse = try decode(data)
        guard response.version == TunnelDiagnosticsResponse.schemaVersion else {
            throw TunnelDiagnosticsCodecError.unsupportedVersion
        }
        return response
    }

    private static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        do {
            let data = try encoder.encode(value)
            guard data.count <= maximumMessageBytes else {
                throw TunnelDiagnosticsCodecError.messageTooLarge
            }
            return data
        } catch let error as TunnelDiagnosticsCodecError {
            throw error
        } catch {
            throw TunnelDiagnosticsCodecError.invalidMessage
        }
    }

    private static func decode<Value: Decodable>(_ data: Data) throws -> Value {
        guard !data.isEmpty else { throw TunnelDiagnosticsCodecError.emptyMessage }
        guard data.count <= maximumMessageBytes else {
            throw TunnelDiagnosticsCodecError.messageTooLarge
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        do {
            return try decoder.decode(Value.self, from: data)
        } catch let error as TunnelDiagnosticsCodecError {
            throw error
        } catch {
            throw TunnelDiagnosticsCodecError.invalidMessage
        }
    }
}

private struct TunnelDiagnosticsAnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}
