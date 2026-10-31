import Foundation

public enum RuleImportTrust: String, Sendable {
    /// v0.2 has no signed-rule format. Imported files are trusted only as local input.
    case localImportOnly
}

public struct RuleStoreSnapshot: Sendable {
    public let generation: UInt64
    public let configuration: RoutingConfiguration
    public let engine: RuleEngine
    public let trust: RuleImportTrust
}

public enum RuleStoreError: Error, Equatable, Sendable {
    case noActiveRules
    case persistenceFailed
    case inputTooLarge(Int)
}

public protocol RulePersistence: Sendable {
    func persist(_ data: Data, to destination: URL) throws
}

/// Foundation's atomic write creates a same-directory temporary file and renames it
/// over the destination. The completed file is then synced on platforms where
/// `FileHandle.synchronize()` is available. Foundation does not expose directory fsync.
public struct AtomicRuleFilePersistence: RulePersistence {
    public init() {}

    public func persist(_ data: Data, to destination: URL) throws {
        do {
            try data.write(to: destination, options: .atomic)
            if let handle = try? FileHandle(forWritingTo: destination) {
                try? handle.synchronize()
                try? handle.close()
            }
        } catch {
            throw error
        }
    }
}

/// Validates and compiles a complete candidate before persisting or activating it.
/// A decode, compile, or persistence failure leaves the current generation unchanged.
public actor RuleStore {
    public static let maximumInputBytes = 32 * 1_024 * 1_024

    private let persistence: any RulePersistence
    private var active: RuleStoreSnapshot?
    private var nextGeneration: UInt64 = 1

    public init(persistence: any RulePersistence = AtomicRuleFilePersistence()) {
        self.persistence = persistence
    }

    public init(
        startupURL: URL,
        persistence: any RulePersistence = AtomicRuleFilePersistence()
    ) throws {
        self.persistence = persistence
        let data = try Data(contentsOf: startupURL)
        guard data.count <= Self.maximumInputBytes else {
            throw RuleStoreError.inputTooLarge(data.count)
        }
        let configuration = try RoutingConfiguration.decode(from: data)
        let engine = try RuleEngine(configuration: configuration)
        active = RuleStoreSnapshot(
            generation: 1,
            configuration: configuration,
            engine: engine,
            trust: .localImportOnly
        )
        nextGeneration = 2
    }

    @discardableResult
    public func importRules(from data: Data, persistTo destination: URL? = nil) throws -> RuleStoreSnapshot {
        guard data.count <= Self.maximumInputBytes else {
            throw RuleStoreError.inputTooLarge(data.count)
        }
        let configuration = try RoutingConfiguration.decode(from: data)
        let engine = try RuleEngine(configuration: configuration)
        if let destination {
            try persistence.persist(data, to: destination)
        }
        let snapshot = RuleStoreSnapshot(
            generation: nextGeneration,
            configuration: configuration,
            engine: engine,
            trust: .localImportOnly
        )
        nextGeneration &+= 1
        active = snapshot
        return snapshot
    }

    @discardableResult
    public func importRules(from source: URL, persistTo destination: URL? = nil) throws -> RuleStoreSnapshot {
        try importRules(from: Data(contentsOf: source), persistTo: destination)
    }

    public func snapshot() throws -> RuleStoreSnapshot {
        guard let active else { throw RuleStoreError.noActiveRules }
        return active
    }

    public var generation: UInt64 { active?.generation ?? 0 }
}
