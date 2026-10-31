#if canImport(UniformTypeIdentifiers)
import Foundation
import IPadProxyCore

struct RuleImportResult: Sendable {
    let generation: UInt64
    let ruleCount: Int
}

/// Imports one security-scoped JSON document into the App Group rules file.
/// RuleStore validates and compiles the candidate before its atomic persistence step,
/// so a failed import never replaces the previous on-disk rules.
actor RuleImportService {
    private let destinationURL: URL
    private let ruleStore: RuleStore

    init(destinationURL: URL, ruleStore: RuleStore = RuleStore()) {
        self.destinationURL = destinationURL
        self.ruleStore = ruleStore
    }

    /// Creates the strict v1 empty-rule/PROXY-final baseline only when no rules
    /// file exists. `.withoutOverwriting` closes the check/write race and never
    /// replaces an imported file.
    func ensureDefaultRulesIfMissing() async throws -> Bool {
        guard !FileManager.default.fileExists(atPath: destinationURL.path) else {
            return false
        }
        let data = Data(#"{"version":1,"rules":[],"final":"PROXY"}"#.utf8)
        let validator = RuleStore()
        _ = try await validator.importRules(from: data)
        do {
            try data.write(
                to: destinationURL,
                options: [.atomic, .withoutOverwriting, .completeFileProtection]
            )
            return true
        } catch let error as CocoaError where error.code == .fileWriteFileExists {
            return false
        }
    }

    func importRules(from sourceURL: URL) async throws -> RuleImportResult {
        let didAccessSecurityScope = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if didAccessSecurityScope {
                sourceURL.stopAccessingSecurityScopedResource()
            }
        }

        let data = try Self.readData(from: sourceURL, maximumBytes: RuleStore.maximumInputBytes)
        let snapshot = try await ruleStore.importRules(from: data, persistTo: destinationURL)
        return RuleImportResult(
            generation: snapshot.generation,
            ruleCount: snapshot.configuration.rules.count
        )
    }

    private static func readData(from url: URL, maximumBytes: Int) throws -> Data {
        let resourceValues = try? url.resourceValues(forKeys: [.fileSizeKey])
        if let fileSize = resourceValues?.fileSize, fileSize > maximumBytes {
            throw RuleStoreError.inputTooLarge(fileSize)
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let chunkSize = 64 * 1_024
        var data = Data()
        data.reserveCapacity(min(resourceValues?.fileSize ?? 0, maximumBytes))

        while let chunk = try handle.read(upToCount: chunkSize), !chunk.isEmpty {
            let (newCount, overflow) = data.count.addingReportingOverflow(chunk.count)
            guard !overflow, newCount <= maximumBytes else {
                throw RuleStoreError.inputTooLarge(newCount)
            }
            data.append(chunk)
        }
        return data
    }
}
#endif
