import Foundation

public enum CredentialStoreError: Error, Equatable, Sendable {
    case notFound
    case invalidCredential
    case storageFailure
}

/// Secret-storage boundary. Implementations must not include credential bytes in errors,
/// descriptions, logs, or reflection output. Apple targets provide a Keychain adapter.
public protocol CredentialStore: Sendable {
    func loadAuthenticationToken() async throws -> AuthenticationToken
    func saveAuthenticationToken(_ token: AuthenticationToken) async throws
    func deleteAuthenticationToken() async throws
}
