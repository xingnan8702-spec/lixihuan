#if canImport(Security)
import Foundation
import IPadProxyCore
import Security

/// Keychain-backed token storage for the containing app and Packet Tunnel extension.
/// Configure the same access group in both targets when sharing credentials.
public actor KeychainCredentialStore: CredentialStore {
    private let service: String
    private let account: String
    private let accessGroup: String?

    public init(service: String, account: String = "relay-token", accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }

    public func loadAuthenticationToken() async throws -> AuthenticationToken {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw CredentialStoreError.notFound }
        guard status == errSecSuccess, let data = item as? Data else {
            throw CredentialStoreError.storageFailure
        }
        do { return try AuthenticationToken(data) }
        catch { throw CredentialStoreError.invalidCredential }
    }

    public func saveAuthenticationToken(_ token: AuthenticationToken) async throws {
        let secret = token.dataRepresentation()
        let attributes: [String: Any] = [
            kSecValueData as String: secret,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = baseQuery
            item.merge(attributes) { _, new in new }
            status = SecItemAdd(item as CFDictionary, nil)
            // The containing app and extension are separate processes. If both add
            // concurrently, retry as an update after the other process wins.
            if status == errSecDuplicateItem {
                status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
            }
        }
        guard status == errSecSuccess else {
            throw CredentialStoreError.storageFailure
        }
    }

    public func deleteAuthenticationToken() async throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.storageFailure
        }
    }

    private var baseQuery: [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }
}
#endif
