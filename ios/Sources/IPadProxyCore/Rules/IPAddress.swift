import Foundation

public enum IPAddressFamily: Hashable, Sendable {
    case ipv4
    case ipv6
}

public struct IPAddress: Equatable, Sendable, CustomStringConvertible {
    public let family: IPAddressFamily
    private let bytes: [UInt8]

    public init(_ text: String) throws {
        if let bytes = Self.parseIPv4(text) {
            family = .ipv4
            self.bytes = bytes
        } else if let bytes = Self.parseIPv6(text) {
            family = .ipv6
            self.bytes = bytes
        } else {
            throw RoutingConfigurationError.invalidIPAddress(text)
        }
    }

    static func validated(family: IPAddressFamily, bytes: [UInt8]) -> IPAddress {
        IPAddress(family: family, bytes: bytes)
    }

    private init(family: IPAddressFamily, bytes: [UInt8]) {
        self.family = family
        self.bytes = bytes
    }

    var rawBytes: [UInt8] { bytes }

    public var description: String {
        switch family {
        case .ipv4:
            return bytes.map(String.init).joined(separator: ".")
        case .ipv6:
            return stride(from: 0, to: 16, by: 2).map {
                String(UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]), radix: 16)
            }.joined(separator: ":")
        }
    }

    private static func parseIPv4(_ text: String) -> [UInt8]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(4)
        for part in parts {
            guard !part.isEmpty,
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let value = UInt8(part)
            else { return nil }
            result.append(value)
        }
        return result
    }

    private static func parseIPv6(_ original: String) -> [UInt8]? {
        guard !original.isEmpty, !original.contains("%") else { return nil }
        var text = original

        if text.contains(".") {
            guard let lastColon = text.lastIndex(of: ":") else { return nil }
            let ipv4Text = String(text[text.index(after: lastColon)...])
            guard let ipv4 = parseIPv4(ipv4Text) else { return nil }
            let high = UInt16(ipv4[0]) << 8 | UInt16(ipv4[1])
            let low = UInt16(ipv4[2]) << 8 | UInt16(ipv4[3])
            text = String(text[..<lastColon]) + ":" + String(high, radix: 16) + ":" + String(low, radix: 16)
        }

        let compressedParts = text.components(separatedBy: "::")
        guard compressedParts.count <= 2 else { return nil }
        let hasCompression = compressedParts.count == 2

        func parseSide(_ side: String) -> [UInt16]? {
            if side.isEmpty { return [] }
            let tokens = side.split(separator: ":", omittingEmptySubsequences: false)
            var groups: [UInt16] = []
            groups.reserveCapacity(tokens.count)
            for token in tokens {
                guard (1...4).contains(token.count),
                      token.allSatisfy({ $0.isASCII && $0.isHexDigit }),
                      let value = UInt16(token, radix: 16)
                else { return nil }
                groups.append(value)
            }
            return groups
        }

        guard let left = parseSide(compressedParts[0]) else { return nil }
        let right: [UInt16]
        if hasCompression {
            guard let parsed = parseSide(compressedParts[1]) else { return nil }
            right = parsed
        } else {
            right = []
        }

        let explicitCount = left.count + right.count
        let groups: [UInt16]
        if hasCompression {
            guard explicitCount < 8 else { return nil }
            groups = left + Array(repeating: 0, count: 8 - explicitCount) + right
        } else {
            guard explicitCount == 8 else { return nil }
            groups = left
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        for group in groups {
            bytes.append(UInt8(group >> 8))
            bytes.append(UInt8(group & 0xff))
        }
        return bytes
    }
}

struct CIDR: Equatable, Sendable {
    let network: IPAddress
    let prefixLength: Int

    init(_ text: String) throws {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[1].isEmpty,
              parts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
              let prefix = Int(parts[1])
        else { throw RoutingConfigurationError.invalidCIDR(text) }

        let address: IPAddress
        do {
            address = try IPAddress(String(parts[0]))
        } catch {
            throw RoutingConfigurationError.invalidCIDR(text)
        }
        let bitCount = address.family == .ipv4 ? 32 : 128
        guard (0...bitCount).contains(prefix) else {
            throw RoutingConfigurationError.invalidCIDR(text)
        }

        let masked = Self.mask(address.rawBytes, prefixLength: prefix)
        network = IPAddress.validated(family: address.family, bytes: masked)
        prefixLength = prefix
    }

    func contains(_ address: IPAddress) -> Bool {
        guard address.family == network.family else { return false }
        return Self.mask(address.rawBytes, prefixLength: prefixLength) == network.rawBytes
    }

    private static func mask(_ bytes: [UInt8], prefixLength: Int) -> [UInt8] {
        bytes.enumerated().map { index, byte in
            let remaining = prefixLength - index * 8
            if remaining >= 8 { return byte }
            if remaining <= 0 { return 0 }
            let mask = UInt8(0xff << (8 - remaining))
            return byte & mask
        }
    }
}
