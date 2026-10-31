import Foundation

public enum RoutingAction: String, Codable, Equatable, Sendable {
    case direct = "DIRECT"
    case proxy = "PROXY"
    case reject = "REJECT"
}

public enum RoutingRuleType: String, Codable, Equatable, Sendable {
    case domain
    case domainSuffix = "domain_suffix"
    case domainKeyword = "domain_keyword"
    case ipCIDR = "ip_cidr"
    case port
}

public enum RoutingConfigurationError: Error, Equatable, Sendable {
    case malformedJSON
    case unknownKey(String)
    case unsupportedVersion(Int)
    case invalidGeneratedAt(String)
    case tooManyRules(Int)
    case invalidValueLength(Int)
    case invalidDomain(String)
    case invalidIPAddress(String)
    case invalidCIDR(String)
    case invalidPort(String)
    case missingDestinationHost
    case zeroPort
}

public struct RoutingRule: Equatable, Sendable {
    public let type: RoutingRuleType
    public let value: String
    public let action: RoutingAction

    public init(type: RoutingRuleType, value: String, action: RoutingAction) throws {
        let scalarCount = value.unicodeScalars.count
        guard (1...1_024).contains(scalarCount) else {
            throw RoutingConfigurationError.invalidValueLength(scalarCount)
        }
        try RuleMatcher.validate(type: type, value: value)
        self.type = type
        self.value = value
        self.action = action
    }
}

public struct RoutingDestination: Equatable, Sendable {
    public let domain: String?
    public let ipAddress: IPAddress?
    public let port: UInt16

    public init(domain: String? = nil, ipAddress: IPAddress? = nil, port: UInt16) throws {
        guard port != 0 else { throw RoutingConfigurationError.zeroPort }
        let normalizedDomain = try domain.map(DomainNormalizer.normalize)
        guard normalizedDomain != nil || ipAddress != nil else {
            throw RoutingConfigurationError.missingDestinationHost
        }
        self.domain = normalizedDomain
        self.ipAddress = ipAddress
        self.port = port
    }
}

struct AnyCodingKey: CodingKey {
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

extension RoutingRule: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        let allowed = Set(["type", "value", "action"])
        if let unknown = container.allKeys.map(\.stringValue).first(where: { !allowed.contains($0) }) {
            throw RoutingConfigurationError.unknownKey(unknown)
        }
        guard let typeKey = AnyCodingKey(stringValue: "type"),
              let valueKey = AnyCodingKey(stringValue: "value"),
              let actionKey = AnyCodingKey(stringValue: "action")
        else { throw RoutingConfigurationError.malformedJSON }
        let type = try container.decode(RoutingRuleType.self, forKey: typeKey)
        let value = try container.decode(String.self, forKey: valueKey)
        let action = try container.decode(RoutingAction.self, forKey: actionKey)
        try self.init(type: type, value: value, action: action)
    }
}
