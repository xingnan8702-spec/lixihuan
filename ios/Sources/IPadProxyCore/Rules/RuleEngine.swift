import Foundation

/// An order-preserving rule engine. Exact domains, suffixes, and ports are indexed;
/// keyword and CIDR rules retain bounded linear fallback. The smallest matching source
/// index always wins, so indexing never changes first-match semantics.
public struct RuleEngine: Sendable {
    private let rules: [CompiledRule]
    private let finalAction: RoutingAction
    private let exactDomains: [String: Int]
    private let domainSuffixes: [String: Int]
    private let ports: [UInt16: Int]
    private let keywordAndCIDRIndices: [Int]

    public init(configuration: RoutingConfiguration) throws {
        var compiled: [CompiledRule] = []
        var exact: [String: Int] = [:]
        var suffixes: [String: Int] = [:]
        var indexedPorts: [UInt16: Int] = [:]
        var fallback: [Int] = []
        compiled.reserveCapacity(configuration.rules.count)

        for (index, rule) in configuration.rules.enumerated() {
            let value = try CompiledRule(rule)
            compiled.append(value)
            switch value.matcher {
            case let .domain(domain):
                if exact[domain] == nil { exact[domain] = index }
            case let .domainSuffix(suffix):
                if suffixes[suffix] == nil { suffixes[suffix] = index }
            case let .port(port):
                if indexedPorts[port] == nil { indexedPorts[port] = index }
            case .domainKeyword, .cidr:
                fallback.append(index)
            }
        }
        rules = compiled
        finalAction = configuration.final
        exactDomains = exact
        domainSuffixes = suffixes
        ports = indexedPorts
        keywordAndCIDRIndices = fallback
    }

    public func action(for destination: RoutingDestination) -> RoutingAction {
        var earliest: Int?
        func consider(_ index: Int?) {
            guard let index else { return }
            if earliest == nil || index < earliest! { earliest = index }
        }

        if let domain = destination.domain {
            consider(exactDomains[domain])
            var suffix = domain
            while true {
                consider(domainSuffixes[suffix])
                guard let dot = suffix.firstIndex(of: ".") else { break }
                suffix = String(suffix[suffix.index(after: dot)...])
            }
        }
        consider(ports[destination.port])

        for index in keywordAndCIDRIndices {
            if let earliest, index >= earliest { break }
            if rules[index].matcher.matches(destination) { earliest = index }
        }
        return earliest.map { rules[$0].action } ?? finalAction
    }
}

private struct CompiledRule: Sendable {
    let matcher: RuleMatcher
    let action: RoutingAction

    init(_ rule: RoutingRule) throws {
        matcher = try RuleMatcher(type: rule.type, value: rule.value)
        action = rule.action
    }
}

enum RuleMatcher: Sendable {
    case domain(String)
    case domainSuffix(String)
    case domainKeyword(String)
    case cidr(CIDR)
    case port(UInt16)

    init(type: RoutingRuleType, value: String) throws {
        switch type {
        case .domain:
            self = .domain(try DomainNormalizer.normalizeRuleDomain(value))
        case .domainSuffix:
            self = .domainSuffix(try DomainNormalizer.normalizeRuleDomain(value))
        case .domainKeyword:
            self = .domainKeyword(try DomainNormalizer.normalizeKeyword(value))
        case .ipCIDR:
            self = .cidr(try CIDR(value))
        case .port:
            guard value.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let port = UInt16(value), port != 0
            else { throw RoutingConfigurationError.invalidPort(value) }
            self = .port(port)
        }
    }

    static func validate(type: RoutingRuleType, value: String) throws {
        _ = try RuleMatcher(type: type, value: value)
    }

    func matches(_ destination: RoutingDestination) -> Bool {
        switch self {
        case let .domain(expected):
            return destination.domain == expected
        case let .domainSuffix(suffix):
            guard let domain = destination.domain else { return false }
            return domain == suffix || domain.hasSuffix("." + suffix)
        case let .domainKeyword(keyword):
            return destination.domain?.contains(keyword) == true
        case let .cidr(cidr):
            guard let address = destination.ipAddress else { return false }
            return cidr.contains(address)
        case let .port(port):
            return destination.port == port
        }
    }
}

enum DomainNormalizer {
    static func normalize(_ value: String) throws -> String {
        var result = value.lowercased()
        while result.last == "." { result.removeLast() }
        guard !result.isEmpty, result.utf8.count <= 253 else {
            throw RoutingConfigurationError.invalidDomain(value)
        }
        return result
    }

    static func normalizeRuleDomain(_ value: String) throws -> String {
        let result = try normalize(value)
        guard !result.hasPrefix("."), !result.contains("..") else {
            throw RoutingConfigurationError.invalidDomain(value)
        }
        return result
    }

    static func normalizeKeyword(_ value: String) throws -> String {
        var result = value.lowercased()
        while result.last == "." { result.removeLast() }
        guard !result.isEmpty else { throw RoutingConfigurationError.invalidDomain(value) }
        return result
    }
}
