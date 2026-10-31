import Foundation

public struct RoutingConfiguration: Equatable, Sendable {
    public static let currentVersion = 1
    public static let maximumRuleCount = 20_000

    public let version: Int
    public let generatedAt: String?
    public let rules: [RoutingRule]
    public let final: RoutingAction

    public init(
        version: Int = currentVersion,
        generatedAt: String? = nil,
        rules: [RoutingRule],
        final: RoutingAction
    ) throws {
        guard version == Self.currentVersion else {
            throw RoutingConfigurationError.unsupportedVersion(version)
        }
        guard rules.count <= Self.maximumRuleCount else {
            throw RoutingConfigurationError.tooManyRules(rules.count)
        }
        if let generatedAt, !Self.isRFC3339DateTime(generatedAt) {
            throw RoutingConfigurationError.invalidGeneratedAt(generatedAt)
        }
        self.version = version
        self.generatedAt = generatedAt
        self.rules = rules
        self.final = final
    }

    public static func decode(from data: Data) throws -> RoutingConfiguration {
        do {
            return try JSONDecoder().decode(RoutingConfiguration.self, from: data)
        } catch let error as RoutingConfigurationError {
            throw error
        } catch {
            throw RoutingConfigurationError.malformedJSON
        }
    }

    private static func isRFC3339DateTime(_ value: String) -> Bool {
        let pattern = #"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(?:Z|[+-]([0-9]{2}):([0-9]{2}))$"#
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(
                in: value,
                range: NSRange(value.startIndex..<value.endIndex, in: value)
              )
        else { return false }

        let string = value as NSString
        func integer(_ capture: Int) -> Int? {
            let range = match.range(at: capture)
            guard range.location != NSNotFound else { return nil }
            return Int(string.substring(with: range))
        }

        guard let year = integer(1),
              let month = integer(2),
              let day = integer(3),
              let hour = integer(4),
              let minute = integer(5),
              let second = integer(6),
              (1...12).contains(month),
              (0...23).contains(hour),
              (0...59).contains(minute),
              (0...60).contains(second)
        else { return false }

        let leapYear = year.isMultiple(of: 4)
            && (!year.isMultiple(of: 100) || year.isMultiple(of: 400))
        let daysPerMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard (1...daysPerMonth[month - 1]).contains(day) else { return false }

        if let offsetHour = integer(7), let offsetMinute = integer(8) {
            guard (0...23).contains(offsetHour), (0...59).contains(offsetMinute) else {
                return false
            }
        }
        return true
    }
}

extension RoutingConfiguration: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        let allowed = Set(["version", "generatedAt", "rules", "final"])
        if let unknown = container.allKeys.map(\.stringValue).first(where: { !allowed.contains($0) }) {
            throw RoutingConfigurationError.unknownKey(unknown)
        }

        guard let versionKey = AnyCodingKey(stringValue: "version"),
              let generatedAtKey = AnyCodingKey(stringValue: "generatedAt"),
              let rulesKey = AnyCodingKey(stringValue: "rules"),
              let finalKey = AnyCodingKey(stringValue: "final")
        else { throw RoutingConfigurationError.malformedJSON }

        let version = try container.decode(Int.self, forKey: versionKey)
        let generatedAt: String?
        if container.contains(generatedAtKey) {
            generatedAt = try container.decode(String.self, forKey: generatedAtKey)
        } else {
            generatedAt = nil
        }

        var rulesContainer = try container.nestedUnkeyedContainer(forKey: rulesKey)
        if let count = rulesContainer.count, count > Self.maximumRuleCount {
            throw RoutingConfigurationError.tooManyRules(count)
        }
        var rules: [RoutingRule] = []
        rules.reserveCapacity(rulesContainer.count ?? 0)
        while !rulesContainer.isAtEnd {
            guard rules.count < Self.maximumRuleCount else {
                throw RoutingConfigurationError.tooManyRules(rules.count + 1)
            }
            rules.append(try rulesContainer.decode(RoutingRule.self))
        }
        let final = try container.decode(RoutingAction.self, forKey: finalKey)
        try self.init(version: version, generatedAt: generatedAt, rules: rules, final: final)
    }
}
