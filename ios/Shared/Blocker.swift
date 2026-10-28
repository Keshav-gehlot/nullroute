import Foundation

/// The four Safari content blockers. Each one is its own app extension because
/// WebKit caps a single blocker at 150,000 rules.
enum Blocker: String, CaseIterable, Identifiable {
    case ads, privacy, hosts, cosmetic

    var id: String { rawValue }

    /// Must match PRODUCT_BUNDLE_IDENTIFIER in project.yml.
    var bundleIdentifier: String { "io.github.keshavgehlot.nullroute.\(rawValue)" }

    var title: String {
        switch self {
        case .ads: return "Ads"
        case .privacy: return "Trackers"
        case .hosts: return "Bad hosts"
        case .cosmetic: return "Element hiding"
        }
    }

    var detail: String {
        switch self {
        case .ads: return "EasyList ad servers and ad scripts"
        case .privacy: return "EasyPrivacy analytics and fingerprinting"
        case .hosts: return "Known ad and malware domains"
        case .cosmetic: return "Hides empty ad slots and banners"
        }
    }

    /// Name of the bundled list and of the customised copy in the App Group.
    var fileName: String { "\(rawValue).json" }

    /// Path inside report.json's "files" map for downloaded updates.
    var reportPath: String { "safari/\(fileName)" }
}

enum SharedStore {
    static let appGroup: String = {
        (Bundle.main.object(forInfoDictionaryKey: "NullRouteAppGroup") as? String)
            ?? "group.io.github.keshavgehlot.nullroute"
    }()

    static var container: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    /// Rules the extension should load: the app-written copy (downloaded list +
    /// allowlist) when present, otherwise the list bundled at build time.
    static func activeRulesURL(for blocker: Blocker, bundle: Bundle = .main) -> URL? {
        if let customised = container?.appendingPathComponent("rules").appendingPathComponent(blocker.fileName),
           FileManager.default.fileExists(atPath: customised.path) {
            return customised
        }
        return bundle.url(forResource: blocker.rawValue, withExtension: "json")
    }
}
