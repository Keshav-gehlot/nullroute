import CryptoKit
import Foundation
import SafariServices

/// Owns everything the app does to the Safari blockers: checking whether each
/// one is enabled, applying the user's allowed sites, and installing verified
/// list updates.
@MainActor
final class BlockerManager: ObservableObject {
    @Published private(set) var enabled: [Blocker: Bool] = [:]
    @Published private(set) var allowlist: [String]
    @Published private(set) var lastUpdated: Date?
    @Published private(set) var busy = false
    @Published var message: String?

    private let defaults = UserDefaults(suiteName: SharedStore.appGroup) ?? .standard

    init() {
        allowlist = defaults.stringArray(forKey: "allowlist") ?? []
        lastUpdated = defaults.object(forKey: "listsUpdatedAt") as? Date
    }

    var enabledCount: Int { enabled.values.filter { $0 }.count }

    // MARK: Status

    func refreshState() async {
        for blocker in Blocker.allCases {
            let on = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
                SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: blocker.bundleIdentifier) { state, _ in
                    cont.resume(returning: state?.isEnabled ?? false)
                }
            }
            enabled[blocker] = on
        }
    }

    // MARK: Allowed sites

    func allow(_ input: String) async {
        guard let domain = Self.normalize(input) else {
            message = "Enter a site like example.com"
            return
        }
        guard !allowlist.contains(domain) else { return }
        allowlist = (allowlist + [domain]).sorted()
        await applyAllowlist()
    }

    func remove(_ domain: String) async {
        allowlist.removeAll { $0 == domain }
        await applyAllowlist()
    }

    private func applyAllowlist() async {
        defaults.set(allowlist, forKey: "allowlist")
        busy = true
        defer { busy = false }
        do {
            let sites = allowlist
            try await Task.detached(priority: .userInitiated) { try Self.writeActiveRules(allowlist: sites) }.value
            try await reloadAll()
            message = nil
        } catch {
            message = "Couldn't apply allowed sites: \(error.localizedDescription)"
        }
    }

    /// Writes base rules + one trailing `ignore-previous-rules` rule per blocker
    /// into the App Group, where the extensions read them. The rule is appended
    /// by byte-splicing so multi-megabyte lists are never fully parsed.
    nonisolated private static func writeActiveRules(allowlist: [String]) throws {
        let fm = FileManager.default
        guard let container = SharedStore.container else { throw ManagerError.noAppGroup }
        let dir = container.appendingPathComponent("rules", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let hasDownloads = Blocker.allCases.contains { fm.fileExists(atPath: downloadedURL($0).path) }

        for blocker in Blocker.allCases {
            let target = dir.appendingPathComponent(blocker.fileName)
            if allowlist.isEmpty && !hasDownloads {
                try? fm.removeItem(at: target) // fall back to the bundled list
                continue
            }
            guard let base = baseRulesURL(blocker) else { throw ManagerError.missingList(blocker.title) }
            var data = try Data(contentsOf: base)
            if !allowlist.isEmpty {
                let rule: [String: Any] = [
                    "trigger": ["url-filter": ".*", "if-domain": allowlist.map { "*\($0)" }],
                    "action": ["type": "ignore-previous-rules"],
                ]
                let ruleData = try JSONSerialization.data(withJSONObject: rule)
                // Trim trailing whitespace and the closing bracket, then append.
                while let last = data.last, last == 0x0A || last == 0x20 || last == 0x0D { data.removeLast() }
                guard data.last == UInt8(ascii: "]") else { throw ManagerError.corruptList(blocker.title) }
                data.removeLast()
                data.append(contentsOf: Array(",".utf8))
                data.append(ruleData)
                data.append(contentsOf: Array("]\n".utf8))
            }
            try data.write(to: target, options: .atomic)
        }
    }

    /// Downloaded list if we have one, otherwise the copy inside the extension.
    nonisolated private static func baseRulesURL(_ blocker: Blocker) -> URL? {
        let fm = FileManager.default
        let downloaded = downloadedURL(blocker)
        if fm.fileExists(atPath: downloaded.path) { return downloaded }
        let appex = Bundle.main.builtInPlugInsURL?
            .appendingPathComponent("Blocker\(blocker.rawValue.capitalized).appex")
        return appex.flatMap { Bundle(url: $0)?.url(forResource: blocker.rawValue, withExtension: "json") }
    }

    nonisolated private static func downloadedURL(_ blocker: Blocker) -> URL {
        (SharedStore.container ?? FileManager.default.temporaryDirectory)
            .appendingPathComponent("lists", isDirectory: true)
            .appendingPathComponent(blocker.fileName)
    }

    private func reloadAll() async throws {
        for blocker in Blocker.allCases {
            try await SFContentBlockerManager.reloadContentBlocker(withIdentifier: blocker.bundleIdentifier)
        }
    }

    // MARK: List updates

    /// Fetches report.json, then every Safari list, verifying each against the
    /// SHA-256 in the report before anything is installed.
    func updateLists() async {
        guard let base = Bundle.main.object(forInfoDictionaryKey: "NullRouteListsBaseURL") as? String,
              let baseURL = URL(string: base) else { return }
        busy = true
        defer { busy = false }
        do {
            let (reportData, _) = try await Self.fetch(baseURL.appendingPathComponent("report.json"))
            guard let report = try JSONSerialization.jsonObject(with: reportData) as? [String: Any],
                  let files = report["files"] as? [String: String],
                  let version = report["generatedAt"] as? String
            else { throw ManagerError.badReport }
            if version == defaults.string(forKey: "listsVersion") {
                message = "Lists are already up to date"
                return
            }
            var staged: [(Blocker, Data)] = []
            for blocker in Blocker.allCases {
                guard let expected = files[blocker.reportPath] else { throw ManagerError.badReport }
                let (data, _) = try await Self.fetch(baseURL.appendingPathComponent(blocker.reportPath))
                let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                guard digest == expected.lowercased() else { throw ManagerError.checksum(blocker.title) }
                guard (try? JSONSerialization.jsonObject(with: data)) is [Any] else {
                    throw ManagerError.corruptList(blocker.title)
                }
                staged.append((blocker, data))
            }
            // Everything verified: install all lists together.
            let sites = allowlist
            let toInstall = staged  // immutable copy for the detached task
            try await Task.detached(priority: .userInitiated) {
                for (blocker, data) in toInstall {
                    let url = Self.downloadedURL(blocker)
                    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try data.write(to: url, options: .atomic)
                }
                try Self.writeActiveRules(allowlist: sites)
            }.value
            try await reloadAll()
            defaults.set(version, forKey: "listsVersion")
            lastUpdated = Date()
            defaults.set(lastUpdated, forKey: "listsUpdatedAt")
            message = "Lists updated"
        } catch {
            message = "Update failed: \(error.localizedDescription)"
        }
    }

    private static func fetch(_ url: URL) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
        request.setValue("NullRoute-iOS/1.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw ManagerError.http(url.lastPathComponent) }
        return (data, response)
    }

    // MARK: Helpers

    static func normalize(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let url = URL(string: s), let host = url.host { s = host }
        s = s.replacingOccurrences(of: "*.", with: "")
        if s.hasPrefix("www.") { s.removeFirst(4) }
        while s.hasSuffix(".") { s.removeLast() }
        let pattern = #"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.(?!-)[a-z0-9-]{1,63})+$"#
        return s.range(of: pattern, options: .regularExpression) != nil ? s : nil
    }
}

enum ManagerError: LocalizedError {
    case noAppGroup, badReport, missingList(String), corruptList(String), checksum(String), http(String)

    var errorDescription: String? {
        switch self {
        case .noAppGroup: return "The shared app group isn't configured."
        case .badReport: return "The list index couldn't be read."
        case .missingList(let n): return "The \(n) list is missing from the app."
        case .corruptList(let n): return "The \(n) list is damaged."
        case .checksum(let n): return "The \(n) list failed its integrity check, so it wasn't installed."
        case .http(let f): return "Couldn't download \(f)."
        }
    }
}
