import SwiftUI
import WebKit

/// NullRoute Browser for iOS: a WKWebView that applies the same compiled rule
/// lists as the Safari content blockers (so it works even before they're turned
/// on in Settings), lets ad *loaders* through so video players and ad-blocker
/// detectors don't trip (the ads themselves stay blocked), removes "turn off your
/// ad blocker" walls by their message, and refuses pop-up windows and redirects
/// into other apps.
struct BrowserView: View {
    @StateObject private var model = BrowserModel()
    @State private var address = ""
    @FocusState private var editing: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Button { model.webView.goBack() } label: { Image(systemName: "chevron.backward") }
                        .disabled(!model.canGoBack)
                        .accessibilityLabel("Back")
                    TextField("Search or type a web address", text: $address)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.webSearch)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.go)
                        .focused($editing)
                        .onSubmit { model.load(BrowserModel.url(from: address)) }
                    Button { model.webView.reload() } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel("Reload")
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                if model.progress < 1 {
                    ProgressView(value: model.progress).progressViewStyle(.linear)
                }
                Text(model.status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
                    .padding(.bottom, 4)
                WebViewContainer(webView: model.webView)
            }
            .navigationTitle("Browse")
            .navigationBarTitleDisplayMode(.inline)
            .onChange(of: model.currentURL) { url in
                if !editing { address = url }
            }
            .task { await model.prepare() }
        }
    }
}

private struct WebViewContainer: UIViewRepresentable {
    let webView: WKWebView
    func makeUIView(context: Context) -> WKWebView { webView }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

@MainActor
final class BrowserModel: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate {
    @Published var progress: Double = 1
    @Published var canGoBack = false
    @Published var currentURL = ""
    @Published var status = "Preparing filters…"

    let webView: WKWebView
    private var observations: [NSKeyValueObservation] = []
    private var ready = false
    private var pending: URL?

    override init() {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        if let source = Bundle.main.url(forResource: "antinag", withExtension: "js"),
           let js = try? String(contentsOf: source, encoding: .utf8) {
            // Ad-blocker walls are recognised by their message, not their (random) names.
            config.userContentController.addUserScript(
                WKUserScript(source: js, injectionTime: .atDocumentEnd, forMainFrameOnly: true))
        }
        webView = WKWebView(frame: .zero, configuration: config)
        super.init()
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        observations = [
            webView.observe(\.estimatedProgress) { [weak self] w, _ in
                Task { @MainActor in self?.progress = w.estimatedProgress }
            },
            webView.observe(\.canGoBack) { [weak self] w, _ in
                Task { @MainActor in self?.canGoBack = w.canGoBack }
            },
            webView.observe(\.url) { [weak self] w, _ in
                Task { @MainActor in self?.currentURL = w.url?.absoluteString ?? "" }
            },
        ]
    }

    /// Compiles (or looks up the cached) rule lists and attaches them.
    func prepare() async {
        guard !ready else { return }
        var count = 0
        for blocker in Blocker.allCases {
            if let list = await Self.ruleList(for: blocker) {
                webView.configuration.userContentController.add(list)
                count += 1
            }
        }
        ready = true
        status = count == Blocker.allCases.count
            ? "Ads, trackers and ad-blocker walls are removed in this browser."
            : "Some filter lists couldn't be loaded (\(count) of \(Blocker.allCases.count))."
        if let url = pending { pending = nil; webView.load(URLRequest(url: url)) }
    }

    func load(_ url: URL) {
        if ready { webView.load(URLRequest(url: url)) } else { pending = url }
    }

    static func url(from input: String) -> URL {
        let t = input.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("http://") || t.hasPrefix("https://"), let u = URL(string: t) { return u }
        if !t.contains(" "), t.contains("."), let u = URL(string: "https://\(t)") { return u }
        var c = URLComponents(string: "https://duckduckgo.com/")!
        c.queryItems = [URLQueryItem(name: "q", value: t)]
        return c.url!
    }

    /// The same JSON the Safari extension uses: the app's customised copy (downloaded
    /// lists + allowlist) when present, else the list inside the extension bundle.
    private static func ruleList(for blocker: Blocker) async -> WKContentRuleList? {
        let url = SharedStore.activeRulesURL(for: blocker) ?? Bundle.main.builtInPlugInsURL?
            .appendingPathComponent("Blocker\(blocker.rawValue.capitalized).appex")
            .appendingPathComponent(blocker.fileName)
        guard let url, let json = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let modified = (attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let id = "nr-\(blocker.rawValue)-\(json.utf8.count)-\(Int(modified))"
        guard let store = WKContentRuleListStore.default() else { return nil }
        let cached: WKContentRuleList? = await withCheckedContinuation { cont in
            store.lookUpContentRuleList(forIdentifier: id) { list, _ in cont.resume(returning: list) }
        }
        if let cached { return cached }
        return await withCheckedContinuation { cont in
            store.compileContentRuleList(forIdentifier: id, encodedContentRuleList: json) { list, _ in
                cont.resume(returning: list)
            }
        }
    }

    // MARK: WKNavigationDelegate

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // Ad redirects love app-store and custom-scheme links; stay on the web.
        let scheme = action.request.url?.scheme?.lowercased()
        decisionHandler(scheme == "http" || scheme == "https" || scheme == "about" || scheme == "data"
                        || scheme == "blob" ? .allow : .cancel)
    }

    // MARK: WKUIDelegate

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        // No pop-up windows. A user-tapped target=_blank link opens in this view instead.
        if action.navigationType == .linkActivated, let url = action.request.url {
            webView.load(URLRequest(url: url))
        }
        return nil
    }
}
