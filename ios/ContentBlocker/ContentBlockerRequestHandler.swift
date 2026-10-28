import Foundation

/// Safari calls this when it (re)compiles the blocker. We hand back a JSON rule
/// list; WebKit compiles it to bytecode once and enforces it inside Safari, so
/// this extension never sees any browsing data.
final class ContentBlockerRequestHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let id = Bundle.main.object(forInfoDictionaryKey: "NullRouteBlockerID") as? String
        guard let blocker = id.flatMap(Blocker.init(rawValue:)),
              let url = SharedStore.activeRulesURL(for: blocker),
              let attachment = NSItemProvider(contentsOf: url)
        else {
            context.cancelRequest(withError: NSError(domain: "NullRoute", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Rule list missing"]))
            return
        }
        let item = NSExtensionItem()
        item.attachments = [attachment]
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }
}
