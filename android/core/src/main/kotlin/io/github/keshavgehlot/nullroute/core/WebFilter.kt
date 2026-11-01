package io.github.keshavgehlot.nullroute.core

import java.net.URI

/**
 * Request policy for the NullRoute Browser (an in-app WebView).
 *
 * Inside its own browser NullRoute sees full URLs, not just DNS names, so it can
 * do what a DNS sinkhole can't: hand a page a harmless stand-in for an ad loader
 * (so players and ad-blocker detectors think ads loaded) while still blocking
 * everything else the lists name.
 */
class WebFilter(private val matcher: () -> DomainMatcher) {
    sealed interface Action {
        data object Allow : Action
        data object Block : Action
        /** Serve assets/web/surrogates/[asset] as JavaScript instead of fetching. */
        data class Surrogate(val asset: String) : Action
    }

    data class SurrogateRule(val hosts: Set<String>, val pathPrefix: String, val asset: String)

    fun decide(url: String, isMainFrame: Boolean): Action {
        val uri = runCatching { URI(url) }.getOrNull() ?: return Action.Allow
        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") return Action.Allow
        val host = uri.host?.lowercase()?.trimEnd('.') ?: return Action.Allow
        val path = uri.rawPath ?: "/"
        if (!isMainFrame) {
            SURROGATES.firstOrNull { host in it.hosts && path.startsWith(it.pathPrefix) }
                ?.let { return Action.Surrogate(it.asset) }
        }
        // The page the user opened is never blocked here (the VPN/reputation layer
        // handles dangerous sites); everything it loads is.
        if (isMainFrame) return Action.Allow
        return if (matcher().verdict(host).blocked) Action.Block else Action.Allow
    }

    companion object {
        val SURROGATES = listOf(
            SurrogateRule(setOf("pagead2.googlesyndication.com"), "/pagead/js/adsbygoogle.js", "adsbygoogle.js"),
            SurrogateRule(setOf("securepubads.g.doubleclick.net", "www.googletagservices.com"), "/tag/js/gpt.js", "gpt.js"),
            SurrogateRule(setOf("imasdk.googleapis.com"), "/js/sdkloader/ima3", "ima3.js"),
            SurrogateRule(setOf("imasdk.googleapis.com"), "/js/sdkloader/ima3_dai", "ima3.js"),
            SurrogateRule(setOf("www.googletagmanager.com"), "/gtag/js", "noop.js"),
            SurrogateRule(setOf("www.googletagmanager.com"), "/gtm.js", "noop.js"),
            SurrogateRule(setOf("www.google-analytics.com"), "/analytics.js", "noop.js"),
            SurrogateRule(setOf("c.amazon-adsystem.com"), "/aax2/apstag.js", "noop.js"),
        )
    }
}
