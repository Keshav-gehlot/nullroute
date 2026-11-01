package io.github.keshavgehlot.nullroute.core

import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebFilterTest {
    private val matcher = DomainMatcher(
        setOf("doubleclick.net", "googlesyndication.com", "googleapis.com", "tracker.example"),
        listAllowed = setOf("entitlements.jwplayer.com"),
        userAllowed = setOf("cdn.tracker.example"),
    )
    private val filter = WebFilter { matcher }

    @Test
    fun adLoadersGetStandInsSoDetectorsAndPlayersAreSatisfied() {
        assertEquals(WebFilter.Action.Surrogate("adsbygoogle.js"),
            filter.decide("https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1", false))
        assertEquals(WebFilter.Action.Surrogate("gpt.js"), filter.decide("https://securepubads.g.doubleclick.net/tag/js/gpt.js", false))
        assertEquals(WebFilter.Action.Surrogate("ima3.js"), filter.decide("https://imasdk.googleapis.com/js/sdkloader/ima3.js", false))
        assertEquals(WebFilter.Action.Surrogate("ima3.js"), filter.decide("https://imasdk.googleapis.com/js/sdkloader/ima3_debug.js", false))
    }

    @Test
    fun everythingElseOnTheListsIsBlockedButPagesAreNot() {
        assertEquals(WebFilter.Action.Block, filter.decide("https://googleads.g.doubleclick.net/pagead/ads?x=1", false))
        assertEquals(WebFilter.Action.Block, filter.decide("https://pagead2.googlesyndication.com/pagead/ads?x", false))
        assertEquals(WebFilter.Action.Block, filter.decide("https://px.tracker.example/p.gif", false))
        assertEquals(WebFilter.Action.Allow, filter.decide("https://cdn.tracker.example/app.js", false), "user allow wins")
        assertEquals(WebFilter.Action.Allow, filter.decide("https://cdn.jwplayer.com/v2/media/x", false))
        assertEquals(WebFilter.Action.Allow, filter.decide("https://tracker.example/", true), "the page itself loads")
        assertEquals(WebFilter.Action.Allow, filter.decide("data:text/plain,hi", false))
        assertEquals(WebFilter.Action.Allow, filter.decide("not a url", false))
    }

    @Test
    fun everySurrogateFileExists() {
        val dir = File("../app/src/main/assets/web/surrogates")
        for (rule in WebFilter.SURROGATES) assertTrue(File(dir, rule.asset).isFile, rule.asset)
    }
}
