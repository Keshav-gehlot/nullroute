package io.github.keshavgehlot.nullroute.ui

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import io.github.keshavgehlot.nullroute.NullRouteApp
import io.github.keshavgehlot.nullroute.core.DomainMatcher
import io.github.keshavgehlot.nullroute.core.WebFilter
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.URLEncoder

/**
 * NullRoute Browser: a WebView where NullRoute sees full URLs and page content,
 * so it can do what DNS filtering can't:
 *  - serve stand-ins for ad loaders (AdSense, GPT, the IMA video SDK), so video
 *    players and ad-blocker detectors think ads loaded while none are fetched;
 *  - hide ad slots with the generic element-hiding rules;
 *  - remove "turn off your ad blocker" walls by their message, whatever random
 *    ids and classes they use;
 *  - suppress pop-up windows and redirects to app-store / intent links.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun BrowserScreen(app: NullRouteApp, modifier: Modifier) {
    val context = LocalContext.current
    val focus = LocalFocusManager.current
    var address by remember { mutableStateOf("") }
    var progress by remember { mutableIntStateOf(100) }
    var canGoBack by remember { mutableStateOf(false) }
    var blocked by remember { mutableIntStateOf(0) }
    var standIns by remember { mutableIntStateOf(0) }

    val engine = remember {
        BrowserEngine(context, onPage = { url ->
            address = url; blocked = 0; standIns = 0
        }, onProgress = { progress = it }, onHistory = { canGoBack = it },
            onBlocked = { blocked++ }, onStandIn = { standIns++ })
    }
    LaunchedEffect(Unit) { engine.matcher = app.lists.matcher() }
    DisposableEffect(Unit) { onDispose { engine.webView.onPause() } }
    BackHandler(enabled = canGoBack || engine.inFullscreen) { engine.back() }

    Column(modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(start = 8.dp, end = 4.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { engine.back() }, enabled = canGoBack) {
                Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
            }
            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                singleLine = true,
                placeholder = { Text("Search or type a web address") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = {
                    focus.clearFocus()
                    engine.load(toUrl(address))
                }),
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = { engine.webView.reload() }) { Icon(Icons.Outlined.Refresh, contentDescription = "Reload") }
        }
        if (progress < 100) LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth().padding(top = 4.dp))
        Text(
            if (address.isBlank()) "Ads, trackers and \"turn off your ad blocker\" walls are removed in this browser."
            else "$blocked blocked · $standIns ad loaders faked on this page",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
        AndroidView(factory = { engine.webView.also { it.onResume() } }, modifier = Modifier.weight(1f).fillMaxWidth())
    }
}

private fun toUrl(input: String): String {
    val t = input.trim()
    if (t.startsWith("http://") || t.startsWith("https://")) return t
    if (!t.contains(' ') && t.contains('.')) return "https://$t"
    return "https://duckduckgo.com/?q=" + URLEncoder.encode(t, "UTF-8")
}

@SuppressLint("SetJavaScriptEnabled")
private class BrowserEngine(
    private val context: Context,
    private val onPage: (String) -> Unit,
    private val onProgress: (Int) -> Unit,
    private val onHistory: (Boolean) -> Unit,
    private val onBlocked: () -> Unit,
    private val onStandIn: () -> Unit,
) {
    @Volatile var matcher: DomainMatcher? = null
    private val filter = WebFilter { matcher ?: EMPTY }
    private val pageScript: String by lazy { buildPageScript(context) }
    private var fullscreenView: View? = null
    private var fullscreenCallback: WebChromeClient.CustomViewCallback? = null
    val inFullscreen get() = fullscreenView != null

    val webView: WebView = WebView(context).apply {
        layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.mediaPlaybackRequiresUserGesture = true
        // Pop-ups and pop-unders: no new windows, scripts can't open them.
        settings.setSupportMultipleWindows(false)
        settings.javaScriptCanOpenWindowsAutomatically = false
        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            WebViewCompat.addDocumentStartJavaScript(this, pageScript, setOf("*"))
        }
        webViewClient = Client()
        webChromeClient = Chrome()
    }

    fun load(url: String) = webView.loadUrl(url)

    fun back() {
        if (inFullscreen) fullscreenCallback?.onCustomViewHidden() else if (webView.canGoBack()) webView.goBack()
    }

    private inner class Client : WebViewClient() {
        override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
            when (val action = filter.decide(request.url.toString(), request.isForMainFrame)) {
                WebFilter.Action.Allow -> null
                WebFilter.Action.Block -> {
                    view.post { onBlocked() }
                    WebResourceResponse("text/plain", "utf-8", 204, "No Content", emptyMap(), ByteArrayInputStream(ByteArray(0)))
                }
                is WebFilter.Action.Surrogate -> {
                    view.post { onStandIn() }
                    WebResourceResponse("application/javascript", "utf-8",
                        context.assets.open("web/surrogates/${action.asset}"))
                }
            }

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            // Ad redirects love intent:, market: and app-store links; stay on the web.
            val scheme = request.url.scheme?.lowercase()
            return scheme != "http" && scheme != "https"
        }

        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            onPage(url)
            if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
                view.evaluateJavascript(pageScript, null) // older WebView: as early as we can
            }
        }

        override fun doUpdateVisitedHistory(view: WebView, url: String, isReload: Boolean) {
            onPage(url)
            onHistory(view.canGoBack())
        }
    }

    private inner class Chrome : WebChromeClient() {
        override fun onProgressChanged(view: WebView, newProgress: Int) = onProgress(newProgress)

        // Full-screen video.
        override fun onShowCustomView(view: View, callback: CustomViewCallback) {
            val decor = (context as? Activity)?.window?.decorView as? FrameLayout ?: return callback.onCustomViewHidden()
            fullscreenView = view
            fullscreenCallback = callback
            decor.addView(view, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        }

        override fun onHideCustomView() {
            val decor = (context as? Activity)?.window?.decorView as? FrameLayout
            fullscreenView?.let { decor?.removeView(it) }
            fullscreenView = null
            fullscreenCallback = null
        }
    }

    companion object {
        private val EMPTY = DomainMatcher(emptySet())

        /** Generic element hiding (skipping sites that opted out) + the ad-blocker wall remover. */
        fun buildPageScript(context: Context): String {
            val assets = context.assets
            val css = runCatching { assets.open("lists/web/generic.css").bufferedReader().use { it.readText() } }.getOrDefault("")
            val excluded = runCatching {
                assets.open("lists/web/generic-excluded.txt").bufferedReader().use { r ->
                    r.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
                }
            }.getOrDefault(emptyList())
            val antinag = assets.open("web/antinag.js").bufferedReader().use { it.readText() }
            return """
                (function () {
                  if (window.__nullrouteCss) return; window.__nullrouteCss = true;
                  var ex = new Set(${JSONArray(excluded)});
                  var p = location.hostname.split('.');
                  for (var i = 0; i < p.length - 1; i++) if (ex.has(p.slice(i).join('.'))) return;
                  var s = document.createElement('style');
                  s.textContent = ${JSONObject.quote(css)};
                  (document.head || document.documentElement).appendChild(s);
                })();
            """.trimIndent() + "\n" + antinag
        }
    }
}
