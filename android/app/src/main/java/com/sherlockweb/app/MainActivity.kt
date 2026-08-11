package com.sherlockweb.app

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.view.Menu
import android.view.MenuItem
import android.webkit.HttpAuthHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast

class MainActivity : Activity() {

    private lateinit var webView: WebView

    // Cached in memory only: entered once per session, reused for every
    // subsequent HTTP Basic challenge from the same server.
    private var authUser: String? = null
    private var authPass: String? = null

    private val prefs by lazy { getSharedPreferences("sherlock_web", MODE_PRIVATE) }

    private val serverUrl: String
        get() = prefs.getString(KEY_SERVER_URL, null) ?: BuildConfig.SERVER_URL

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this)
        setContentView(webView)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
        }

        webView.webViewClient = object : WebViewClient() {

            override fun onReceivedHttpAuthRequest(
                view: WebView,
                handler: HttpAuthHandler,
                host: String,
                realm: String
            ) {
                val user = authUser
                val pass = authPass
                if (user != null && pass != null) {
                    // Already unlocked this session: answer silently.
                    handler.proceed(user, pass)
                } else {
                    promptForCredentials(host, handler)
                }
            }
        }

        webView.loadUrl(serverUrl)
    }

    // -- HTTP Basic auth ------------------------------------------------------

    private fun promptForCredentials(host: String, handler: HttpAuthHandler) {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
        }
        val userField = EditText(this).apply { hint = "Username (any)" }
        val passField = EditText(this).apply {
            hint = "Password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(userField)
        layout.addView(passField)

        AlertDialog.Builder(this)
            .setTitle("Sign in required")
            .setMessage(host)
            .setView(layout)
            .setCancelable(false)
            .setPositiveButton("Sign in") { _, _ ->
                authUser = userField.text.toString()
                authPass = passField.text.toString()
                handler.proceed(authUser.orEmpty(), authPass.orEmpty())
            }
            .setNegativeButton("Cancel") { _, _ ->
                handler.cancel()
                Toast.makeText(this, "Authentication cancelled", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    // -- Overflow menu --------------------------------------------------------

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, MENU_SET_URL, 0, "Set server URL")
        menu.add(0, MENU_RELOAD, 1, "Reload")
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_SET_URL -> { showUrlDialog(); true }
            MENU_RELOAD -> { webView.reload(); true }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showUrlDialog() {
        val field = EditText(this).apply {
            setText(serverUrl)
            setSingleLine()
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSelection(text.length)
        }
        AlertDialog.Builder(this)
            .setTitle("Server URL")
            .setView(field)
            .setPositiveButton("Save") { _, _ ->
                val url = field.text.toString().trim()
                if (url.startsWith("http://") || url.startsWith("https://")) {
                    prefs.edit().putString(KEY_SERVER_URL, url).apply()
                    authUser = null  // server may differ: forget old credentials
                    authPass = null
                    webView.loadUrl(url)
                } else {
                    Toast.makeText(this, "URL must start with http:// or https://", Toast.LENGTH_LONG).show()
                }
            }
            .setNeutralButton("Reset") { _, _ ->
                prefs.edit().remove(KEY_SERVER_URL).apply()
                authUser = null
                authPass = null
                webView.loadUrl(BuildConfig.SERVER_URL)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // -- Navigation -----------------------------------------------------------

    @Deprecated("Simple WebView wrapper: goBack() first, then default behavior.")
    override fun onBackPressed() {
        if (webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }

    companion object {
        private const val KEY_SERVER_URL = "server_url"
        private const val MENU_SET_URL = 1
        private const val MENU_RELOAD = 2
    }
}
