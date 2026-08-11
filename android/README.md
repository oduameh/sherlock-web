# Sherlock Web — Android app

A minimal Kotlin WebView wrapper around the deployed Sherlock Web app. The APK is
built by GitHub Actions (`.github/workflows/android-apk.yml` in the repo root) —
no local Android SDK needed.

## What it does

- Full-screen WebView (JavaScript + DOM storage enabled) loading your Railway URL
- Default URL baked in at build time via `BuildConfig.SERVER_URL`
- Overflow menu → **Set server URL** to override at runtime (persisted in
  SharedPreferences; **Reset** restores the build-time default)
- If the server has `APP_PASSWORD` set, the app prompts once for the Basic-auth
  credentials and reuses them for the rest of the session
- Back button navigates back inside the WebView before closing the app

## Build the APK

The workflow runs automatically on pushes to `main` that touch `android/**`,
and manually via **Actions → Android APK → Run workflow**.

1. In the GitHub repo, go to **Settings → Secrets and variables → Actions →
   Variables** and add a variable named `SERVER_URL` with your Railway URL,
   e.g. `https://sherlock-web-production.up.railway.app`. (If you skip this,
   the APK is built with the placeholder URL and you must set the real URL
   in the app's overflow menu.)
2. Run the workflow (or push a change under `android/`).
3. Open the workflow run, download the `sherlock-web-apk` artifact, unzip it
   and install `app-debug.apk` on your phone (allow "install from unknown
   sources").

## Local build (optional)

With JDK 17 and Gradle 8.9 installed:

```bash
gradle -p android assembleDebug -PSERVER_URL=https://your-app.up.railway.app
# APK: android/app/build/outputs/apk/debug/app-debug.apk
```

No Gradle wrapper is committed; `SERVER_URL` can also come from the environment.

## Stack

AGP 8.5.2 · Kotlin 2.0.0 · Gradle 8.9 · JDK 17 · compileSdk 34 · minSdk 24
