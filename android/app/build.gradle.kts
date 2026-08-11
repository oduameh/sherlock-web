plugins {
    id("com.android.application")
    kotlin("android")
}

// Server URL baked into the APK. Override with:
//   gradle -p android assembleDebug -PSERVER_URL=https://your-app.up.railway.app
// or a SERVER_URL environment variable (the GitHub Actions workflow does this).
val serverUrl: String = providers.gradleProperty("SERVER_URL")
    .orElse(providers.environmentVariable("SERVER_URL"))
    .filter { it.isNotBlank() }
    .orElse("https://REPLACE-WITH-YOUR-RAILWAY-URL.up.railway.app")
    .get()

android {
    namespace = "com.sherlockweb.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.sherlockweb.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        buildConfigField("String", "SERVER_URL", "\"$serverUrl\"")
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}
