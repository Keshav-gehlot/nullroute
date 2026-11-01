import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Compiled lists come from the repo's filter compiler (../../dist/dns, ../../dist/rep).
val listsDir = rootProject.file("../dist/dns")
val generatedAssets = layout.buildDirectory.dir("generated/lists")
val syncLists by tasks.registering(Copy::class) {
    description = "Bundles the compiled DNS blocklist into the APK"
    // Plain local values only: the configuration cache can't serialise script references.
    val blocklist = listsDir.resolve("blocklist.txt")
    val listsPath = listsDir.path
    doFirst {
        if (!blocklist.exists()) {
            throw GradleException(
                "No compiled blocklist at $listsPath. Run the compiler first:\n" +
                    "  cd compiler && python -m nullroute_compiler --out ../dist"
            )
        }
    }
    from(listsDir) { include("blocklist.txt", "allowlist.txt", "cname_targets.txt", "dga_model.txt", "compat.txt") }
    from(listsDir.resolve("../rep")) { include("prefixes.rice") }  // reputation prefix set (~3.7 MB)
    into(generatedAssets.map { it.dir("lists") })
}

val signing = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "io.github.keshavgehlot.nullroute"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.keshavgehlot.nullroute"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        // The `lists` branch CI publishes compiled lists to (see .github/workflows/lists.yml).
        buildConfigField(
            "String", "LISTS_BRANCH_URL",
            "\"https://raw.githubusercontent.com/Keshav-gehlot/nullroute/lists/\"",
        )
    }

    signingConfigs {
        if (signing.isNotEmpty()) create("release") {
            storeFile = rootProject.file(signing.getProperty("storeFile"))
            storePassword = signing.getProperty("storePassword")
            keyAlias = signing.getProperty("keyAlias")
            keyPassword = signing.getProperty("keyPassword")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    sourceSets["main"].assets.srcDir(generatedAssets)

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

tasks.named("preBuild") { dependsOn(syncLists) }

dependencies {
    implementation(project(":core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.work)
    implementation(libs.coroutines.android)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.icons)
    debugImplementation(libs.compose.ui.tooling)
}
