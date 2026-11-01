// Pure-Kotlin packet/DNS engine. No Android dependencies, so it is unit-tested
// on the JVM (including real UDP forwarding) without an emulator.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Target Java 17 bytecode (same as the app) but build with whatever JDK runs
// Gradle (17+), so Android Studio's bundled JBR works without a separate JDK 17.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlin.test)
    testRuntimeOnly(libs.junit.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}
