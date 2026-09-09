import com.android.build.api.dsl.LibraryExtension

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kover)
    alias(libs.plugins.dokka)
}

// One version for every published artifact. `sdkVersion` in gradle.properties
// is the version of the NEXT release and is bumped by the release PR; CI
// overrides it from the tag (`-PsdkVersion=${GITHUB_REF_NAME#v}`) so what is
// published always matches the tag that triggered it.
val sdkVersion: String = (findProperty("sdkVersion") as String?)
    ?: error("sdkVersion must be set in gradle.properties or with -PsdkVersion=")

subprojects {
    apply(plugin = "org.jetbrains.kotlinx.kover")
    apply(plugin = "org.jetbrains.dokka")

    // Everything under :sdk: is a published artifact: org.siros:siros-sdk-<module>.
    // The sample app is not.
    if (path.startsWith(":sdk:")) {
        apply(plugin = "maven-publish")
        group = "org.siros"
        version = sdkVersion
        extensions.configure<PublishingExtension> {
            repositories { sirosRepositories() }
        }

        // Android library modules publish their release variant with a
        // sources jar. The BOM (:sdk:bom, a java-platform) configures its own
        // publication in its build file.
        plugins.withId("com.android.library") {
            extensions.configure<LibraryExtension> {
                publishing {
                    singleVariant("release") {
                        withSourcesJar()
                    }
                }
            }
            afterEvaluate {
                extensions.configure<PublishingExtension> {
                    publications {
                        create<MavenPublication>("release") {
                            from(components["release"])
                            artifactId = "siros-sdk-${project.name}"
                            pom { sirosPom("SIROS SDK ${project.name}", "The ${project.name} module of the SIROS wallet SDK for Android.") }
                        }
                    }
                }
            }
        }
    }
}

/**
 * POM metadata shared by every published module. Maven Central requires
 * name, description, url, licenses, developers and scm; GitHub Packages does
 * not, but a consumer reads the same POM either way.
 */
fun MavenPom.sirosPom(pomName: String, pomDescription: String) {
    name.set(pomName)
    description.set(pomDescription)
    url.set("https://github.com/sirosfoundation/siros-sdk-kotlin")
    licenses {
        license {
            name.set("BSD-2-Clause")
            url.set("https://opensource.org/licenses/BSD-2-Clause")
        }
    }
    developers {
        developer {
            id.set("sirosfoundation")
            name.set("SIROS Foundation")
            url.set("https://siros.org")
        }
    }
    scm {
        url.set("https://github.com/sirosfoundation/siros-sdk-kotlin")
        connection.set("scm:git:https://github.com/sirosfoundation/siros-sdk-kotlin.git")
        developerConnection.set("scm:git:ssh://git@github.com/sirosfoundation/siros-sdk-kotlin.git")
    }
}

/**
 * Where `publish` goes. GitHub Packages today, alongside the SDK's own native
 * dependencies (siros-wscd-manager, siros-dc-matcher, zk-cred-*), which live
 * there too - a consumer that can resolve those can resolve this. Credentials
 * come from the same places settings.gradle.kts reads them for consumption:
 * CI's GITHUB_ACTOR/GITHUB_TOKEN, or gpr.user/gpr.key Gradle properties.
 *
 * Maven Central is the intended home once the org.siros namespace is
 * verified with Sonatype: add a second repository here and the `signing`
 * plugin (Central requires signed artifacts; GitHub Packages does not).
 */
fun RepositoryHandler.sirosRepositories() {
    maven {
        name = "GitHubPackages"
        url = uri("https://maven.pkg.github.com/sirosfoundation/siros-sdk-kotlin")
        credentials {
            username = providers.gradleProperty("gpr.user").orElse(providers.environmentVariable("GITHUB_ACTOR")).orNull
            password = providers.gradleProperty("gpr.key").orElse(providers.environmentVariable("GITHUB_TOKEN")).orNull
        }
    }
}
