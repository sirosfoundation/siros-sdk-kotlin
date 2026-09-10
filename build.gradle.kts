import com.android.build.api.dsl.LibraryExtension

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kover)
    alias(libs.plugins.dokka)
    alias(libs.plugins.binary.compatibility.validator)
}

// The public API of every published module, recorded in api/<module>.api
// and checked on every build. Now that the modules are published artifacts
// consumed by other apps, an accidental signature change is a consumer
// break, not a refactor; `./gradlew apiCheck` fails on any difference and
// `./gradlew apiDump` records an intended one, which then shows up in review
// as a diff of the .api file. Generated UniFFI bindings are included: they
// are in the AAR and reachable from SDK signatures, so a bindings bump that
// changes them is a change consumers see.
apiValidation {
    ignoredProjects += listOf("sample-app", "bom")
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
        apply(plugin = "signing")
        group = "org.siros"
        version = sdkVersion
        extensions.configure<PublishingExtension> {
            repositories { sirosRepositories() }
        }
        // Maven Central rejects unsigned artifacts. The key arrives as
        // org-level Actions secrets (ASCII-armored private key + passphrase);
        // with neither present - every local build - nothing is signed and
        // publishToMavenLocal / GitHub Packages keep working as before.
        val signingKey = providers.environmentVariable("SIGNING_KEY").orNull
        val signingPassword = providers.environmentVariable("SIGNING_PASSWORD").orNull
        if (!signingKey.isNullOrBlank()) {
            afterEvaluate {
                extensions.configure<SigningExtension> {
                    useInMemoryPgpKeys(signingKey, signingPassword ?: "")
                    sign(extensions.getByType<PublishingExtension>().publications)
                }
            }
        }

        // Android library modules publish their release variant with a
        // sources jar. The BOM (:sdk:bom, a java-platform) configures its own
        // publication in its build file.
        plugins.withId("com.android.library") {
            tasks.register<Jar>("javadocPlaceholderJar") {
                archiveClassifier.set("javadoc")
                from(rootProject.layout.projectDirectory.file("docs/JAVADOC.md"))
            }
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
                            // Central requires a -javadoc jar per artifact. AGP's
                            // withJavadocJar() runs a bundled Dokka that fails on
                            // current class files, and the real API reference is
                            // the Dokka site built separately, so this ships a
                            // minimal jar that points there.
                            artifact(tasks.named("javadocPlaceholderJar"))
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
 * Where `publish` goes: GitHub Packages, alongside the SDK's own native
 * dependencies (siros-wscd-manager, siros-dc-matcher, zk-cred-*), which live
 * there too. Credentials come from the same places settings.gradle.kts reads
 * them for consumption: CI's GITHUB_ACTOR/GITHUB_TOKEN, or gpr.user/gpr.key
 * Gradle properties.
 *
 * Maven Central is not a repository here: it is fed by Nmcp (see
 * settings.gradle.kts), which aggregates every module's publication into one
 * Central Portal deployment - `publishAggregationToCentralPortal`. The native
 * crates reach Central through .github/actions/central-publish instead (their
 * release workflows, plus central-backfill-native.yml for versions released
 * before that step existed).
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
