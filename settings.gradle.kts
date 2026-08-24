pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        mavenLocal() // local-dev override: must precede GitHubPackages so local builds win
        // siros-wscd-manager AAR, published to GitHub Packages Maven.
        // Credentials come from env (CI: GITHUB_ACTOR/GITHUB_TOKEN) or Gradle
        // properties (local: gpr.user/gpr.key in ~/.gradle/gradle.properties).
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/sirosfoundation/siros-wscd-manager")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
        // zk-cred-longfellow AAR, published to its own GitHub Packages Maven -
        // each GH Packages Maven repo is scoped per-repo, not shared org-wide,
        // so this is a separate entry from siros-wscd-manager's above even
        // though the credentials are the same.
        maven {
            name = "GitHubPackagesZkCredLongfellow"
            url = uri("https://maven.pkg.github.com/sirosfoundation/zk-cred-longfellow")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
        // zk-cred-vega AAR, published to its own GitHub Packages Maven as of
        // v0.0.2 - same per-repo-scoped reasoning as zk-cred-longfellow above.
        // LOCAL ONLY, DO NOT PUSH/MERGE this entry to origin/main - see
        // VegaProofSystem.kt's own doc comment for why (circuit artifacts
        // still unpublished, expert review still pending).
        maven {
            name = "GitHubPackagesZkCredVega"
            url = uri("https://maven.pkg.github.com/sirosfoundation/zk-cred-vega")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
    }
}

rootProject.name = "siros-sdk-kotlin"

include(":sdk:transport")
include(":sdk:auth")
include(":sdk:keystore")
include(":sdk:flow")
include(":sdk:credentials")
include(":sdk:wallet")
include(":sdk:idv")
include(":sdk:passkey-provider")
include(":sample-app")
