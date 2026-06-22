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
        mavenLocal() // local-dev fallback for an unpublished AAR
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
