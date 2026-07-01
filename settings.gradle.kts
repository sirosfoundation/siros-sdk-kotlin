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
        mavenLocal() // local development builds
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
