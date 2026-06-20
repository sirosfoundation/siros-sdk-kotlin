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
        mavenLocal() // siros-wscd-manager AAR (pre-publication)
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
