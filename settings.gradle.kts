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
