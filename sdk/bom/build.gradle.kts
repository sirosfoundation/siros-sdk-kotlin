// Bill of materials: pins every SDK module to one version so a consumer
// writes
//
//     implementation(platform("org.siros:siros-sdk-bom:<version>"))
//     implementation("org.siros:siros-sdk-wallet")
//
// and can never mix module versions. Published as org.siros:siros-sdk-bom.
plugins {
    `java-platform`
}

dependencies {
    constraints {
        rootProject.subprojects
            .filter { it.path.startsWith(":sdk:") && it.path != project.path }
            .forEach { api("org.siros:siros-sdk-${it.name}:${project.version}") }
    }
}

publishing {
    publications {
        create<MavenPublication>("bom") {
            from(components["javaPlatform"])
            artifactId = "siros-sdk-bom"
            pom {
                name.set("SIROS SDK BOM")
                description.set("Bill of materials pinning every SIROS wallet SDK module for Android to one version.")
                url.set("https://github.com/sirosfoundation/siros-sdk-kotlin")
                licenses { license { name.set("BSD-2-Clause"); url.set("https://opensource.org/licenses/BSD-2-Clause") } }
                developers { developer { id.set("sirosfoundation"); name.set("SIROS Foundation"); url.set("https://siros.org") } }
                scm {
                    url.set("https://github.com/sirosfoundation/siros-sdk-kotlin")
                    connection.set("scm:git:https://github.com/sirosfoundation/siros-sdk-kotlin.git")
                }
            }
        }
    }
}
