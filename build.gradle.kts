plugins {
    kotlin("jvm") version "1.9.23"
}

group = "org.example"
version = "0.1"

repositories {
    mavenCentral()
}

dependencies {
    implementation("commons-cli:commons-cli:1.7.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.WARN

    manifest{
        attributes["Main-Class"] = "org.example.MainKt"
    }

    configurations["compileClasspath"].forEach { f : File ->
        from(zipTree(f.absoluteFile))
    }
}

kotlin {
    jvmToolchain(17)
}