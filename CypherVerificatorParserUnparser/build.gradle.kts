
plugins {
    kotlin("jvm") version "2.1.10"
    kotlin("plugin.spring") version "2.1.10"
    id("org.springframework.boot") version "4.0.0"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "at.daho.cypherrewriting.verification"
version = "0.0.1-SNAPSHOT"
description = "CypherVerificatorParserUnparser"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation(project(":CypherRewritingCore"))
    implementation(project(":CypherFuzzer"))
    implementation("org.neo4j:neo4j:2025.10.1") {
        exclude(group = "org.neo4j", module = "neo4j-slf4j-provider")
    }
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
