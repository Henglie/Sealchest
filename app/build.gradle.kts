plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.henglie.sealchest"
    // 本机仅装 android-36，对齐免再下载。minSdk 23 = Android 6.0，覆盖 2015 至今。
    compileSdk = 36

    // 本机实装 NDK r30。显式 pin，避免 Gradle 去找其它未装版本。
    ndkVersion = "30.0.14904198"

    defaultConfig {
        applicationId = "com.henglie.sealchest"
        minSdk = 23
        targetSdk = 36
        versionCode = 4
        versionName = "0.4"

        // JNI 层（VeraCrypt 解密核心）。arm64-v8a 主流，armeabi-v7a 覆盖老 ARM，
        // x86_64 给模拟器调试。
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                // C++17。VeraCrypt C 核心走 CRYPTOPP_DISABLE_ASM 纯 C 路径。
                // 隐藏符号缩小攻击面，只导出 JNI_OnLoad 与 Java_ 符号。
                cppFlags += listOf("-std=c++17", "-fvisibility=hidden")
                arguments += "-DANDROID_STL=c++_shared"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    // 仅支持中 / 英；其它语言回落英文。
    androidResources {
        localeFilters += listOf("en", "zh")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    debugImplementation(libs.androidx.ui.tooling)

    // SAF 选容器文件 / 持久化 URI 读权限
    implementation(libs.androidx.documentfile)

    testImplementation(libs.junit)
}
