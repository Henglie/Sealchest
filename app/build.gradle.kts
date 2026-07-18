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
        // 版本号：0.2（2026-07-11 恒烈授权升级：UI 改进 + 16 国语言 + 酒红色锁图标）。
        // 日常功能开发、bug 修复一律不动版本号；仅「同步上游 VeraCrypt」且经恒烈同意时才可升，
        // 且改前必须问过恒烈（见 上游同步与供应链安全.md「版本号纪律」）。
        versionCode = 5
        versionName = "0.2"

        // 供应链透明信息：把「编进这个 APK 的上游 VeraCrypt 到底是哪个版本 / commit」
        // 与构建环境编入 BuildConfig，关于页直接读，单一真相源与实际构建绑定。
        // 同步上游后必须同步改这几项（见 上游同步与供应链安全.md「当前锁定版本」）。
        buildConfigField("String", "VC_UPSTREAM_VERSION", "\"1.26.29\"")
        buildConfigField("String", "VC_UPSTREAM_COMMIT", "\"21dba20af41101e59c36bf9a29c26af2870d30b3\"")
        buildConfigField("String", "VC_UPSTREAM_REPO", "\"github.com/veracrypt/VeraCrypt\"")
        buildConfigField("String", "BUILD_TOOLCHAIN", "\"NDK 30.0.14904198 · CMake 3.22.1 · C11/C++17\"")
        buildConfigField("String", "BUILD_ABIS", "\"arm64-v8a, armeabi-v7a, x86_64\"")

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
            // 0.2 落地版：暂用 debug 签名（未配正式 keystore）。后续正式发行需换正式签名。
            signingConfig = signingConfigs.getByName("debug")
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
            // bouncycastle 1.79 与 jspecify 1.0.0 都带此多版本 jar 清单，合并冲突，排除。
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }

    // 16 国语言全部打包进 APK（zh/en/fr/de/es/ja/ko/ru/it/pt/nl/ar/hi/tr/pl/vi）。
    // 早期仅 en/zh 是因为还没做翻译；现在翻译齐全，放开过滤。
    androidResources {
    }

    // 单元测试 fork 出的 JVM 默认按系统码页（本机中文 GBK）解析 classpath，
    // 项目路径含中文「我的项目源码」→ kotlin-classes 目录路径被损坏 → ClassNotFoundException。
    // 强制 fork JVM 用 UTF-8 解码文件名，classpath 中文路径才正确。
    testOptions {
        unitTests.all {
            it.jvmArgs("-Dfile.encoding=UTF-8", "-Dsun.jnu.encoding=UTF-8")
            // 把宿主的 ntfs.emit.dir 透传给 fork 的 test JVM（NtfsEmitRawTest 用它选输出目录）。
            System.getProperty("ntfs.emit.dir")?.let { d -> it.systemProperty("ntfs.emit.dir", d) }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
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

    // Media3：内置加密媒体播放器（ExoPlayer + PlayerView），播放容器内视频/音频。
    implementation(libs.androidx.media3.exoplayer)
    implementation(libs.androidx.media3.ui)

    // PIN 锁：Argon2id 派生（BouncyCastle）+ 哈希存 EncryptedSharedPreferences
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.androidx.security.crypto)

    // 生物识别：BiometricPrompt 解锁 PIN 门禁（指纹/面部）
    implementation(libs.androidx.biometric)

    testImplementation(libs.junit)
}
