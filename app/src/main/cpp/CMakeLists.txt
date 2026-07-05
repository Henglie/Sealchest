# ============================================================
#  密匣 Sealchest · JNI native 层 CMake 构建脚本
#  产物 libsealchest.so，由 NativeBridge.kt 的 System.loadLibrary("sealchest") 加载。
#
#  第一阶段：native_lib.cpp + sha256 自检，跑通工具链。（已完成）
#  第二阶段（当前）：VeraCrypt C 核心编成独立静态库 veracrypt_core，
#                    链进 libsealchest.so。开卷/解扇区/关卷 JNI 桥随后接。
# ============================================================
cmake_minimum_required(VERSION 3.22.1)

project(sealchest LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Release 走 -O2，解密热路径要性能；隐藏符号缩小攻击面
# （与 gradle 的 -fvisibility=hidden 一致，只导出 JNI_OnLoad 与 Java_ 符号）。
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# ============================================================
#  VeraCrypt C 核心 静态库 veracrypt_core
#
#  只挑要编的 .c（移植清单），大量无关文件（BootEncryption/EMVCard/
#  Dlgcode/libzip/RNG/jitterentropy/wolfCrypt/sm4/t1ha 及全部 .asm/SIMD）
#  躺在树里不参与编译。CMake 只列这批，无害。
#
#  平台适配靠 force-include sc_compat.h（-include），先于 config.h/Tcdefs.h
#  生效，摁死汇编/SIMD/AES-NI/ARM-crypto、强制单线程、补 Windows 类型与
#  API 桩。平台符号桩在 sc_stubs.c。
# ============================================================
set(VC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/veracrypt)

# Crypto/ —— 算法核心。AES 走纯软 Aescrypt/Aeskey/Aestab；Serpent 用
# SerpentFast（不编 Serpent.c，避 serpent_set_key 重复定义，单块由 sc_stubs 包装）；
# blake2s/Camellia/Twofish/kuznyechik/Whirlpool/Streebog/Sha2 用基础 .c；
# cpu.c 提供 DetectArmFeatures 等（内部靠 sc_compat 关掉的宏走空路径）。
set(VC_CRYPTO_SRC
        ${VC_ROOT}/Crypto/Aescrypt.c
        ${VC_ROOT}/Crypto/Aeskey.c
        ${VC_ROOT}/Crypto/Aestab.c
        ${VC_ROOT}/Crypto/SerpentFast.c
        ${VC_ROOT}/Crypto/Twofish.c
        ${VC_ROOT}/Crypto/Camellia.c
        ${VC_ROOT}/Crypto/kuznyechik.c
        ${VC_ROOT}/Crypto/Sha2.c
        ${VC_ROOT}/Crypto/Whirlpool.c
        ${VC_ROOT}/Crypto/Streebog.c
        ${VC_ROOT}/Crypto/blake2s.c
        ${VC_ROOT}/Crypto/cpu.c
)

# Argon2 —— KDF。ref.c 单线程回退；opt_sse2/opt_avx2 自带 #else fallback
# 桩，非 x86 无害全编；blake2b.c 是 Argon2 内部哈希（≠ Crypto/blake2s）。
set(VC_ARGON2_SRC
        ${VC_ROOT}/Crypto/Argon2/src/argon2.c
        ${VC_ROOT}/Crypto/Argon2/src/core.c
        ${VC_ROOT}/Crypto/Argon2/src/ref.c
        ${VC_ROOT}/Crypto/Argon2/src/opt_sse2.c
        ${VC_ROOT}/Crypto/Argon2/src/opt_avx2.c
        ${VC_ROOT}/Crypto/Argon2/src/blake2/blake2b.c
)

# Common/ —— 卷头解析 + 加解密调度 + XTS + PBKDF2。
set(VC_COMMON_SRC
        ${VC_ROOT}/Common/Crypto.c
        ${VC_ROOT}/Common/Volumes.c
        ${VC_ROOT}/Common/Pkcs5.c
        ${VC_ROOT}/Common/Endian.c
        ${VC_ROOT}/Common/GfMul.c
        ${VC_ROOT}/Common/Xts.c
        ${VC_ROOT}/Common/Crc.c
)

# OBJECT 库（非 STATIC）：所有 .o 直接折进 libsealchest.so，绕开静态库
# 「按需拉取 + 单次处理」的对象顺序坑 —— Volumes.c 引用 Crypto.c 的
# GetMaxPkcs5OutSize、cpu.c 的 DetectX86Features 等「定义在同库却因归档
# 处理顺序被丢弃」的符号，STATIC 下会误报 undefined。OBJECT 全量并入即根治。
add_library(veracrypt_core OBJECT
        ${VC_CRYPTO_SRC}
        ${VC_ARGON2_SRC}
        ${VC_COMMON_SRC}
        sc_stubs.c
        sc_volume.c
        sc_random.c
)

# include 拓扑：VeraCrypt 源混用「有前缀」(Common/Endian.h) 与「无前缀」
# (Tcdefs.h / cpu.h / Xts.h) 两种风格，故根、Common、Crypto 三处都要挂。
# Argon2 用 "Crypto/config.h" 与 "blake2/blake2b.h"，故还需 Argon2/src 与
# Argon2/include。
# shim/ 必须排在最前：Volumes.c 的 <io.h>、Crypto.c 的 <strsafe.h> 是
# Android 没有的 Windows 头，用 shim/ 下的垫片顶上。angle-bracket include
# 从 -I 列表按序解析，NDK sysroot 无同名头，不冲突。
target_include_directories(veracrypt_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/shim
        ${VC_ROOT}
        ${VC_ROOT}/Common
        ${VC_ROOT}/Crypto
        ${VC_ROOT}/Crypto/Argon2/src
        ${VC_ROOT}/Crypto/Argon2/include
)

# force-include 垫片，先于任何 VeraCrypt 头生效。只作用于本静态库。
target_compile_options(veracrypt_core PRIVATE
        -include ${CMAKE_CURRENT_SOURCE_DIR}/sc_compat.h
)

# GNU89 inline 语义：VeraCrypt cpu.c 的 CPU_QueryAES/CPU_QuerySHA2 是纯 `inline`
# （无 static/extern）。C99 语义下纯 inline 不产生外部符号，Debug(-O0) 不内联时
# DetectArmFeatures 引用它俩链接失败（arm64 特有，Release -O2 内联侥幸过）。
# gnu89-inline 下纯 inline 会产出外部定义 —— 这也是 VeraCrypt 原本假设的语义。
target_compile_options(veracrypt_core PRIVATE
        -fgnu89-inline
)

# VeraCrypt 源在 POSIX 分支下有大量旧式写法，压掉噪声警告，保留真错误。
target_compile_options(veracrypt_core PRIVATE
        -Wno-unused-parameter
        -Wno-unused-variable
        -Wno-unused-function
        -Wno-implicit-function-declaration
        -Wno-incompatible-pointer-types
        -Wno-pointer-sign
)

# ============================================================
#  JNI 共享库
# ============================================================
#  veracrypt_core 是 OBJECT 库，用 $<TARGET_OBJECTS> 把它的对象整体并进 .so，
#  绕开静态库「按需拉取」丢符号的坑（GetMaxPkcs5OutSize/DetectX86Features 等
#  明明编了却链接不到，就是被静态库 gc 掉）。
add_library(
        sealchest SHARED
        native_lib.cpp
        sha256.cpp
        $<TARGET_OBJECTS:veracrypt_core>
)

# native_lib.cpp 调开卷/解扇区需要 VeraCrypt 头（Crypto.h/Volumes.h 等）。
target_include_directories(sealchest PRIVATE
        ${VC_ROOT}
        ${VC_ROOT}/Common
        ${VC_ROOT}/Crypto
)

# Android log 库：native 侧 __android_log_print 调试用。
find_library(log-lib log)

target_link_libraries(
        sealchest
        ${log-lib}
)

# ============================================================
#  可选：开卷/解扇区正确性验证器 sc_test（独立可执行，非 JNI）
#
#  仅当 -DSC_BUILD_TEST=ON 时编译；gradle 的 externalNativeBuild 不传此
#  开关，故 APK 构建不受影响。手动交叉编到 x86_64-linux-android，推模拟器
#  跑，用官方测试容器验证 sc_volume 的偏移语义与解密正确性。
#  只 include 纯净门面 sc_volume.h，与 JNI 层同一条 C API。
# ============================================================
option(SC_BUILD_TEST "Build standalone sc_test verifier" OFF)
if(SC_BUILD_TEST)
    add_executable(sc_test
            sc_test.c
            $<TARGET_OBJECTS:veracrypt_core>
    )
    target_include_directories(sc_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
