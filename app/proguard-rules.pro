# 密匣 Sealchest · ProGuard/R8 规则
# 第一版 release 开 minify。native 桥的 external 方法名必须与 C++ 侧 Java_ 符号对齐，
# 不能被混淆，否则 JNI 找不到实现。

# JNI 桥：保留 NativeBridge 的方法名（C++ 侧按全限定名导出 Java_com_henglie_sealchest_..._nativeXxx）
-keepclasseswithmembernames,includedescriptorclasses class com.henglie.sealchest.**.NativeBridge {
    native <methods>;
}

# Compose 运行时自带规则，无需额外配置。
