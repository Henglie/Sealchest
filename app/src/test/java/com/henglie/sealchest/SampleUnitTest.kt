package com.henglie.sealchest

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 纯 JVM 单元测试地基验证（src/test，不上设备，秒级迭代）。
 *
 * 这只是地基 sample：证明 JUnit4 + testDebugUnitTest 链路通。
 * T2-T10 的纯 Kotlin FS 逻辑测试（FAT 解析等）后续挂在同目录。
 *
 * 主开发收口跑：gradlew.bat testDebugUnitTest （钉 JBR 21）
 */
class SampleUnitTest {

    @Test
    fun addition_isCorrect() {
        assertEquals(4, 2 + 2)
    }
}
