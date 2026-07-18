package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFormatter
import com.henglie.sealchest.fs.NtfsRecordCodec
import com.henglie.sealchest.fs.NtfsSecure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * $Secure (MFT#9) 视图索引 $SDH/$SII 字节不变量（纯 JVM，秒级）。
 *
 * 守护 2026-07-18 定位的全簇唯一 NTFS chkdsk 真 bug：$SDH 索引项的 data_length 被写成 0x18
 * （把尾部 "II"=0x00490049 对齐填充误算进 data），正确值是 0x14（= SECURITY_DESCRIPTOR_HEADER：
 * hash4 + security_id4 + offset8 + length4）。填充只补到 entry_length，不属于 data。
 *
 * 铁证不对称：$SII 项 data_length=0x14（正确）→ chkdsk 通过；$SDH data_length=0x18（错）→
 * chkdsk 阶段2 报「文件 9 的索引 $SDH 中检测到错误」。逐字节对照真·Windows format 盘的 $SDH
 * 叶子项（dataOff=0x18 dataLen=0x14 entryLen=0x30 keyLen=0x08）确认。改回 0x14 后全 9 簇
 * chkdsk rc=0「未发现问题」（VHD format+overwrite 法验证）。
 *
 * $SDH/$SII 的 DATA 都是同一个 SECURITY_DESCRIPTOR_HEADER 结构（20B），两者 data_length 必相等
 * 且恒为 0x14——本测试直接断言这一点，无需 VHD/chkdsk 即可拦截回归。
 */
class NtfsSecureViewIndexTest {

    private val clusterMatrix = listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

    /** SECURITY_DESCRIPTOR_HEADER 大小：hash(4)+id(4)+offset(8)+length(4)=20=0x14。 */
    private val sdEntryHeaderLen = 0x14

    /** 从视图索引 $INDEX_ROOT 内容里读第一个索引项（跳过 0x10 ROOT 头 + 0x10 INDEX_HEADER）的字段。 */
    private data class ViewEntry(val entryLen: Int, val keyLen: Int, val dataOff: Int, val dataLen: Int)

    private fun firstEntry(root: ByteArray): ViewEntry {
        val o = 0x20   // entries 起点：ROOT 头(0x10) + INDEX_HEADER(0x10)
        val dataOff = NtfsRecordCodec.u16(root, o + 0x00)
        val dataLen = NtfsRecordCodec.u16(root, o + 0x02)
        val entryLen = NtfsRecordCodec.u16(root, o + 0x08)
        val keyLen = NtfsRecordCodec.u16(root, o + 0x0A)
        return ViewEntry(entryLen, keyLen, dataOff, dataLen)
    }

    /**
     * 直接构造层：$SDH 与 $SII 的 DATA 都是 20 字节 SD 头，data_length 必等且 = 0x14。
     * 这是最贴近 bug 的断言——data_length 绝不能包含项对齐填充。
     */
    @Test
    fun viewIndexDataLengthIsHeaderSizeNotPadded() {
        val sd = NtfsSecure.buildSharedSd()
        val hash = NtfsSecure.securityHash(sd)
        for (cs in clusterMatrix) {
            val sdh = firstEntry(NtfsSecure.buildSdhIndexRoot(NtfsSecure.FIRST_SECURITY_ID, hash, sd.size, cs))
            val sii = firstEntry(NtfsSecure.buildSiiIndexRoot(NtfsSecure.FIRST_SECURITY_ID, hash, sd.size, cs))

            assertEquals(
                "簇=$cs：\$SDH data_length 必为 0x14(SD 头)，实为 0x%02x —— 0x18 是把尾部 II 填充误算进 data".format(sdh.dataLen),
                sdEntryHeaderLen, sdh.dataLen,
            )
            assertEquals(
                "簇=$cs：\$SII data_length 必为 0x14(SD 头)，实为 0x%02x".format(sii.dataLen),
                sdEntryHeaderLen, sii.dataLen,
            )
            // $SDH 与 $SII 指向同一个 SD 头结构，data_length 必相等。
            assertEquals("簇=$cs：\$SDH 与 \$SII 的 data_length 应相等（同一 SD 头结构）",
                sii.dataLen, sdh.dataLen)
            // data 区域必须落在 entry_length 内：data_offset + data_length <= entry_length。
            assertTrue("簇=$cs：\$SDH data 越出 entry（off=${sdh.dataOff} len=${sdh.dataLen} entry=${sdh.entryLen}）",
                sdh.dataOff + sdh.dataLen <= sdh.entryLen)
            assertTrue("簇=$cs：\$SII data 越出 entry（off=${sii.dataOff} len=${sii.dataLen} entry=${sii.entryLen}）",
                sii.dataOff + sii.dataLen <= sii.entryLen)
        }
    }

    /**
     * 造盘集成层：从 buildEmpty 产出的完整卷里读 MFT#9，USA fixup 后取 $SDH/$SII $INDEX_ROOT，
     * 断言其索引项 data_length=0x14。复刻 chkdsk 校验路径（同 [NtfsRecordCodec] 解析器）。
     */
    @Test
    fun secureRecordSdhDataLengthCorrectAllClusters() {
        val dataSize = 10L * 1024 * 1024
        for (cs in clusterMatrix) {
            val img = NtfsFormatter.buildEmpty(dataSize, cs)
            val image = ByteArray(dataSize.toInt())
            for ((off, bytes) in img.sectors) System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)

            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            val off = (boot.mftByteOffset + 9L * recSize).toInt()
            val rec = image.copyOfRange(off, off + recSize)
            assertEquals("簇=$cs：\$Secure 不是 FILE 记录", 'F'.code.toByte(), rec[0])
            assertTrue("簇=$cs：\$Secure USA 修复失败", codec.applyUsaFixup(rec))

            for (viewName in listOf("\$SDH", "\$SII")) {
                val attrOff = NtfsRecordCodec.attrOffsetOf(rec, NtfsRecordCodec.ATTR_INDEX_ROOT, viewName)
                assertNotNull("簇=$cs：\$Secure 缺 $viewName \$INDEX_ROOT", attrOff)
                val valOff = attrOff!! + NtfsRecordCodec.u16(rec, attrOff + 0x14)
                val entry = firstEntry(rec.copyOfRange(valOff, valOff + 0x60))
                assertEquals(
                    "簇=$cs：\$Secure $viewName 索引项 data_length 应为 0x14，实为 0x%02x".format(entry.dataLen),
                    sdEntryHeaderLen, entry.dataLen,
                )
            }
        }
    }
}
