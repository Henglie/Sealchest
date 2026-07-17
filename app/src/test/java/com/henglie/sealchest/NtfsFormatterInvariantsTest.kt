package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFormatter
import com.henglie.sealchest.fs.NtfsRecordCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * NTFS 造盘结构不变量（纯 JVM，src/test，秒级）。
 *
 * NTFS 运行时读写路径无法在宿主跑（[com.henglie.sealchest.crypto.NativeBridge.Volume] 是
 * final + 全 native，[com.henglie.sealchest.fs.VolumeReader] 死耦合它），无法伪造。但造盘产物
 * 是纯 Kotlin，且运行时挂载解析走的正是 [NtfsBoot.parse] / [NtfsRecordCodec.parseAttrs] /
 * [NtfsRecordCodec.findAttr]——本测试用同一套解析器断言不变量，是运行时行为的忠实代理。
 *
 * 复现并守护本轮修的两个真机必失败 bug：
 *   A. 大簇（16K/32K/64K）bootClusters 向下取整为 0 → mftLcn=0 → MFT 覆盖引导扇区 →
 *      NTFS 签名被冲掉 → 挂载分发落到 FAT 解析器。断言：全簇矩阵下偏移 0 仍是 NTFS 引导扇区。
 *   B. 根目录 $INDEX_ROOT 造盘时漏起名 "$I30" → 运行时 insertIndexEntry 的
 *      findAttr(INDEX_ROOT,"$I30") 恒 null → 所有写根目录操作恒失败（auto~8K 全数据用例挂）。
 *      断言：根目录记录含名为 "$I30" 的 $INDEX_ROOT 属性。
 */
class NtfsFormatterInvariantsTest {

    /** 与设备侧一键自检同一簇矩阵（字节，0=自动=4K）。 */
    private val clusterMatrix = listOf(0, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

    /** 10MB 数据区（够放全部元数据 + 大簇）。 */
    private val dataSize = 10L * 1024 * 1024

    /** 把稀疏扇区列表铺成完整卷镜像（逻辑偏移 0 = 引导扇区）。 */
    private fun buildImage(clusterSize: Int): ByteArray {
        val img = NtfsFormatter.buildEmpty(dataSize, clusterSize)
        val image = ByteArray(dataSize.toInt())
        for ((off, bytes) in img.sectors) {
            System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)
        }
        return image
    }

    /** Bug A：全簇矩阵下偏移 0 必须仍是可识别的 NTFS 引导扇区（大簇不再被 MFT 覆盖）。 */
    @Test
    fun bootSectorSurvivesAllClusterSizes() {
        for (cs in clusterMatrix) {
            val image = buildImage(cs)
            val boot = image.copyOfRange(0, 512)
            assertTrue(
                "簇=$cs：偏移 0 的 NTFS 签名被冲掉（bootClusters 向下取整为 0 覆盖引导扇区）",
                NtfsBoot.isNtfs(boot),
            )
            // 引导扇区能被运行时解析器解析（挂载分发的实际判据）。
            val parsed = NtfsBoot.parse(boot)
            assertEquals("簇=$cs：解析出的簇大小与请求不符", if (cs == 0) 4096 else cs, parsed.bytesPerCluster)
            // MFT 起始簇必 >= 1（引导区至少占一簇），否则 MFT 会覆盖引导扇区。
            assertTrue("簇=$cs：mftCluster=${parsed.mftCluster} 落在引导区上", parsed.mftCluster >= 1)
        }
    }

    /** Bug B：根目录（MFT 记录 5）的 $INDEX_ROOT 必须名为 "$I30"，否则运行时写根目录恒失败。 */
    @Test
    fun rootDirIndexRootIsNamedI30() {
        for (cs in clusterMatrix) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val rootOff = (boot.mftByteOffset + 5L * recSize).toInt()
            val rec = image.copyOfRange(rootOff, rootOff + recSize)
            assertEquals("簇=$cs：根目录记录不是 FILE 记录", 'F'.code.toByte(), rec[0])

            // 运行时读记录必先 USA 修复，再解析属性——完全复刻挂载路径。
            val codec = NtfsRecordCodec(boot)
            assertTrue("簇=$cs：根目录 USA 修复失败", codec.applyUsaFixup(rec))
            val attrs = NtfsRecordCodec.parseAttrs(rec)

            // 这正是 NtfsIndex.insertIndexEntry 的取属性方式；null 即所有写根目录操作失败。
            val root = NtfsRecordCodec.findAttr(attrs, NtfsRecordCodec.ATTR_INDEX_ROOT, "\$I30")
            assertNotNull(
                "簇=$cs：根目录 \$INDEX_ROOT 未命名 \$I30 → 运行时 insertIndexEntry 恒返回 false（所有写操作失败）",
                root,
            )
        }
    }

    /**
     * Bug D：12 条系统记录的 $FILE_NAME(0x30) 属性头 resident_flags(偏移 0x16) 必须 = 0x01
     * （RESIDENT_ATTR_IS_INDEXED）。真·Windows/mkntfs 恒置此位（$FILE_NAME 被 $I30 索引）；
     * 漏置 → 桌面 chkdsk 对每条记录报「属性记录(30，"")已损坏」→ Windows NTFS.sys 拒挂 → RAW 卷。
     * 逐字节对照真·Windows VHD 记录 0 的 $FN 头：...18000100 末字节 01 即此位。
     */
    @Test
    fun allSystemRecordsFileNameAttrIsIndexed() {
        for (cs in clusterMatrix) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            for (recNo in 0 until 12) {
                val off = (boot.mftByteOffset + recNo.toLong() * recSize).toInt()
                val rec = image.copyOfRange(off, off + recSize)
                assertEquals("簇=$cs 记录=$recNo：不是 FILE 记录", 'F'.code.toByte(), rec[0])
                assertTrue("簇=$cs 记录=$recNo：USA 修复失败", codec.applyUsaFixup(rec))
                val fnOff = NtfsRecordCodec.attrOffsetOf(rec, NtfsRecordCodec.ATTR_FILE_NAME, "")
                assertNotNull("簇=$cs 记录=$recNo：无 \$FILE_NAME 属性", fnOff)
                val residentFlags = NtfsRecordCodec.u16(rec, fnOff!! + 0x16)
                assertEquals(
                    "簇=$cs 记录=$recNo：\$FILE_NAME resident_flags 应为 0x01(INDEXED)，实为 0x%02x".format(residentFlags),
                    0x01, residentFlags,
                )
            }
        }
    }

    /**
     * Bug E：$BadClus(记录 8) 的 "$Bad" 命名 $DATA(0x80) 属性**不得**标 SPARSE(flags 0x8000)。
     * 真·Windows 用满卷 hole run 但属性头 flags=0、alloc=real=满卷（逐字节对照 VHD：flags=0x0
     * alloc=real=满卷 init=0 runs=hole）。误标 SPARSE + alloc=0 → chkdsk 报「属性记录(80，\$Bad)损坏」。
     */
    @Test
    fun badClusBadStreamIsNotSparse() {
        for (cs in clusterMatrix) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            val off = (boot.mftByteOffset + 8L * recSize).toInt()
            val rec = image.copyOfRange(off, off + recSize)
            assertEquals("簇=$cs：\$BadClus 不是 FILE 记录", 'F'.code.toByte(), rec[0])
            assertTrue("簇=$cs：\$BadClus USA 修复失败", codec.applyUsaFixup(rec))
            val badOff = NtfsRecordCodec.attrOffsetOf(rec, NtfsRecordCodec.ATTR_DATA, "\$Bad")
            assertNotNull("簇=$cs：\$BadClus 无 \$Bad 命名 \$DATA 流", badOff)
            // 属性头 flags 在偏移 0x0C(u16)；SPARSE = 0x8000。
            val attrFlags = NtfsRecordCodec.u16(rec, badOff!! + 0x0C)
            assertEquals(
                "簇=$cs：\$Bad 流误标 SPARSE(flags=0x%04x)，真·Windows 为 0".format(attrFlags),
                0, attrFlags and 0x8000,
            )
        }
    }

    /**
     * Bug F：记录序列号规约。真·Windows/mkntfs 前 16 条系统记录序列号 rec0=1、rec1..15=记录号；
     * 且子记录 $FILE_NAME.parentRef 的高 16 位序列号必等于父目录（根=记录 5）的实际记录头序列号。
     * 全硬编码 seq=1 时 rec2..11 头 seq(=1)≠记录号 + parentSeq(=1)≠根目录应有 seq(=5) →
     * 桌面 chkdsk 报「文件记录段 N 检测到不正确的信息」→ NTFS.sys 拒挂 → RAW 卷（rec0/1 恰好 seq=1
     * 故不报，掩盖了问题）。断言：①记录头 seq=mftSeqOf(n)；②各记录 $FILE_NAME.parentSeq=5（父=根目录）。
     */
    @Test
    fun systemRecordSequenceNumbersMatchWindows() {
        for (cs in clusterMatrix) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            for (recNo in 0 until 12) {
                val off = (boot.mftByteOffset + recNo.toLong() * recSize).toInt()
                val rec = image.copyOfRange(off, off + recSize)
                assertTrue("簇=$cs 记录=$recNo：USA 修复失败", codec.applyUsaFixup(rec))
                // ① 记录头序列号(偏移 0x10)。规约：rec0=1，rec1..15=记录号。
                val expectSeq = if (recNo == 0) 1 else recNo
                val headSeq = NtfsRecordCodec.u16(rec, 0x10)
                assertEquals(
                    "簇=$cs 记录=$recNo：记录头序列号应为 $expectSeq，实为 $headSeq", expectSeq, headSeq,
                )
                // ② $FILE_NAME.parentRef 高 16 位序列号 = 根目录(记录 5)序列号 = 5。
                val fnOff = NtfsRecordCodec.attrOffsetOf(rec, NtfsRecordCodec.ATTR_FILE_NAME, "")!!
                val valOff = fnOff + NtfsRecordCodec.u16(rec, fnOff + 0x14)
                val parentRef = NtfsRecordCodec.u64(rec, valOff)
                val parentSeq = (parentRef ushr 48).toInt() and 0xFFFF
                assertEquals(
                    "簇=$cs 记录=$recNo：\$FILE_NAME.parentSeq 应为 5（父=根目录 rec5），实为 $parentSeq",
                    5, parentSeq,
                )
            }
        }
    }
}
