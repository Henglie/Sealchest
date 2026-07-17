package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFormatter
import com.henglie.sealchest.fs.NtfsRecordCodec
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 诊断 2k/16k/64k 簇下 chkdsk 阶段1报错：
 *   - 16k/64k：文件记录段2($LogFile)的 $DATA(0x80) 属性损坏
 *   - 2k：$MFT 整体损坏
 *
 * 逐字节检查 MFT 记录 0..11 的属性链表、$DATA 属性头字段、data runs 解码一致性、
 * sectors 列表偏移重叠，定位 formatter 层根因。
 */
class NtfsClusterSizeDiagnosticTest {

    private val dataSize = 10L * 1024 * 1024

    private fun buildImage(clusterSize: Int): ByteArray {
        val img = NtfsFormatter.buildEmpty(dataSize, clusterSize)
        val image = ByteArray(dataSize.toInt())
        for ((off, bytes) in img.sectors) {
            System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)
        }
        return image
    }

    /** Dump MFT 记录 0..11 的属性链表完整性 + $DATA 属性头字段。 */
    @Test
    fun dumpMftRecordsForProblemClusterSizes() {
        for (cs in listOf(2048, 16384, 65536)) {
            println("\n${"=".repeat(80)}")
            println("簇大小 = $cs")
            println("=" .repeat(80))

            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            val mftOff = boot.mftByteOffset.toInt()

            println("bytesPerCluster=${boot.bytesPerCluster} totalSectors=${boot.totalSectors} " +
                    "mftCluster=${boot.mftCluster} mftByteOffset=${boot.mftByteOffset} " +
                    "fileRecordSize=${boot.fileRecordSize} indexRecordSize=${boot.indexRecordSize}")
            println("totalClusters=${boot.totalSectors / boot.sectorsPerCluster}")

            for (recNo in 0 until 12) {
                val off = mftOff + recNo * recSize
                val rec = image.copyOfRange(off, off + recSize)
                println("\n--- 记录 $recNo (偏移=0x${off.toString(16)}) ---")
                println("FILE sig: ${rec[0]}${rec[1]}${rec[2]}${rec[3]}")
                println("usaOff=0x${NtfsRecordCodec.u16(rec,4).toString(16)} " +
                        "usaCount=${NtfsRecordCodec.u16(rec,6)} " +
                        "seq=0x${NtfsRecordCodec.u16(rec,0x10).toString(16)} " +
                        "hardLinks=${NtfsRecordCodec.u16(rec,0x12)} " +
                        "firstAttrOff=0x${NtfsRecordCodec.u16(rec,0x14).toString(16)} " +
                        "usedSize=0x${NtfsRecordCodec.u32(rec,0x18).toString(16)} " +
                        "allocSize=0x${NtfsRecordCodec.u32(rec,0x1C).toString(16)} " +
                        "flags=0x${NtfsRecordCodec.u16(rec,0x16).toString(16)}")

                val usaOk = codec.applyUsaFixup(rec)
                println("USA fixup: $usaOk")

                // 遍历属性链表
                var attrOff = NtfsRecordCodec.u16(rec, 0x14)
                var attrIdx = 0
                while (attrOff + 4 <= rec.size) {
                    val type = NtfsRecordCodec.u32(rec, attrOff)
                    if (type == 0xFFFFFFFFL) {
                        println("  attr[$attrIdx] @0x${attrOff.toString(16)}: END")
                        break
                    }
                    val totalLen = NtfsRecordCodec.u32(rec, attrOff + 4).toInt()
                    val nonRes = rec[attrOff + 8].toInt() and 0xFF
                    val nameLen = rec[attrOff + 9].toInt() and 0xFF
                    val nameOff = NtfsRecordCodec.u16(rec, attrOff + 0x0A)
                    val flags = NtfsRecordCodec.u16(rec, attrOff + 0x0C)
                    val attrId = NtfsRecordCodec.u16(rec, attrOff + 0x0E)

                    val name = if (nameLen > 0) {
                        val sb = StringBuilder(nameLen)
                        for (k in 0 until nameLen) {
                            sb.append(NtfsRecordCodec.u16(rec, attrOff + nameOff + k * 2).toChar())
                        }
                        sb.toString()
                    } else ""

                    if (nonRes == 0) {
                        val valLen = NtfsRecordCodec.u32(rec, attrOff + 0x10)
                        val valOff = NtfsRecordCodec.u16(rec, attrOff + 0x14)
                        val resFlags = NtfsRecordCodec.u16(rec, attrOff + 0x16)
                        println("  attr[$attrIdx] @0x${attrOff.toString(16)}: type=0x${type.toString(16)} " +
                                "totalLen=$totalLen RESIDENT name='$name' valOff=$valOff valLen=$valLen " +
                                "resFlags=0x${resFlags.toString(16)} attrId=$attrId")
                    } else {
                        val startVcn = NtfsRecordCodec.u64(rec, attrOff + 0x10)
                        val endVcn = NtfsRecordCodec.u64(rec, attrOff + 0x18)
                        val runsOff = NtfsRecordCodec.u16(rec, attrOff + 0x20)
                        val compUnit = NtfsRecordCodec.u16(rec, attrOff + 0x22)
                        val allocSz = NtfsRecordCodec.u64(rec, attrOff + 0x28)
                        val realSz = NtfsRecordCodec.u64(rec, attrOff + 0x30)
                        val initSz = NtfsRecordCodec.u64(rec, attrOff + 0x38)
                        println("  attr[$attrIdx] @0x${attrOff.toString(16)}: type=0x${type.toString(16)} " +
                                "totalLen=$totalLen NONRESIDENT name='$name' " +
                                "vcn=$startVcn..$endVcn runsOff=$runsOff compUnit=$compUnit " +
                                "alloc=$allocSz real=$realSz init=$initSz flags=0x${flags.toString(16)} attrId=$attrId")

                        // dump runs 原始字节
                        val runsEnd = attrOff + totalLen
                        val runsBytes = rec.copyOfRange(attrOff + runsOff, runsEnd)
                        val runsHex = runsBytes.joinToString(" ") { "%02x".format(it) }
                        println("    runs bytes: $runsHex")

                        // 解码 runs
                        val runs = NtfsRecordCodec.decodeRuns(rec, attrOff + runsOff)
                        var totalRunClusters = 0L
                        for (r in runs) {
                            println("    run: length=${r.length} lcn=${r.lcn} sparse=${r.sparse}")
                            totalRunClusters += r.length
                        }
                        val expectedClusters = endVcn - startVcn + 1
                        println("    runs总簇数=$totalRunClusters 期望=$expectedClusters " +
                                "匹配=${totalRunClusters == expectedClusters}")

                        // 校验 allocSize = clusters * bpc
                        val expectedAlloc = expectedClusters * boot.bytesPerCluster
                        println("    alloc期望=$expectedAlloc 匹配=${allocSz == expectedAlloc}")
                    }

                    if (totalLen <= 0 || attrOff + totalLen > rec.size) {
                        println("  *** 属性 totalLen 异常！totalLen=$totalLen rec.size=${rec.size} ***")
                        break
                    }
                    attrOff += totalLen
                    attrIdx++
                }
                println("  属性链结束于 attrOff=0x${attrOff.toString(16)} (rec.size=${rec.size})")
            }
        }
    }

    /** 检查 FatImage.sectors 列表中的偏移范围是否有重叠。 */
    @Test
    fun checkSectorsOverlap() {
        for (cs in listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)) {
            val img = NtfsFormatter.buildEmpty(dataSize, cs)
            val ranges = img.sectors.mapIndexed { idx, (off, bytes) ->
                Triple(idx, off, off + bytes.size)
            }.sortedBy { it.second }

            println("\n簇=$cs: ${ranges.size} 个 sector")
            var overlap = false
            for (i in 1 until ranges.size) {
                val prev = ranges[i - 1]
                val curr = ranges[i]
                println("  [${prev.first}] ${prev.second}..${prev.third} (size=${prev.third - prev.second})")
                if (curr.second < prev.third) {
                    println("  *** 重叠！sector[${prev.first}] [${prev.second},${prev.third}) 与 " +
                            "sector[${curr.first}] [${curr.second},${curr.third}) ***")
                    overlap = true
                }
            }
            if (ranges.isNotEmpty()) {
                val last = ranges.last()
                println("  [${last.first}] ${last.second}..${last.third} (size=${last.third - last.second})")
            }
            assertTrue("簇=$cs 有 sector 重叠", !overlap)
        }
    }

    /** 检查所有簇大小下 MFT 记录 0..11 的属性链表都能完整解析到 $END。 */
    @Test
    fun allMftRecordsAttrChainComplete() {
        for (cs in listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            val mftOff = boot.mftByteOffset.toInt()

            for (recNo in 0 until 12) {
                val off = mftOff + recNo * recSize
                val rec = image.copyOfRange(off, off + recSize)
                assertTrue("簇=$cs 记录=$recNo: USA fixup 失败", codec.applyUsaFixup(rec))

                var attrOff = NtfsRecordCodec.u16(rec, 0x14)
                var foundEnd = false
                var iter = 0
                while (attrOff + 4 <= rec.size && iter < 20) {
                    val type = NtfsRecordCodec.u32(rec, attrOff)
                    if (type == 0xFFFFFFFFL) { foundEnd = true; break }
                    val totalLen = NtfsRecordCodec.u32(rec, attrOff + 4).toInt()
                    assertTrue("簇=$cs 记录=$recNo: attr type=0x${type.toString(16)} totalLen=$totalLen ≤ 0",
                        totalLen > 0)
                    assertTrue("簇=$cs 记录=$recNo: attr type=0x${type.toString(16)} 越界 " +
                        "(off=$attrOff len=$totalLen recSize=${rec.size})",
                        attrOff + totalLen <= rec.size)
                    attrOff += totalLen
                    iter++
                }
                assertTrue("簇=$cs 记录=$recNo: 未找到 \$END 属性标记", foundEnd)
            }
        }
    }

    /** 检查 $LogFile 记录(2) 的 $DATA 属性 runs 解码后的 LCN 在卷范围内。 */
    @Test
    fun logFileDataRunsInVolumeRange() {
        for (cs in listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val recSize = boot.fileRecordSize
            val codec = NtfsRecordCodec(boot)
            val mftOff = boot.mftByteOffset.toInt()
            val totalClusters = boot.totalSectors / boot.sectorsPerCluster

            // 记录2 = $LogFile
            val off = mftOff + 2 * recSize
            val rec = image.copyOfRange(off, off + recSize)
            assertTrue("簇=$cs: \$LogFile USA fixup 失败", codec.applyUsaFixup(rec))

            val attrs = NtfsRecordCodec.parseAttrs(rec)
            val data = NtfsRecordCodec.findAttr(attrs, NtfsRecordCodec.ATTR_DATA, "")
            assertTrue("簇=$cs: \$LogFile 无 \$DATA 属性", data != null)

            val runs = NtfsRecordCodec.decodeRuns(rec, data!!.runsOffset)
            var totalRunClusters = 0L
            for (r in runs) {
                totalRunClusters += r.length
                if (!r.sparse) {
                    assertTrue("簇=$cs: \$LogFile run LCN=${r.lcn} < 0", r.lcn >= 0)
                    assertTrue("簇=$cs: \$LogFile run LCN=${r.lcn} + len=${r.length} > totalClusters=$totalClusters",
                        r.lcn + r.length <= totalClusters)
                }
            }
            val expectedClusters = data.realSize / boot.bytesPerCluster
            assertTrue("簇=$cs: \$LogFile runs总簇数=$totalRunClusters ≠ realSize/cluster=$expectedClusters",
                totalRunClusters == expectedClusters)
        }
    }
}
