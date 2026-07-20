package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFormatter
import com.henglie.sealchest.fs.NtfsRecordCodec
import org.junit.Test

/**
 * 大簇造盘索引诊断：对比 4k(idxblk>=簇) vs 8k(idxblk<簇) 的记录 9($Secure)/11($Extend)/5(root)
 * 的 $INDEX_ROOT / $SDH / $SII 视图索引字节。真机 chkdsk 仅 8k+ 报「文件9 $SDH/$SII、文件B $I30」
 * 错误——这些记录**造盘写死**、不受运行时影响，故差异必在造盘的大簇 index-block 编码路径。
 *
 * 用与运行时/chkdsk 同源的 NtfsBoot/NtfsRecordCodec 解析（避免 Python dump 的 USA/偏移 bug）。
 */
class NtfsLargeClusterIndexTest {

    private val dataSize = 10L * 1024 * 1024

    private fun buildImage(cs: Int): ByteArray {
        val img = NtfsFormatter.buildEmpty(dataSize, cs)
        val image = ByteArray(dataSize.toInt())
        for ((off, bytes) in img.sectors) System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)
        return image
    }

    private fun hex(b: ByteArray, from: Int, len: Int): String {
        val sb = StringBuilder()
        for (i in from until minOf(from + len, b.size)) sb.append("%02x ".format(b[i]))
        return sb.toString()
    }

    /** dump 一条记录里指定 type+name 的 $INDEX_ROOT 内容 + 全部索引项头。 */
    private fun dumpIndexRoot(rec: ByteArray, wantName: String) {
        var off = NtfsRecordCodec.u16(rec, 0x14)
        val used = NtfsRecordCodec.u32(rec, 0x18).toInt()
        var iter = 0
        while (off + 8 <= used && off + 8 <= rec.size && iter < 40) {
            val type = NtfsRecordCodec.u32(rec, off)
            if (type == 0xFFFFFFFFL) break
            val tot = NtfsRecordCodec.u32(rec, off + 4).toInt()
            if (tot <= 0 || off + tot > rec.size) break
            val nlen = rec[off + 9].toInt() and 0xFF
            val noff = NtfsRecordCodec.u16(rec, off + 0x0A)
            val nm = if (nlen > 0) buildString { for (k in 0 until nlen) append(NtfsRecordCodec.u16(rec, off + noff + k * 2).toChar()) } else ""
            if (type == 0x90L && nm == wantName) {
                val voff = NtfsRecordCodec.u16(rec, off + 0x14)
                val vlen = NtfsRecordCodec.u32(rec, off + 0x10).toInt()
                val vs = off + voff
                val collation = NtfsRecordCodec.u32(rec, vs + 4)
                val idxblk = NtfsRecordCodec.u32(rec, vs + 8)
                val cpib = rec[vs + 0x0C].toInt()   // signed
                val ihFlags = NtfsRecordCodec.u32(rec, vs + 0x1C)
                val idxLen = NtfsRecordCodec.u32(rec, vs + 0x14)
                println("    \$INDEX_ROOT name=$wantName vlen=$vlen collation=0x${collation.toString(16)} idxblk=$idxblk cpib=$cpib ihFlags=0x${ihFlags.toString(16)} idxLen=0x${idxLen.toString(16)}")
                // 索引项
                var eo = vs + 0x10 + NtfsRecordCodec.u32(rec, vs + 0x10).toInt()
                var e = 0
                while (eo + 16 <= vs + vlen && e < 10) {
                    val elen = NtfsRecordCodec.u16(rec, eo + 8)
                    val clen = NtfsRecordCodec.u16(rec, eo + 10)
                    val fl = NtfsRecordCodec.u16(rec, eo + 12)
                    val dataOff = NtfsRecordCodec.u16(rec, eo + 0x00)
                    val dataLen = NtfsRecordCodec.u16(rec, eo + 0x02)
                    println("      entry elen=$elen clen=$clen flags=0x${fl.toString(16)} dataOff=0x${dataOff.toString(16)} dataLen=0x${dataLen.toString(16)}  bytes=[${hex(rec, eo, minOf(elen, 48))}]")
                    if (fl and 0x02 != 0 || elen < 16) break
                    eo += elen; e++
                }
            }
            off += tot; iter++
        }
    }

    @Test
    fun compareSecureExtendIndex4kVs8k() {
        for (cs in listOf(4096, 8192)) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val codec = NtfsRecordCodec(boot)
            val recSize = boot.fileRecordSize
            val mftOff = boot.mftByteOffset.toInt()
            println("\n############ cs=$cs bpc=${boot.bytesPerCluster} indexRecordSize=${boot.indexRecordSize} boot[0x44]=${image[0x44].toInt()} ############")
            for (no in listOf(9, 11, 5)) {
                val off = mftOff + no * recSize
                val rec = image.copyOfRange(off, off + recSize)
                codec.applyUsaFixup(rec)
                println("--- 记录 $no flags=0x${NtfsRecordCodec.u16(rec, 0x16).toString(16)} ---")
                when (no) {
                    9 -> { dumpIndexRoot(rec, "\$SDH"); dumpIndexRoot(rec, "\$SII") }
                    else -> dumpIndexRoot(rec, "\$I30")
                }
            }
        }
    }
}
