package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFormatter
import com.henglie.sealchest.fs.NtfsRecordCodec
import org.junit.Test

/**
 * 大簇诊断：dump 记录 9($Secure)、11($Extend)、5(root) 的**全部属性**（含 $DATA($SDS) 的
 * realSize/allocSize/runs、$INDEX_ALLOCATION 布局），对比 4k vs 8k 找大簇特有差异。
 * cpib 已经真机排除（非 $SDH/$SII/$I30 报错根因），聚焦非驻留流的簇布局。
 */
class NtfsLargeClusterIndexTest {

    private val dataSize = 10L * 1024 * 1024

    private fun buildImage(cs: Int): ByteArray {
        val img = NtfsFormatter.buildEmpty(dataSize, cs)
        val image = ByteArray(dataSize.toInt())
        for ((off, bytes) in img.sectors) System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)
        return image
    }

    private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xFF) or ((b[o+1].toInt() and 0xFF) shl 8)
    private fun u32(b: ByteArray, o: Int) = u16(b,o).toLong() or (u16(b,o+2).toLong() shl 16)
    private fun u64(b: ByteArray, o: Int): Long { var v=0L; for (k in 0 until 8) v = v or ((b[o+k].toInt() and 0xFF).toLong() shl (8*k)); return v }

    @Test
    fun dumpIndexRoots() {
        for (cs in listOf(4096, 8192)) {
            val image = buildImage(cs)
            val boot = NtfsBoot.parse(image.copyOfRange(0, 512))
            val codec = NtfsRecordCodec(boot)
            val recSize = boot.fileRecordSize
            val mftOff = boot.mftByteOffset.toInt()
            println("\n############ cs=$cs bpc=${boot.bytesPerCluster} idxblk=${boot.indexRecordSize} boot[0x44]=${image[0x44].toInt()} ############")

            for (recNo in listOf(9, 11, 5)) {
                val off = mftOff + recNo * recSize
                val rec = image.copyOfRange(off, off + recSize)
                codec.applyUsaFixup(rec)
                println("--- 记录 $recNo flags=0x${u16(rec,0x16).toString(16)} used=0x${u32(rec,0x18).toString(16)} ---")
                var ao = u16(rec, 0x14)
                while (ao + 4 <= rec.size) {
                    val t = u32(rec, ao)
                    if (t == 0xFFFFFFFFL) break
                    val ln = u32(rec, ao+4).toInt()
                    if (ln <= 0 || ao+ln > rec.size) break
                    val nonres = rec[ao+8].toInt()
                    val nlen = rec[ao+9].toInt() and 0xFF
                    val noff = u16(rec, ao+0x0A)
                    val nm = if (nlen>0) String(CharArray(nlen){ u16(rec, ao+noff+it*2).toChar() }) else ""
                    if (nonres == 0) {
                        val vlen = u32(rec, ao+0x10)
                        val voff = u16(rec, ao+0x14)
                        print("    attr=0x${t.toString(16)} name='$nm' RESIDENT vlen=$vlen voff=0x${voff.toString(16)}")
                        if (t == 0x90L) {
                            val vs = ao+voff
                            println("  IR: coll=0x${u32(rec,vs+4).toString(16)} idxblk=${u32(rec,vs+8)} cpib=${rec[vs+0x0C].toInt()} ihFlags=0x${u32(rec,vs+0x1C).toString(16)} idxLen=0x${u32(rec,vs+0x14).toString(16)}")
                        } else println()
                    } else {
                        val startVcn = u64(rec, ao+0x10); val endVcn = u64(rec, ao+0x18)
                        val runsOff = u16(rec, ao+0x20)
                        val allocSz = u64(rec, ao+0x28); val realSz = u64(rec, ao+0x30); val initSz = u64(rec, ao+0x38)
                        val aFlags = u16(rec, ao+0x0C)
                        print("    attr=0x${t.toString(16)} name='$nm' NONRES vcn=$startVcn..$endVcn alloc=$allocSz real=$realSz init=$initSz aFlags=0x${aFlags.toString(16)}")
                        // decode runs
                        val runs = NtfsRecordCodec.decodeRuns(rec, ao+runsOff)
                        val rs = runs.joinToString(",") { "lcn=${it.lcn}/len=${it.length}${if(it.sparse)"(sparse)" else ""}" }
                        println("  runs=[$rs] runsBytes=${(ao+runsOff until ao+ln).take(16).joinToString(" "){ "%02x".format(rec[it]) }}")
                    }
                    ao += ln
                }
            }
        }
    }
}
