package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFileSystem
import com.henglie.sealchest.fs.NtfsFormatter
import com.henglie.sealchest.fs.NtfsRecordCodec
import com.henglie.sealchest.fs.VolumeReader
import org.junit.Assert.fail
import org.junit.Test

/**
 * NTFS 运行时写路径纯 JVM 复现（关键杠杆）。
 *
 * 真机 chkdsk 报的 2k「主文件表损坏」/ 1k「属性记录(0x80)损坏」/ 8k「$I30/$SDH/$SII 错误」
 * 都发生在**运行时写文件路径**（[NtfsDataOps]/[NtfsIndex] 改盘），不是造盘。此前认为运行时
 * 无法在宿主跑（native 加密），但 [VolumeReader] 是 open 类、[NtfsFileSystem.mount] 接受任意
 * reader——用内存明文卷（恒等加密、ByteArray 后端）即可在 JVM 里确定性跑完整写路径，
 * 用与 chkdsk 同源的解析器（[NtfsBoot]/[NtfsRecordCodec]）逐步验证结构不变量。
 *
 * 复刻 [com.henglie.sealchest.fs.VolumeBatchTest] 的写序列（小/大文件、子目录、rename、move、
 * delete、批量 50 文件），每步后全 MFT 结构完整性 + root 索引可遍历性断言，精确定位哪个
 * 操作、哪个簇破坏了哪条记录。
 */
class NtfsWritePathTest {

    private val dataSize = 10L * 1024 * 1024
    private val clusterMatrix = listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

    /** 纯内存明文卷：ByteArray 后端，恒等「加密」，无 channel。 */
    private class MemReader(val image: ByteArray) : VolumeReader(null, null) {
        override val dataSize: Long get() = image.size.toLong()
        override fun read(logicalOffset: Long, length: Int): ByteArray {
            val out = ByteArray(length); read(logicalOffset, out, 0, length); return out
        }
        override fun read(logicalOffset: Long, dst: ByteArray, dstOff: Int, length: Int): Int {
            for (i in 0 until length) {
                val p = logicalOffset + i
                dst[dstOff + i] = if (p in 0 until image.size.toLong()) image[p.toInt()] else 0
            }
            return length
        }
        override fun write(logicalOffset: Long, src: ByteArray, srcOff: Int, length: Int) {
            for (i in 0 until length) {
                val p = logicalOffset + i
                if (p in 0 until image.size.toLong()) image[p.toInt()] = src[srcOff + i]
            }
        }
        override fun write(logicalOffset: Long, src: ByteArray) = write(logicalOffset, src, 0, src.size)
        override fun flush() {}
    }

    private fun buildMem(cs: Int): MemReader {
        val img = NtfsFormatter.buildEmpty(dataSize, cs)
        val image = ByteArray(dataSize.toInt())
        for ((off, bytes) in img.sectors) System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)
        return MemReader(image)
    }

    /**
     * 真实 VolumeReader I/O 层复现：不 override read/write，走真实的 512B 单元 LRU 缓存 +
     * read-modify-write（真机唯一走的路径），仅把 decrypt/encrypt override 成恒等、channel
     * 用临时文件后端。[MemReader] 绕过了缓存路径，此 reader 补上——若缓存有写后陈旧 / 驱逐
     * 丢脏 bug，只有这里能揪出。encStart=0（临时文件即数据区，无卷头偏移）。
     */
    private class ChannelReader(private val ch: java.nio.channels.FileChannel, private val size: Long) :
        VolumeReader(ch, null) {
        override val dataSize: Long get() = size
        override fun decryptUnitData(unitNo: Long, buf: ByteArray) { /* 恒等 */ }
        override fun encryptUnitData(unitNo: Long, buf: ByteArray) { /* 恒等 */ }
    }

    private fun buildChannel(cs: Int): Pair<ChannelReader, java.io.File> {
        val img = NtfsFormatter.buildEmpty(dataSize, cs)
        val f = java.io.File.createTempFile("ntfs_cs${cs}_", ".img")
        f.deleteOnExit()
        java.io.RandomAccessFile(f, "rw").use { raf ->
            raf.setLength(dataSize)
            for ((off, bytes) in img.sectors) { raf.seek(off); raf.write(bytes) }
        }
        val ch = java.io.RandomAccessFile(f, "rw").channel
        return ChannelReader(ch, dataSize) to f
    }

    /**
     * chkdsk 视角的结构验证：遍历全 MFT + root 索引，收集问题串。空 = 干净。
     * 检查：①每 in-use 记录 USA+FILE+属性链到 END；②每属性 totalLen 合法、非驻留 runs 在卷内；
     * ③root $I30 可完整遍历、每索引项指向的 MFT 记录 in-use；④双向：每个被索引引用的记录都 in-use。
     */
    private fun verify(reader: VolumeReader, tag: String): String {
        val problems = ArrayList<String>()
        val boot = NtfsBoot.parse(reader.read(0, 512))
        val codec = NtfsRecordCodec(boot)
        val recSize = boot.fileRecordSize
        val totalClusters = boot.totalSectors / boot.sectorsPerCluster

        // MFT 记录总数（从记录 0 的 $DATA realSize）。
        val rec0 = reader.read(boot.mftByteOffset, recSize).also { codec.applyUsaFixup(it) }
        val data0 = NtfsRecordCodec.findAttr(NtfsRecordCodec.parseAttrs(rec0), NtfsRecordCodec.ATTR_DATA, "")
        val totalRecords = ((data0?.realSize ?: 0L) / recSize).toInt().coerceIn(0, 4096)

        fun recOffset(no: Int): Long = boot.mftByteOffset + no.toLong() * recSize

        for (no in 0 until totalRecords) {
            val raw = reader.read(recOffset(no), recSize)
            if (raw[0] != 'F'.code.toByte() || raw[1] != 'I'.code.toByte()) continue // 未用/空
            if (!codec.applyUsaFixup(raw)) { problems.add("rec$no USA fixup 失败"); continue }
            val flags = NtfsRecordCodec.u16(raw, 0x16)
            if (flags and 0x0001 == 0) continue // 非 in-use，跳过
            // 属性链完整性。
            val used = NtfsRecordCodec.u32(raw, 0x18).toInt()
            var off = NtfsRecordCodec.u16(raw, 0x14)
            var foundEnd = false; var iter = 0
            while (off + 4 <= recSize && iter < 40) {
                val type = NtfsRecordCodec.u32(raw, off)
                if (type == 0xFFFFFFFFL) { foundEnd = true; break }
                val tot = NtfsRecordCodec.u32(raw, off + 4).toInt()
                if (tot <= 0 || off + tot > recSize) { problems.add("rec$no attr@0x${off.toString(16)} type=0x${type.toString(16)} totalLen=$tot 越界(recSize=$recSize)"); break }
                // 非驻留 runs 在卷内。
                if (raw[off + 8].toInt() != 0) {
                    val runsOff = NtfsRecordCodec.u16(raw, off + 0x20)
                    if (runsOff in 1 until tot) {
                        val runs = NtfsRecordCodec.decodeRuns(raw, off + runsOff)
                        for (r in runs) if (!r.sparse && (r.lcn < 0 || r.lcn + r.length > totalClusters))
                            problems.add("rec$no attr type=0x${type.toString(16)} run lcn=${r.lcn} len=${r.length} 越界(totalClusters=$totalClusters)")
                    }
                }
                off += tot; iter++
            }
            if (!foundEnd) problems.add("rec$no 属性链未见 END (used=0x${used.toString(16)})")
        }

        // root $I30 可遍历性 + 索引项一致性（复用运行时读侧）。递归遍历全目录树收集可达记录。
        val fs = NtfsFileSystem.mount(reader)
        val reachable = HashSet<Long>()
        fun walk(dirRef: Long) {
            val es = runCatching { fs.listDir(dirRef) }.getOrElse {
                problems.add("rec$dirRef listDir 抛异常 ${it.message}"); emptyList()
            }
            for (e in es) {
                val ref = e.firstCluster
                if (ref < 16 || ref >= totalRecords) { problems.add("目录 rec$dirRef 项 '${e.name}' mftRef=$ref 越界"); continue }
                val tgt = reader.read(recOffset(ref.toInt()), recSize)
                if (tgt[0] != 'F'.code.toByte()) { problems.add("项 '${e.name}' → rec$ref 非 FILE"); continue }
                codec.applyUsaFixup(tgt)
                if (NtfsRecordCodec.u16(tgt, 0x16) and 0x0001 == 0)
                    problems.add("项 '${e.name}' → rec$ref 未标 in-use（悬空索引项）")
                if (reachable.add(ref) && e.isDirectory) walk(ref)   // 递归子目录，防环
            }
        }
        walk(0L)

        // ④ 反向孤立检测（chkdsk 阶段2「未编制索引的文件」的直接对应）：
        //   每个 in-use 的用户记录（no≥24，排除系统 0..23）必须从 root 递归可达，
        //   否则 = 孤立文件（chkdsk 会捞进 found.000/回收箱）。真机「4 个未索引文件」即此。
        for (no in 24 until totalRecords) {
            val raw = reader.read(recOffset(no), recSize)
            if (raw[0] != 'F'.code.toByte() || raw[1] != 'I'.code.toByte()) continue
            if (!codec.applyUsaFixup(raw)) continue
            if (NtfsRecordCodec.u16(raw, 0x16) and 0x0001 == 0) continue   // 非 in-use
            if (no.toLong() !in reachable) problems.add("rec$no in-use 但 root 不可达（孤立文件）")
        }
        return if (problems.isEmpty()) "" else "[$tag] " + problems.joinToString(" | ")
    }

    /** 复刻 VolumeBatchTest 写序列，每步后验证全簇。 */
    @Test
    fun writePathAllClusters() {
        val failures = ArrayList<String>()
        for (cs in clusterMatrix) {
            val reader = buildMem(cs)
            val fs = NtfsFileSystem.mount(reader)
            val tag = if (cs < 1024) "${cs}b" else "${cs / 1024}k"

            fun step(desc: String, body: () -> Boolean) {
                val ok = runCatching { body() }.getOrElse { failures.add("[$tag] $desc 抛异常: ${it.message}"); false }
                if (!ok) failures.add("[$tag] $desc 返回 false")
                verify(reader, "$tag/$desc").let { if (it.isNotEmpty()) failures.add(it) }
            }

            step("小文件") { fs.writeFile(0L, "small.txt", "Hello 匿匣".toByteArray()) }
            step("大文件200KB") { fs.writeFile(0L, "big.bin", ByteArray(200 * 1024) { (it and 0xFF).toByte() }) }
            var sub = 0L
            step("建子目录") { sub = fs.mkdir(0L, "subdir"); sub > 0 }
            step("子目录内文件") { fs.writeFile(sub, "inner.txt", "inner".toByteArray()) }
            step("重命名") { fs.rename(0L, "small.txt", "renamed.txt") }
            step("移动到子目录") { fs.move(0L, "renamed.txt", sub) }
            step("删除") { fs.writeFile(0L, "todel.txt", "x".toByteArray()) && fs.deleteFile(0L, "todel.txt") }
            step("覆写") { fs.writeFile(0L, "over.txt", "old".toByteArray()) && fs.overwriteFile(0L, "over.txt", "new longer content".toByteArray()) }
            // 批量 50 文件——真机残余问题高发区。
            var wrote = 0
            for (i in 1..50) { if (fs.writeFile(0L, "batch_%03d.dat".format(i), "file $i".toByteArray())) wrote++ else break }
            if (wrote < 50) failures.add("[$tag] 批量50 仅写成功 $wrote")
            verify(reader, "$tag/批量50").let { if (it.isNotEmpty()) failures.add(it) }
            // case 9：递归删子目录（真机自检末步）。subdir 里有被 move 进来的 renamed.txt + inner.txt。
            //   递归删要清子文件 MFT 记录 + 子目录记录 + 父索引项——真机「4 个孤立文件」高度疑似出在此。
            step("递归删子目录") { fs.rmdir(0L, "subdir", true) }
        }
        if (failures.isNotEmpty()) fail("运行时写路径问题(${failures.size}):\n" + failures.joinToString("\n"))
    }

    /**
     * 真实 I/O 层 + flush + 重挂验证：走真实 [VolumeReader] 的 512B LRU 缓存 + read-modify-write
     * （真机唯一走的路径，[MemReader] 绕过），跑完整设备序列 → flush → **换新 reader 重挂**
     * （丢弃缓存、只信落盘字节）→ verify。若缓存有写后陈旧 / 驱逐丢脏 / flush 不落盘的 bug，
     * 只有这里能揪出——真机「4 个孤立文件」的头号疑点（写序列末态在缓存里干净，但落盘缺了）。
     */
    @Test
    fun channelIoWithRemountAllClusters() {
        val failures = ArrayList<String>()
        for (cs in clusterMatrix) {
            val tag = if (cs < 1024) "${cs}b" else "${cs / 1024}k"
            val (reader, file) = buildChannel(cs)
            try {
                val fs = NtfsFileSystem.mount(reader)
                // 完整设备序列（与 writePathAllClusters 同）。
                fs.writeFile(0L, "small.txt", "Hello 匿匣".toByteArray())
                fs.writeFile(0L, "big.bin", ByteArray(200 * 1024) { (it and 0xFF).toByte() })
                val sub = fs.mkdir(0L, "subdir")
                if (sub > 0) fs.writeFile(sub, "inner.txt", "inner".toByteArray())
                fs.rename(0L, "small.txt", "renamed.txt")
                if (sub > 0) fs.move(0L, "renamed.txt", sub)
                fs.writeFile(0L, "todel.txt", "x".toByteArray()); fs.deleteFile(0L, "todel.txt")
                fs.writeFile(0L, "over.txt", "old".toByteArray()); fs.overwriteFile(0L, "over.txt", "new longer content".toByteArray())
                var wrote = 0
                for (i in 1..50) { if (fs.writeFile(0L, "batch_%03d.dat".format(i), "file $i".toByteArray())) wrote++ else break }
                if (wrote < 50) failures.add("[$tag] 批量50 仅写成功 $wrote")
                if (sub > 0) fs.rmdir(0L, "subdir", true)
                fs.clearDirtyFlag()
                reader.flush()

                // 换新 reader 重挂：丢弃旧缓存，只读落盘字节（真机卸载后 chkdsk 看到的）。
                val ch2 = java.io.RandomAccessFile(file, "rw").channel
                val reader2 = ChannelReader(ch2, dataSize)
                verify(reader2, "$tag/重挂").let { if (it.isNotEmpty()) failures.add(it) }
                ch2.close()
            } finally {
                runCatching { reader.close() }
                runCatching { file.delete() }
            }
        }
        if (failures.isNotEmpty()) fail("真实 I/O 层重挂问题(${failures.size}):\n" + failures.joinToString("\n"))
    }

    /**
     * 深度多叶 B+树压测：全簇一直建文件到写失败为止（远超单叶容量，强制多 INDX 叶子 +
     * 分隔符提升到 root），验证两条 chkdsk 关心的性质：
     *   ① 优雅失败：写满 root 容量后 writeFile 返 false（不是抛异常、不是写坏盘）。
     *   ② 无损：已写成功的每个文件都能被运行时读侧完整列出（多叶树可遍历、无丢失无重复），
     *      且删一半后收缩仍完整。区分「干净的容量上限」与「损坏」——后者才是 bug。
     *
     * 注：root 目录用户文件上限约 111（受 1024B MFT 记录内驻留 $INDEX_ROOT 放分隔符的
     *   2 层 B+树上限约束，3 层保守拒绝），全簇一致——证明大簇 VCN 修复后与小簇同构。
     *   这是已知的干净上限，非损坏；50 文件的设备自检远在其下。
     */
    @Test
    fun deepMultiLeafAllClusters() {
        val failures = ArrayList<String>()
        for (cs in clusterMatrix) {
            val reader = buildMem(cs)
            val fs = NtfsFileSystem.mount(reader)
            val tag = if (cs < 1024) "${cs}b" else "${cs / 1024}k"

            // ① 一直建到失败为止（上限 500，防死循环）。
            val written = ArrayList<String>()
            var threw = false
            for (i in 1..500) {
                val nm = "f%04d.dat".format(i)
                val ok = runCatching { fs.writeFile(0L, nm, "x".toByteArray()) }
                    .getOrElse { threw = true; failures.add("[$tag] 写第 $i 个抛异常: ${it.message}"); false }
                if (threw) break
                if (!ok) break
                written.add(nm)
            }
            if (written.size < 60) failures.add("[$tag] root 仅容纳 ${written.size} 文件（预期 ≥60，50 自检需求）")
            verify(reader, "$tag/建${written.size}").let { if (it.isNotEmpty()) failures.add(it) }

            // ② 无损：已写成功的全部可列出。
            val listed = fs.listDir(0L).map { it.name }.filter { !it.startsWith("\$") && it != "." }.toSet()
            val missing = written.filter { it !in listed }
            if (missing.isNotEmpty()) failures.add("[$tag] 建 ${written.size} 后缺失 ${missing.size} 项: ${missing.take(5)}")
            if (listed.size != written.size) failures.add("[$tag] 列出 ${listed.size} ≠ 写入 ${written.size}（重复或多余）")

            // ③ 删一半（奇数下标）后收缩仍完整。
            val toDelete = written.filterIndexed { idx, _ -> idx % 2 == 0 }
            val toKeep = written.filterIndexed { idx, _ -> idx % 2 == 1 }
            for (nm in toDelete) fs.deleteFile(0L, nm)
            verify(reader, "$tag/删${toDelete.size}").let { if (it.isNotEmpty()) failures.add(it) }
            val after = fs.listDir(0L).map { it.name }.filter { !it.startsWith("\$") && it != "." }.toSet()
            val badMissing = toKeep.filter { it !in after }
            val badLingering = toDelete.filter { it in after }
            if (badMissing.isNotEmpty()) failures.add("[$tag] 删后应留却丢 ${badMissing.size}: ${badMissing.take(5)}")
            if (badLingering.isNotEmpty()) failures.add("[$tag] 删后仍残留 ${badLingering.size}: ${badLingering.take(5)}")
        }
        if (failures.isNotEmpty()) fail("深度多叶问题(${failures.size}):\n" + failures.joinToString("\n"))
    }
}
