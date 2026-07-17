package com.henglie.sealchest.fs

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile

/**
 * 卷端到端自检器（真机设备侧「一键测试」核心）。
 *
 * 目的：把恒烈原本要手动做几十遍的「建容器 → 桌面 VC 挂载 → 塞文件 → chkdsk」
 * 循环，压成 App 内一次点击。在真机 arm64 + 真加密核心 + 真 SAF 落盘上跑完整条
 * 写读闭环，即时揪出字节级回归——比等桌面 chkdsk 快几个数量级。
 *
 * 覆盖 FAT / exFAT / NTFS 三种文件系统 × 全簇大小矩阵。用例 1-9 走统一 [VolumeFs]
 * 接口，与具体格式无关；用例 10（索引 B+树内存自测）仅 NTFS 有，其余格式跳过。
 *
 * 与桌面 chkdsk 的分工：
 *   - 本自检器验「我们自己写的能被我们自己读对」+ 结构不变量。
 *   - 桌面 chkdsk 验「微软的实现认不认」。两者互补，本器先挡下绝大多数低级回归。
 *
 * 全程走真实 [VolumeCreator] 造盘 + [MountManager] 可写挂载 + 各 [VolumeFs] 写路径，
 * 落盘到真容器文件，故测完的容器可直接拖去桌面 VC 复验（不是内存模拟）。
 */
object VolumeBatchTest {

    /** 批量测试固定口令（测试专用容器，非真实数据）。每次取新数组（调用方会 fill(0) 抹除）。 */
    private val testPassword get() = "sealchest-test-1234".toByteArray(Charsets.UTF_8)
    /** 隐藏卷测试口令（与外层卷不同，验隐藏卷独立密钥）。 */
    private val hiddenPassword get() = "sealchest-hidden-5678".toByteArray(Charsets.UTF_8)
    private const val EA_AES = 1
    private const val EA_SERPENT = 2
    private const val EA_TWOFISH = 3
    private const val PRF_SHA512 = 1
    private const val PRF_SHA256 = 3

    /** 合成测试 keyfile 内容（固定字节，非真实文件；验 keyfile 混入路径 create/mount 对称）。 */
    private fun testKeyfile(seed: Int): ByteArray = ByteArray(1024) { ((it * 31 + seed * 7) and 0xFF).toByte() }
    /** 每个测试容器数据区大小：10MB（够跑满全部用例含批量 50 文件 + 200KB 大文件）。 */
    private const val TEST_DATA_SIZE = 10L * 1024 * 1024
    private const val HEADER_AREA = 131072L

    /** 根目录句柄：接口约定各 FS 都把 0 解释为自己的根（FAT/exFAT=rootCluster，NTFS 内部映射记录 5）。 */
    private const val ROOT = 0L

    /**
     * 一个待测配置。除文件系统类型 + 簇大小外，携带完整 VC 功能维度：加密算法 ea、
     * 派生 prf、pim、外层 keyfiles、是否隐藏卷 + 隐藏卷参数。普通卷用默认值。
     */
    private data class Config(
        val label: String,
        val fsType: Int,
        val cluster: Int,
        val ea: Int = EA_AES,
        val prf: Int = PRF_SHA512,
        val pim: Int = 0,
        val keyfileSeeds: List<Int> = emptyList(),   // 空 = 无 keyfile；多个 = 多 keyfile
        val dynamic: Boolean = false,
        /** 隐藏卷：非 null 时走 HiddenVolumeCreator，用隐藏口令挂载测隐藏卷读写。 */
        val hidden: Boolean = false,
    ) {
        fun keyfiles(): List<ByteArray> = keyfileSeeds.map { testKeyfile(it) }
    }

    /** 簇大小矩阵（字节）。0=自动。覆盖 512..65536 全阶梯 + 自动。 */
    private val CLUSTER_MATRIX = listOf(0, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

    private fun clusterTag(c: Int): String =
        if (c == 0) "auto" else if (c < 1024) "${c}b" else "${c / 1024}k"

    /**
     * 待测配置矩阵。两部分：
     *   A. FS × 全簇矩阵（普通 AES/SHA512 密码卷）—— 覆盖三 FS 各簇大小的字节级正确性（27 项）。
     *   B. VC 功能矩阵 —— 每个功能维度各取一个代表 FS/簇跑通即证明该路径 create/mount 对称：
     *      keyfile 卷、多 keyfile 卷、不同 EA(Serpent/Twofish)、不同 PRF(SHA256)、带 PIM、
     *      动态(稀疏)卷、隐藏卷。
     *
     *   隐藏卷约束：HiddenVolumeCreator 只支持 **FAT 外层**（写保护上界只有 FAT 能保守算出，
     *   见其 openOuterAndMeasure），故隐藏卷两项外层强制 FAT；隐藏内层由其固定格式化为 FAT。
     */
    private fun buildMatrix(): List<Config> {
        val out = ArrayList<Config>()
        // A. FS × 全簇矩阵（普通密码卷）。
        for (c in CLUSTER_MATRIX) out.add(Config("fat_${clusterTag(c)}", 0, c))
        for (c in CLUSTER_MATRIX) out.add(Config("exfat_${clusterTag(c)}", 1, c))
        for (c in CLUSTER_MATRIX) out.add(Config("ntfs_${clusterTag(c)}", 2, c))
        // B. VC 功能矩阵（代表 FS/簇，覆盖各加密/卷型路径）。FS 取 exFAT（三 FS 已在 A 全覆盖，
        //    此处只验加密/卷型维度与 FS 读写正交）。
        out.add(Config("kf1_exfat", 1, 4096, keyfileSeeds = listOf(1)))
        out.add(Config("kf3_ntfs", 2, 4096, keyfileSeeds = listOf(1, 2, 3)))
        out.add(Config("ea_serpent_fat", 0, 4096, ea = EA_SERPENT))
        out.add(Config("ea_twofish_exfat", 1, 4096, ea = EA_TWOFISH))
        out.add(Config("prf_sha256_ntfs", 2, 4096, prf = PRF_SHA256))
        out.add(Config("pim_fat", 0, 4096, pim = 15))
        out.add(Config("kf_pim_serpent_ntfs", 2, 4096, ea = EA_SERPENT, pim = 20, keyfileSeeds = listOf(5, 6)))
        out.add(Config("dynamic_exfat", 1, 4096, dynamic = true))
        // 隐藏卷：外层 + 内层均 FAT（HiddenVolumeCreator 限制）。fsType 此处忽略。
        //   hidden_plain：纯口令隐藏卷；hidden_kf：隐藏卷带 keyfile（验 keyfile 混入隐藏派生路径）。
        out.add(Config("hidden_plain", 0, 4096, hidden = true))
        out.add(Config("hidden_kf", 0, 4096, hidden = true, keyfileSeeds = listOf(9)))
        return out
    }

    /** 单个用例结果。[ok] 真 = 通过；[detail] 附失败细节或关键数字。 */
    data class Case(val name: String, val ok: Boolean, val detail: String = "")

    /** 一个容器一轮完整自检的汇总。 */
    data class Report(val containerName: String, val cases: List<Case>) {
        val allPassed: Boolean get() = cases.isNotEmpty() && cases.all { it.ok }
        val passCount: Int get() = cases.count { it.ok }
    }

    /** 全批量结果：每个容器一份 Report + 是否全绿。 */
    data class BatchResult(val reports: List<Report>) {
        val allPassed: Boolean get() = reports.isNotEmpty() && reports.all { it.allPassed }
        fun summary(): String = buildString {
            val green = reports.count { it.allPassed }
            append("批量自检：").append(green).append('/').append(reports.size).append(" 容器全通过\n\n")
            for (r in reports) {
                append(if (r.allPassed) "✓ " else "✗ ")
                append(r.containerName).append("  ").append(r.passCount).append('/').append(r.cases.size)
                append('\n')
                for (c in r.cases) if (!c.ok) {
                    append("    ✗ ").append(c.name).append(": ").append(c.detail).append('\n')
                }
            }
        }
    }

    /**
     * 全自动批量测试：在 SAF 目录 [treeUri] 下，按配置矩阵逐个建容器 → 可写挂载 →
     * 跑完整读写自检 → 汇总。每步进度经 [onProgress] 回传（供 UI 显示）。
     *
     * 必须在 IO 线程调用（造盘/挂载是阻塞 IO）。测试容器留在目录里，供桌面 VC + chkdsk 复验。
     */
    fun runFullBatch(
        context: Context,
        treeUri: Uri,
        onProgress: (String) -> Unit = {},
    ): BatchResult {
        val tree = DocumentFile.fromTreeUri(context, treeUri)
            ?: return BatchResult(emptyList())
        val matrix = buildMatrix()
        val reports = ArrayList<Report>()

        for ((idx, cfg) in matrix.withIndex()) {
            val fileName = "${cfg.label}_10m.hc"
            onProgress("[${idx + 1}/${matrix.size}] 创建 $fileName …")

            // 删掉同名旧文件（重复跑不堆积）。
            tree.findFile(fileName)?.delete()
            val doc = tree.createFile("application/octet-stream", fileName)
            if (doc == null) {
                reports.add(Report(fileName, listOf(Case("创建容器文件", false, "SAF createFile 返回 null"))))
                continue
            }
            val uri = doc.uri

            val report = runCatching {
                createOneContainer(context, uri, cfg)
                onProgress("[${idx + 1}/${matrix.size}] 挂载 + 自检 $fileName …")
                mountAndTest(context, uri, fileName, cfg)
            }.getOrElse { t ->
                Report(fileName, listOf(Case("造盘/挂载", false, t.message ?: t.toString())))
            }
            reports.add(report)
            // 每个容器测完上锁，释放挂载给下一个。
            runCatching { MountManager.lock(context) }
        }
        return BatchResult(reports)
    }

    /**
     * 按 [cfg] 造一个容器到 [uri]（预分配 → 建卷）。失败抛异常。
     *
     * 普通卷：直接 VolumeCreator.create（带 cfg 的 ea/prf/pim/keyfiles/dynamic）。
     * 隐藏卷：先造 **FAT 外层**（外层用测试口令，无 keyfile），再 HiddenVolumeCreator.create
     *   在其中放隐藏卷（隐藏口令 hiddenPassword + cfg.keyfiles()）。隐藏卷毛尺寸取数据区一半，
     *   够跑全部用例又稳落在外层空闲尾部（外层刚格式化，已用上界≈数据区起点，不会撞写保护）。
     */
    private fun createOneContainer(context: Context, uri: Uri, cfg: Config) {
        val totalSize = TEST_DATA_SIZE + 2L * HEADER_AREA
        // 预分配到目标总大小（VolumeCreator 要在末尾写备份头）。
        context.contentResolver.openFileDescriptor(uri, "rw")?.use { pfd ->
            java.io.RandomAccessFile("/proc/self/fd/${pfd.fd}", "rw").use { raf ->
                raf.setLength(totalSize)
            }
        } ?: throw java.io.FileNotFoundException("无法打开新建容器文件")

        val resolver = context.contentResolver
        if (cfg.hidden) {
            // 外层：FAT 密码卷（HiddenVolumeCreator 只支持 FAT 外层）。
            val outerPw = testPassword
            try {
                VolumeCreator.create(
                    resolver = resolver,
                    containerUri = uri,
                    ea = EA_AES,
                    prf = PRF_SHA512,
                    pim = 0,
                    password = outerPw,
                    keyfiles = emptyList(),
                    volumeSizeBytes = TEST_DATA_SIZE,
                    fsType = 0,          // FAT 外层
                    clusterSize = cfg.cluster,
                    dynamic = false,
                    randomFill = false,
                ).getOrThrow()
            } finally {
                outerPw.fill(0)
            }
            // 隐藏卷：毛尺寸取容器数据区的一半，留足外层已用尾部余量。
            val hiddenGross = TEST_DATA_SIZE / 2
            val outerPw2 = testPassword
            val hiddenPw = hiddenPassword
            try {
                HiddenVolumeCreator.create(
                    resolver = resolver,
                    containerUri = uri,
                    outerPassword = outerPw2,
                    outerPim = 0,
                    outerPrf = PRF_SHA512,
                    outerKeyfiles = emptyList(),
                    hiddenEa = cfg.ea,
                    hiddenPrf = cfg.prf,
                    hiddenPim = cfg.pim,
                    hiddenPassword = hiddenPw,
                    hiddenKeyfiles = cfg.keyfiles(),
                    hiddenVolumeBytes = hiddenGross,
                ).getOrThrow()
            } finally {
                outerPw2.fill(0)
                hiddenPw.fill(0)
            }
        } else {
            val pw = testPassword
            try {
                VolumeCreator.create(
                    resolver = resolver,
                    containerUri = uri,
                    ea = cfg.ea,
                    prf = cfg.prf,
                    pim = cfg.pim,
                    password = pw,
                    keyfiles = cfg.keyfiles(),
                    volumeSizeBytes = TEST_DATA_SIZE,
                    fsType = cfg.fsType,
                    clusterSize = cfg.cluster,
                    dynamic = cfg.dynamic,
                    randomFill = false,
                ).getOrThrow()
            } finally {
                pw.fill(0)
            }
        }
    }

    /**
     * 按 [cfg] 可写挂载 [uri] 并跑全部读写用例。
     *
     * 隐藏卷用隐藏口令 hiddenPassword 挂载（MountManager.unlock 先试主头再试隐藏头，隐藏口令
     *   开不了主头 → 落到隐藏头 → 自动定位隐藏数据区）；普通卷用测试口令。keyfiles/pim/prf 取
     *   cfg。EA 不在挂载参数里——openVolume 自解出算法，故只需 prf/pim/keyfile 对上。
     */
    private fun mountAndTest(context: Context, uri: Uri, containerName: String, cfg: Config): Report {
        val pw = if (cfg.hidden) hiddenPassword else testPassword
        try {
            MountManager.unlock(
                context = context,
                uri = uri,
                displayName = containerName,
                password = pw,
                pim = cfg.pim,
                prf = cfg.prf,
                writable = true,
                keyfiles = cfg.keyfiles(),
            )
        } finally {
            pw.fill(0)
        }
        return runCases(containerName)
    }

    /**
     * 对当前已可写挂载的卷跑完整读写自检（也可被 UI「测当前挂载」单独调）。
     * 未挂载 / 只读挂载返回 null。
     */
    fun runOnCurrentMount(): Report? {
        val mount = MountManager.currentMount() ?: return null
        if (mount.closed || !mount.writable) return null
        return runCases(mount.displayName)
    }

    /** 全部读写用例（要求当前已可写挂载一个卷）。每个用例包 runCatching，防单个抛异常中断整轮。 */
    private fun runCases(containerName: String): Report {
        val cases = ArrayList<Case>()

        // 统一比对器：写 bytes 到 dir/name，读回比对。
        fun writeReadBack(dir: Long, name: String, bytes: ByteArray): Boolean {
            val w = MountManager.withWritableFs { it.writeFile(dir, name, bytes) } ?: false
            if (!w) return false
            val entries = MountManager.withFs { it.listDir(dir) } ?: return false
            val e = entries.firstOrNull { it.name == name } ?: return false
            val read = MountManager.withFs { it.readFile(e.firstCluster, e.size, 0, bytes.size) } ?: return false
            return read.contentEquals(bytes)
        }

        // 每个用例包一层 runCatching：某 FS 不支持某操作（抛 UnsupportedOperationException）
        //   或内部异常，都记为该用例失败而非中断整轮。
        fun case(name: String, body: () -> Pair<Boolean, String>) {
            val (ok, detail) = runCatching { body() }.getOrElse { false to (it.message ?: it.toString()) }
            cases.add(Case(name, ok, if (ok) detail else detail.ifEmpty { "失败" }))
        }

        // 用例 1：小文件（NTFS 驻留 $DATA / FAT-exFAT 短簇链）
        case("小文件读写") {
            val data = "Hello, 匿匣! 小文件测试".toByteArray(Charsets.UTF_8)
            writeReadBack(ROOT, "small.txt", data) to ""
        }

        // 用例 2：大文件（多簇）
        case("大文件读写") {
            val data = ByteArray(200 * 1024) { ((it * 31 + 7) and 0xFF).toByte() }
            writeReadBack(ROOT, "big.bin", data) to "200KB 多簇"
        }

        // 用例 3：子目录 + 目录内文件
        var subDirRef = 0L
        case("子目录建文件") {
            subDirRef = MountManager.withWritableFs { it.mkdir(ROOT, "subdir") } ?: 0L
            val made = subDirRef > 0
            val data = "子目录内文件".toByteArray(Charsets.UTF_8)
            val wrote = made && writeReadBack(subDirRef, "inner.txt", data)
            wrote to (if (wrote) "ref=$subDirRef" else "mkdir 或写入失败")
        }

        // 用例 4：重命名
        case("重命名文件") {
            val renamed = MountManager.withWritableFs { it.rename(ROOT, "small.txt", "renamed.txt") } ?: false
            val entries = MountManager.withFs { it.listDir(ROOT) } ?: emptyList()
            val hasNew = entries.any { it.name == "renamed.txt" }
            val goneOld = entries.none { it.name == "small.txt" }
            val ok = renamed && hasNew && goneOld
            ok to (if (ok) "" else "renamed=$renamed new=$hasNew goneOld=$goneOld")
        }

        // 用例 5：移动到子目录
        case("移动文件到子目录") {
            val ok = if (subDirRef > 0) {
                val moved = MountManager.withWritableFs { it.move(ROOT, "renamed.txt", subDirRef) } ?: false
                val rootEntries = MountManager.withFs { it.listDir(ROOT) } ?: emptyList()
                val subEntries = MountManager.withFs { it.listDir(subDirRef) } ?: emptyList()
                moved && rootEntries.none { it.name == "renamed.txt" } && subEntries.any { it.name == "renamed.txt" }
            } else false
            ok to (if (ok) "" else "移动失败或位置不对")
        }

        // 用例 6：删除文件
        case("删除文件") {
            MountManager.withWritableFs { it.writeFile(ROOT, "todelete.txt", "x".toByteArray()) }
            val deleted = MountManager.withWritableFs { it.deleteFile(ROOT, "todelete.txt") } ?: false
            val entries = MountManager.withFs { it.listDir(ROOT) } ?: emptyList()
            val gone = entries.none { it.name == "todelete.txt" }
            val ok = deleted && gone
            ok to (if (ok) "" else "deleted=$deleted gone=$gone")
        }

        // 用例 7：覆写
        case("覆写文件") {
            MountManager.withWritableFs { it.writeFile(ROOT, "over.txt", "旧内容".toByteArray(Charsets.UTF_8)) }
            val newData = "新内容，比原来更长一些的覆写测试数据".toByteArray(Charsets.UTF_8)
            val over = MountManager.withWritableFs { it.overwriteFile(ROOT, "over.txt", newData) } ?: false
            val entries = MountManager.withFs { it.listDir(ROOT) } ?: emptyList()
            val e = entries.firstOrNull { it.name == "over.txt" }
            val readBack = if (e != null) MountManager.withFs { it.readFile(e.firstCluster, e.size, 0, newData.size) } else null
            val ok = over && readBack != null && readBack.contentEquals(newData)
            ok to (if (ok) "" else "覆写或读回不一致")
        }

        // 用例 8：批量 50 文件
        case("批量建 50 文件") {
            var allWrote = true
            for (i in 1..50) {
                val w = MountManager.withWritableFs {
                    it.writeFile(ROOT, "batch_%03d.dat".format(i), "file $i".toByteArray())
                } ?: false
                if (!w) { allWrote = false; break }
            }
            val entries = MountManager.withFs { it.listDir(ROOT) } ?: emptyList()
            val count = entries.count { it.name.startsWith("batch_") }
            val ok = allWrote && count == 50
            ok to (if (ok) "50 全可列" else "allWrote=$allWrote listed=$count")
        }

        // 用例 9：递归删子目录
        case("递归删子目录") {
            val ok = if (subDirRef > 0) {
                val removed = MountManager.withWritableFs { it.rmdir(ROOT, "subdir", true) } ?: false
                val entries = MountManager.withFs { it.listDir(ROOT) } ?: emptyList()
                removed && entries.none { it.name == "subdir" }
            } else false
            ok to (if (ok) "" else "删除失败或仍可见")
        }

        // 用例 10：索引 B+树内存自测（仅 NTFS）。
        run {
            val fs = MountManager.currentMount()?.fs
            if (fs is NtfsFileSystem) {
                case("索引B+树自测") {
                    val rpt = fs.ntfsIndexSelfTest()
                    (!rpt.contains("FAIL")) to rpt.replace("\n", " ; ")
                }
            }
        }

        return Report(containerName, cases)
    }
}
