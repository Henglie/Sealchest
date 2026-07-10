package com.henglie.sealchest.core

import java.io.File

/**
 * 块设备只读枚举（路线图 F2 PoC）。需 root（[RootManager.isGranted]）。
 *
 * **本卡是探针**：只读枚举 `/dev/block/` 下的分区/块设备，验证访问链路。
 * 不加解密、不写、不挂载。真正分区加密（F2/F3）另立项。
 *
 * 安卓块设备形态与桌面差异大：
 *  - 内部存储通常是 dm-*（device-mapper）/ mmcblk0*（eMMC）/ sda*（UFS）。
 *  - SD 卡通常 mmcblk1* / sdb*。
 *  - /dev/block/by-name/ 有符号链接（如 userdata / system / vendor），最易读。
 *  - /proc/partitions 有内核已知分区表（块数 × 1KB）。
 *
 * 无 root 时本类所有方法返回空列表，绝不崩溃。调用方（UI）应先 [RootManager.isGranted]
 * 再调，入口本身也应 root-gated（X3）。
 *
 * 线程：[list] 会起 `su -c` 子进程读 /proc/partitions + ls /dev/block/by-name/，阻塞，放后台线程。
 */
object BlockDeviceEnumerator {

    /** 一个块设备条目。 */
    data class BlockDevice(
        /** 设备节点路径，如 /dev/block/sda23。 */
        val path: String,
        /** 符号名（by-name 链接名），如 userdata / system；无则取 path 基名。 */
        val name: String,
        /** 大小（字节），从 /proc/partitions 块数 × 1024 算。0 表示未知。 */
        val sizeBytes: Long,
        /** 是否为可移动介质（SD 卡 / U 盘）。粗判：mmcblk1* / sd[b-z]* / sddr*。 */
        val isRemovable: Boolean,
    )

    /**
     * 只读枚举块设备。需 root。无 root 返空列表。
     * 数据源：`cat /proc/partitions`（内核分区表）+ `ls -l /dev/block/by-name/`（符号链接）。
     * 不挂载、不打开、不读写任何设备。
     */
    fun list(): List<BlockDevice> {
        if (!RootManager.isGranted()) return emptyList()
        val partitions = readPartitions()
        val byName = readByNameLinks()
        // 合并：partitions 给大小，by-name 给友好名。按 path 去重。
        val byPath = HashMap<String, BlockDevice>()
        for ((devName, sizeBlocks) in partitions) {
            val path = "/dev/block/$devName"
            val size = sizeBlocks * 1024L
            byPath[path] = BlockDevice(
                path = path,
                name = devName,
                sizeBytes = size,
                isRemovable = isLikelyRemovable(devName),
            )
        }
        // by-name 覆盖 name（更友好），但不改 size/path
        for ((linkName, target) in byName) {
            val dev = byPath[target]
            if (dev != null) {
                byPath[target] = dev.copy(name = linkName)
            }
        }
        return byPath.values.sortedByDescending { it.sizeBytes }
    }

    /**
     * 读 /proc/partitions。格式：major minor #blocks name。
     * 返回 (deviceName -> blocks) 映射。blocks × 1024 = 字节。
     * 失败返空 map（绝不抛）。
     */
    private fun readPartitions(): Map<String, Long> {
        return runCatching {
            val out = execRoot("cat /proc/partitions")
            val result = HashMap<String, Long>()
            for (line in out.lineSequence()) {
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size >= 4 && parts[0].all { it.isDigit() }) {
                    val name = parts[3]
                    val blocks = parts[2].toLongOrNull() ?: 0L
                    if (name.isNotEmpty() && blocks > 0) result[name] = blocks
                }
            }
            result
        }.getOrDefault(emptyMap())
    }

    /**
     * 读 /dev/block/by-name/ 的符号链接。返回 (linkName -> targetPath) 映射。
     * 失败返空 map。
     */
    private fun readByNameLinks(): Map<String, String> {
        return runCatching {
            val dir = File("/dev/block/by-name")
            if (!dir.isDirectory) return@runCatching emptyMap()
            val out = execRoot("ls -l /dev/block/by-name/")
            val result = HashMap<String, String>()
            for (line in out.lineSequence()) {
                // lrwxrwxrwx root root 20 date byname -> /dev/block/sda23
                val arrowIdx = line.indexOf("->")
                if (arrowIdx < 0) continue
                val target = line.substring(arrowIdx + 2).trim()
                val tokens = line.substring(0, arrowIdx).trim().split(Regex("\\s+"))
                val linkName = tokens.lastOrNull() ?: continue
                if (target.startsWith("/dev/block/")) {
                    result[linkName] = target
                }
            }
            result
        }.getOrDefault(emptyMap())
    }

    /** 粗判是否可移动介质。mmcblk1* / sd[b-z]* / sddr* 通常为 SD / U 盘。 */
    private fun isLikelyRemovable(devName: String): Boolean {
        return devName.startsWith("mmcblk1") ||
            (devName.startsWith("sd") && devName.length > 2 && devName[1] in 'b'..'z') ||
            devName.startsWith("sddr")
    }

    /** 执行 `su -c cmd`，返回 stdout。失败返空串。 */
    private fun execRoot(cmd: String): String = runCatching {
        val process = ProcessBuilder("su", "-c", cmd)
            .redirectErrorStream(true)
            .start()
        val out = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()
        out
    }.getOrDefault("")
}
