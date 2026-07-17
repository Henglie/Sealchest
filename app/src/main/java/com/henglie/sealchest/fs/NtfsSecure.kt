package com.henglie.sealchest.fs

/**
 * NTFS $Secure (MFT record 9) content builders: $SDS data stream + $SDH / $SII view indexes.
 *
 * Goal: give every file/dir a resolvable security_id (0x100) so a manually-run chkdsk stays
 * silent about "missing/invalid security". The mount driver resolves security lazily and
 * degrades to a default SD on any lookup miss, so this stream can never block mounting — the
 * downside of a subtle byte error is bounded to "no better than security_id=0".
 *
 * Layout follows ntfs-3g layout.h + mkntfs + [MS-DTYP]:
 *   - ONE shared self-relative SECURITY_DESCRIPTOR (owner/group Administrators, DACL
 *     Everyone:FullControl, no SACL) = 80 bytes (0x50), 4-byte aligned (required by the hash).
 *   - $SDS: SECURITY_DESCRIPTOR_HEADER(0x14) + SD, 16-byte aligned; a mirror copy at
 *     +0x40000 (chkdsk redundancy; mount reads only the primary at offset 0).
 *   - $SDH index (COLLATION_NTOFS_SECURITY_HASH=0x12): key=(hash,security_id).
 *   - $SII index (COLLATION_NTOFS_ULONG=0x10): key=security_id.
 *
 * All values are little-endian except the SID IdentifierAuthority (48-bit big-endian).
 */
internal object NtfsSecure {

    const val FIRST_SECURITY_ID = 0x100
    const val COLLATION_NTOFS_ULONG = 0x10L          // $SII
    const val COLLATION_NTOFS_SECURITY_HASH = 0x12L  // $SDH
    const val SDS_MIRROR_STRIDE = 0x40000L           // primary/mirror block stride (256 KB)

    private const val SD_HEADER_LEN = 0x14           // SECURITY_DESCRIPTOR_HEADER

    /**
     * Shared self-relative SECURITY_DESCRIPTOR (80 bytes).
     * owner=group=Administrators (S-1-5-32-544), DACL: Everyone (S-1-1-0) FILE_ALL_ACCESS.
     */
    fun buildSharedSd(): ByteArray {
        val sd = ByteArray(0x50)
        // --- header (0x14) ---
        sd[0x00] = 1                      // Revision
        sd[0x01] = 0                      // Sbz1
        putU16(sd, 0x02, 0x8004)          // Control = SE_SELF_RELATIVE | SE_DACL_PRESENT
        putU32(sd, 0x04, 0x30L)           // OwnerOffset
        putU32(sd, 0x08, 0x40L)           // GroupOffset
        putU32(sd, 0x0C, 0x00L)           // SaclOffset = none
        putU32(sd, 0x10, 0x14L)           // DaclOffset
        // --- DACL @0x14 (size 0x1C = 8 header + 20 ACE) ---
        sd[0x14] = 2                      // AclRevision = ACL_REVISION
        sd[0x15] = 0                      // Sbz1
        putU16(sd, 0x16, 0x1C)            // AclSize
        putU16(sd, 0x18, 1)              // AceCount
        putU16(sd, 0x1A, 0)              // Sbz2
        // --- ACE @0x1C (ACCESS_ALLOWED_ACE, size 0x14 = 8 + 12-byte SID) ---
        sd[0x1C] = 0                      // AceType = ACCESS_ALLOWED_ACE_TYPE
        sd[0x1D] = 0                      // AceFlags
        putU16(sd, 0x1E, 0x14)            // AceSize
        putU32(sd, 0x20, 0x001F01FFL)     // AccessMask = FILE_ALL_ACCESS
        writeSidEveryone(sd, 0x24)        // S-1-1-0 (12 bytes) -> 0x24..0x30
        // --- Owner SID @0x30, Group SID @0x40 (Administrators, 16 bytes each) ---
        writeSidAdministrators(sd, 0x30)
        writeSidAdministrators(sd, 0x40)
        return sd
    }

    /** S-1-1-0 Everyone: Rev=1, SubAuthCount=1, IdAuth=1 (BE 48-bit), SubAuth[0]=0. 12 bytes. */
    private fun writeSidEveryone(b: ByteArray, off: Int) {
        b[off] = 1; b[off + 1] = 1
        // IdentifierAuthority (48-bit big-endian) = 1
        b[off + 2] = 0; b[off + 3] = 0; b[off + 4] = 0
        b[off + 5] = 0; b[off + 6] = 0; b[off + 7] = 1
        putU32(b, off + 8, 0L)            // SubAuthority[0] = 0
    }

    /** S-1-5-32-544 Administrators: Rev=1, SubAuthCount=2, IdAuth=5, {32,544}. 16 bytes. */
    private fun writeSidAdministrators(b: ByteArray, off: Int) {
        b[off] = 1; b[off + 1] = 2
        b[off + 2] = 0; b[off + 3] = 0; b[off + 4] = 0
        b[off + 5] = 0; b[off + 6] = 0; b[off + 7] = 5
        putU32(b, off + 8, 32L)           // SubAuthority[0] = 32 (BUILTIN)
        putU32(b, off + 12, 544L)         // SubAuthority[1] = 544 (Administrators)
    }

    /**
     * NTFS security-descriptor hash (ntfs_security_hash): over the SD bytes (must be /4),
     * hash = ROL3(hash) + dword_le[i]. Returns u32 (as signed Int with identical bit pattern).
     */
    fun securityHash(sd: ByteArray): Int {
        var hash = 0
        var i = 0
        while (i + 4 <= sd.size) {
            val d = (sd[i].toInt() and 0xFF) or
                    ((sd[i + 1].toInt() and 0xFF) shl 8) or
                    ((sd[i + 2].toInt() and 0xFF) shl 16) or
                    ((sd[i + 3].toInt() and 0xFF) shl 24)
            hash = ((hash ushr 29) or (hash shl 3)) + d   // u32 wraparound is intended
            i += 4
        }
        return hash
    }

    /** Aligned length of one $SDS entry (header + SD, rounded to 16). */
    fun sdsEntryAligned(sd: ByteArray): Int = align16(SD_HEADER_LEN + sd.size)

    /** Real (data) size of the $SDS stream: mirror stride + one aligned entry. */
    fun sdsDataSize(sd: ByteArray): Long = SDS_MIRROR_STRIDE + sdsEntryAligned(sd)

    /**
     * Build the raw $SDS stream bytes: primary entry at offset 0, identical mirror at 0x40000.
     * Both headers carry offset=0 (the primary location), per spec.
     */
    fun buildSdsStream(sd: ByteArray, securityId: Int, hash: Int): ByteArray {
        val entryLen = SD_HEADER_LEN + sd.size
        val out = ByteArray((SDS_MIRROR_STRIDE + align16(entryLen)).toInt())
        writeSdsEntry(out, 0, sd, securityId, hash)
        writeSdsEntry(out, SDS_MIRROR_STRIDE.toInt(), sd, securityId, hash)
        return out
    }

    private fun writeSdsEntry(buf: ByteArray, at: Int, sd: ByteArray, securityId: Int, hash: Int) {
        putU32(buf, at + 0x00, hash.toLong() and 0xFFFFFFFFL)
        putU32(buf, at + 0x04, securityId.toLong())
        putU64(buf, at + 0x08, 0L)                                  // offset of primary = 0
        putU32(buf, at + 0x10, (SD_HEADER_LEN + sd.size).toLong())  // length = header + SD
        System.arraycopy(sd, 0, buf, at + SD_HEADER_LEN, sd.size)
    }

    /**
     * $INDEX_ROOT content for $SDH: single (hash,security_id) entry + END marker (resident-only).
     */
    fun buildSdhIndexRoot(securityId: Int, hash: Int, sdLen: Int, bytesPerCluster: Int): ByteArray {
        val entryLen = 0x30
        val content = ByteArray(0x20 + entryLen + 0x10)
        writeIndexRootHead(content, COLLATION_NTOFS_SECURITY_HASH, bytesPerCluster,
            indexLen = 0x10 + entryLen + 0x10)
        var o = 0x20
        // SDH entry
        putU16(content, o + 0x00, 0x18)          // data_offset
        putU16(content, o + 0x02, 0x18)          // data_length
        putU16(content, o + 0x08, entryLen)      // entry_length
        putU16(content, o + 0x0A, 0x08)          // key_length (hash + security_id)
        putU16(content, o + 0x0C, 0)             // flags
        putU32(content, o + 0x10, hash.toLong() and 0xFFFFFFFFL)   // KEY.hash
        putU32(content, o + 0x14, securityId.toLong())             // KEY.security_id
        putU32(content, o + 0x18, hash.toLong() and 0xFFFFFFFFL)   // DATA.hash
        putU32(content, o + 0x1C, securityId.toLong())             // DATA.security_id
        putU64(content, o + 0x20, 0L)                              // DATA.offset (primary)
        putU32(content, o + 0x28, (SD_HEADER_LEN + sdLen).toLong())// DATA.length
        putU32(content, o + 0x2C, 0x00490049L)                     // DATA padding "II"
        o += entryLen
        writeIndexEnd(content, o)
        return content
    }

    /**
     * $INDEX_ROOT content for $SII: single (security_id) entry + END marker (resident-only).
     */
    fun buildSiiIndexRoot(securityId: Int, hash: Int, sdLen: Int, bytesPerCluster: Int): ByteArray {
        val entryLen = 0x28
        val content = ByteArray(0x20 + entryLen + 0x10)
        writeIndexRootHead(content, COLLATION_NTOFS_ULONG, bytesPerCluster,
            indexLen = 0x10 + entryLen + 0x10)
        var o = 0x20
        putU16(content, o + 0x00, 0x14)          // data_offset
        putU16(content, o + 0x02, 0x14)          // data_length
        putU16(content, o + 0x08, entryLen)      // entry_length
        putU16(content, o + 0x0A, 0x04)          // key_length (security_id)
        putU16(content, o + 0x0C, 0)             // flags
        putU32(content, o + 0x10, securityId.toLong())             // KEY.security_id
        putU32(content, o + 0x14, hash.toLong() and 0xFFFFFFFFL)   // DATA.hash
        putU32(content, o + 0x18, securityId.toLong())             // DATA.security_id
        putU64(content, o + 0x1C, 0L)                              // DATA.offset (primary)
        putU32(content, o + 0x24, (SD_HEADER_LEN + sdLen).toLong())// DATA.length
        o += entryLen
        writeIndexEnd(content, o)
        return content
    }

    /** INDEX_ROOT header (0x10) + INDEX_HEADER (0x10). entries start at content 0x20. */
    private fun writeIndexRootHead(b: ByteArray, collation: Long, bytesPerCluster: Int, indexLen: Int) {
        putU32(b, 0x00, 0L)                                  // indexed_attr_type = 0 (view index)
        putU32(b, 0x04, collation)                           // collation rule
        putU32(b, 0x08, NtfsFormatter.indexRecordSize(bytesPerCluster).toLong())
        b[0x0C] = NtfsFormatter.indexBufferCode(bytesPerCluster).toByte()
        // INDEX_HEADER @0x10
        putU32(b, 0x10, 0x10L)                               // entries_offset (rel to INDEX_HEADER)
        putU32(b, 0x14, indexLen.toLong())                   // index_length
        putU32(b, 0x18, indexLen.toLong())                   // allocated_size
        putU32(b, 0x1C, 0L)                                  // flags = 0 (small, resident only)
    }

    /** Terminal END index entry (16 bytes, LAST flag, no key/data). */
    private fun writeIndexEnd(b: ByteArray, o: Int) {
        putU16(b, o + 0x08, 0x10)                            // entry_length
        putU16(b, o + 0x0A, 0)                               // key_length
        putU16(b, o + 0x0C, NtfsFormatter.INDEX_ENTRY_LAST)  // flags = LAST
    }

    private fun align16(v: Int): Int = (v + 15) and 15.inv()
}
