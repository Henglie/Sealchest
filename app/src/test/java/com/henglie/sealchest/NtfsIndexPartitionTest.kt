package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsIndex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * NTFS directory index 2-level B-tree partition invariants ([NtfsIndex.partitionLeaves]).
 * Pure JVM, sub-second. No native, no VolumeReader.
 *
 * Guards Bug C (2026-07-14 device run): NTFS <=4K clusters "batch create 50 files" fails
 * at the 34th item (device reported listed=33). Root cause: the old "empty tail leaf fix"
 * shoved the just-overflowed separator back into the ALREADY-FULL previous leaf -> that leaf
 * exceeds cap -> buildIndxLeafRecord returns null -> the whole write fails. >=8K clusters have
 * a big enough leaf that 50 items fit in one leaf and never split, so only <=4K is affected.
 *
 * partitionLeaves is a companion pure function (no instance state, no native), callable directly.
 * We assert the three B-tree invariants: (1) separators == leaves-1; (2) every leaf non-empty
 * and <= cap; (3) reconstructed order (leaf0 ++ sep0 ++ leaf1 ++ ...) equals input order.
 *
 * partitionLeaves only reads entry .size, so synthetic fixed-size byte arrays are a faithful
 * stand-in for real $FILE_NAME index entries (device batch_%03d.dat entry = 112 bytes).
 */
class NtfsIndexPartitionTest {

    /** A synthetic index entry of exactly [size] bytes (identity carried by array reference). */
    private fun entry(size: Int): ByteArray = ByteArray(size)

    /** Assert all B-tree invariants and that leaves+separators splice back to the input in order. */
    private fun assertInvariants(sorted: List<ByteArray>, cap: Int, part: NtfsIndex.Companion.LeafPartition) {
        // (1) separators == leaves - 1
        assertEquals("separators must equal leaves-1", part.leaves.size - 1, part.separators.size)
        // (2) every leaf non-empty and total bytes <= cap
        for ((i, leaf) in part.leaves.withIndex()) {
            assertTrue("leaf $i must not be empty", leaf.isNotEmpty())
            val bytes = leaf.sumOf { it.size }
            assertTrue("leaf $i bytes $bytes exceeds cap $cap", bytes <= cap)
        }
        // (3) reconstructed order = input: leaf0 ++ sep0 ++ leaf1 ++ sep1 ++ ... ++ leafK
        val rebuilt = ArrayList<ByteArray>()
        for (i in part.leaves.indices) {
            rebuilt.addAll(part.leaves[i])
            if (i < part.separators.size) rebuilt.add(part.separators[i])
        }
        assertEquals("reconstructed item count must equal input", sorted.size, rebuilt.size)
        for (k in sorted.indices) {
            assertTrue("reconstructed item $k differs from input (order broken)", sorted[k] === rebuilt[k])
        }
    }

    /**
     * Bug C exact reproduction: cap=4016 (real leaf capacity at <=4K clusters), 112 bytes per
     * entry (device batch_%03d.dat $FILE_NAME index entry size), 37 items (root item count when
     * the 34th batch file is being written). Old code returned null here; new code partitions ok.
     */
    @Test
    fun bugC_boundaryDoesNotOverflowLeaf() {
        val cap = 4016
        val sorted = (1..37).map { entry(112) }
        val part = NtfsIndex.partitionLeaves(sorted, cap)
        assertNotNull("37 x 112B / cap $cap must partition (Bug C: old code returned null here)", part)
        assertInvariants(sorted, cap, part!!)
    }

    /**
     * Sweep item counts across several caps. This crosses every "last item exactly overflows,
     * tail leaf would be empty" boundary. All must satisfy the invariants.
     */
    @Test
    fun sweepAllCountsMaintainInvariants() {
        for (cap in listOf(1024, 2048, 4016, 8176)) {
            for (n in 1..200) {
                val sorted = (1..n).map { entry(112) }
                val part = NtfsIndex.partitionLeaves(sorted, cap)
                assertNotNull("cap=$cap n=$n should partition", part)
                assertInvariants(sorted, cap, part!!)
            }
        }
    }

    /** Single item larger than cap -> cannot partition -> null (caller also guards; double safety). */
    @Test
    fun oversizeSingleEntryReturnsNull() {
        assertNull("oversize single entry must return null", NtfsIndex.partitionLeaves(listOf(entry(5000)), 4016))
    }

    /** Small directory stays in a single leaf with no separators. */
    @Test
    fun smallInputSingleLeaf() {
        val sorted = (1..3).map { entry(100) }
        val part = NtfsIndex.partitionLeaves(sorted, 4016)
        assertNotNull(part)
        assertEquals("3 small items should be a single leaf", 1, part!!.leaves.size)
        assertEquals(0, part.separators.size)
    }
}
