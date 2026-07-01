// ============================================================
//  密匣 Sealchest · SHA-256 自包含实现（头文件）
//  不依赖 OpenSSL / BoringSSL，纯标准 C++，任何 NDK / ABI 都能编。
//  FIPS 180-4 标准 SHA-256。
//
//  第一阶段用途：native 自检的已知向量比对，证明 native 链路通。
//  （VeraCrypt 接入后，卷头派生用的是它自带的 Sha2.c，与本文件无关。）
// ============================================================
#ifndef SEALCHEST_SHA256_H
#define SEALCHEST_SHA256_H

#include <cstdint>
#include <cstddef>
#include <string>

namespace sc {

/**
 * 流式 SHA-256：可分块 update，适合大文件不占内存。
 * 用法：Sha256 h; h.update(buf, n); ...; std::string hex = h.hexDigest();
 */
class Sha256 {
public:
    Sha256();

    /** 喂入一段数据，可多次调用。 */
    void update(const uint8_t* data, size_t len);

    /** 结束并取 32 字节摘要写入 out[32]。调用后对象不应再 update。 */
    void final(uint8_t out[32]);

    /** 便捷：结束并返回小写十六进制字符串（64 字符）。 */
    std::string hexDigest();

    /** 一次性：对整段数据算 SHA-256，返回小写 hex。 */
    static std::string hash(const uint8_t* data, size_t len);

private:
    void transform(const uint8_t* chunk);

    uint32_t state_[8];     // 8 个工作变量 h0..h7
    uint64_t bitLen_;       // 已处理的总比特数
    uint8_t buffer_[64];    // 未满一块的缓冲
    size_t bufferLen_;      // 缓冲已用字节
};

} // namespace sc

#endif // SEALCHEST_SHA256_H
