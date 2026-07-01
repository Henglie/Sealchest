// SHA-256 实现（FIPS 180-4），自包含、零依赖（不依赖 OpenSSL/BoringSSL）。
// 保证任何 NDK / ABI 都能编出来，避免外部库带来的链接与体积问题。
//
// 用途：密匣第一阶段 native 自检的已知向量比对，证明 native 链路通。

#include "sha256.h"
#include <cstring>

namespace sc {

namespace {

// SHA-256 轮常量（前 64 个素数立方根小数部分前 32 位）
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

Sha256::Sha256() {
    // 初始哈希值（前 8 个素数平方根小数部分前 32 位）
    state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f; state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
    bitLen_ = 0;
    bufferLen_ = 0;
}

void Sha256::transform(const uint8_t* chunk) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(chunk[i * 4]) << 24) | (uint32_t(chunk[i * 4 + 1]) << 16) |
               (uint32_t(chunk[i * 4 + 2]) << 8) | (uint32_t(chunk[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;

    // 内存红线：清掉栈上消息调度表（含输入派生数据）
    memset(w, 0, sizeof(w));
}

void Sha256::update(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buffer_[bufferLen_++] = data[i];
        if (bufferLen_ == 64) {
            transform(buffer_);
            bitLen_ += 512;
            bufferLen_ = 0;
        }
    }
}

void Sha256::final(uint8_t out[32]) {
    uint64_t totalBits = bitLen_ + uint64_t(bufferLen_) * 8;

    // 追加 0x80，再补 0 到 56 字节，最后 8 字节写长度（大端）
    buffer_[bufferLen_++] = 0x80;
    if (bufferLen_ > 56) {
        while (bufferLen_ < 64) buffer_[bufferLen_++] = 0x00;
        transform(buffer_);
        bufferLen_ = 0;
    }
    while (bufferLen_ < 56) buffer_[bufferLen_++] = 0x00;
    for (int i = 7; i >= 0; --i) {
        buffer_[bufferLen_++] = uint8_t((totalBits >> (i * 8)) & 0xff);
    }
    transform(buffer_);

    // 输出大端 32 字节
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = uint8_t((state_[i] >> 24) & 0xff);
        out[i * 4 + 1] = uint8_t((state_[i] >> 16) & 0xff);
        out[i * 4 + 2] = uint8_t((state_[i] >> 8) & 0xff);
        out[i * 4 + 3] = uint8_t(state_[i] & 0xff);
    }

    // 内存红线：清空内部状态与缓冲，不留哈希中间态
    memset(state_, 0, sizeof(state_));
    memset(buffer_, 0, sizeof(buffer_));
    bufferLen_ = 0;
    bitLen_ = 0;
}

std::string Sha256::hexDigest() {
    uint8_t out[32];
    final(out);
    static const char* d = "0123456789abcdef";
    std::string s;
    s.resize(64);
    for (int i = 0; i < 32; ++i) {
        s[i * 2]     = d[(out[i] >> 4) & 0xf];
        s[i * 2 + 1] = d[out[i] & 0xf];
    }
    memset(out, 0, sizeof(out));
    return s;
}

std::string Sha256::hash(const uint8_t* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.hexDigest();
}

}  // namespace sc
