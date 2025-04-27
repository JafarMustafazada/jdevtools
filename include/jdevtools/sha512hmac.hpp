#ifndef JDEVTOOLS_SHA512HMAC_HPP
#define JDEVTOOLS_SHA512HMAC_HPP

#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>

namespace jdevtools {
	class SHA512 {
	public:
		static const size_t BlockSize = 128;   // SHA-512 processes 1024-bit blocks
		static const size_t DigestSize = 64;   // 512-bit (64-byte) digest
	
		SHA512() { init(); }
	
		// Process input data in chunks.
		void update(const unsigned char* data, size_t len) {
			for (size_t i = 0; i < len; i++) {
				m_data[m_datalen] = data[i];
				m_datalen++;
				if (m_datalen == BlockSize) {
					transform(m_data);
					addBitLength(BlockSize * 8); // 128 bytes * 8 = 1024 bits
					m_datalen = 0;
				}
			}
		}
	
		// Finalize the hash and produce the digest.
		void final(unsigned char hash[DigestSize]) {
			// Update bit length with the remaining data.
			addBitLength(m_datalen * 8);
	
			size_t i = m_datalen;
	
			// Pad: append 0x80 then zeros until 112 bytes (since 128 - 16 = 112).
			if (m_datalen < 112) {
				m_data[i++] = 0x80;
				while (i < 112)
					m_data[i++] = 0x00;
			} else {
				m_data[i++] = 0x80;
				while (i < BlockSize)
					m_data[i++] = 0x00;
				transform(m_data);
				i = 0;
				memset(m_data, 0, 112);
				i = 112;
			}
	
			// Append 128-bit (16-byte) length (big-endian): first 64 bits high, then 64 bits low.
			for (int j = 0; j < 8; j++) {
				m_data[i++] = (m_bitlen[0] >> (56 - j * 8)) & 0xff;
			}
			for (int j = 0; j < 8; j++) {
				m_data[i++] = (m_bitlen[1] >> (56 - j * 8)) & 0xff;
			}
			transform(m_data);
	
			// Convert internal state to digest (big-endian).
			for (int i = 0; i < 8; i++) {
				hash[i * 8 + 0] = (m_state[i] >> 56) & 0xff;
				hash[i * 8 + 1] = (m_state[i] >> 48) & 0xff;
				hash[i * 8 + 2] = (m_state[i] >> 40) & 0xff;
				hash[i * 8 + 3] = (m_state[i] >> 32) & 0xff;
				hash[i * 8 + 4] = (m_state[i] >> 24) & 0xff;
				hash[i * 8 + 5] = (m_state[i] >> 16) & 0xff;
				hash[i * 8 + 6] = (m_state[i] >> 8)  & 0xff;
				hash[i * 8 + 7] = m_state[i] & 0xff;
			}
		}
	
		// Utility: compute SHA512 of a string.
		static std::vector<unsigned char> hash(const std::string &input) {
			SHA512 ctx;
			ctx.update(reinterpret_cast<const unsigned char*>(input.c_str()), input.size());
			unsigned char digest[DigestSize];
			ctx.final(digest);
			return std::vector<unsigned char>(digest, digest + DigestSize);
		}
	
		// Utility: convert digest to hexadecimal string.
		static std::string toHexString(const unsigned char* digest) {
			std::ostringstream oss;
			for (size_t i = 0; i < DigestSize; i++) {
				oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
			}
			return oss.str();
		}
	
	private:
		// Initialize SHA512 context.
		void init() {
			m_datalen = 0;
			m_bitlen[0] = m_bitlen[1] = 0;
			// Initial state (first 64 bits of the fractional parts of the square roots of the first 8 primes)
			m_state[0] = 0x6a09e667f3bcc908ULL;
			m_state[1] = 0xbb67ae8584caa73bULL;
			m_state[2] = 0x3c6ef372fe94f82bULL;
			m_state[3] = 0xa54ff53a5f1d36f1ULL;
			m_state[4] = 0x510e527fade682d1ULL;
			m_state[5] = 0x9b05688c2b3e6c1fULL;
			m_state[6] = 0x1f83d9abfb41bd6bULL;
			m_state[7] = 0x5be0cd19137e2179ULL;
		}
	
		// SHA512 transformation function. Processes one 1024-bit block.
		void transform(const unsigned char data[]) {
			uint64_t m[80];
	
			// Macros for 64-bit operations.
			#define ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
			#define CH(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
			#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
			#define SIGMA0(x) (ROTR64((x),28) ^ ROTR64((x),34) ^ ROTR64((x),39))
			#define SIGMA1(x) (ROTR64((x),14) ^ ROTR64((x),18) ^ ROTR64((x),41))
			#define sigma0(x) (ROTR64((x),1) ^ ROTR64((x),8) ^ ((x) >> 7))
			#define sigma1(x) (ROTR64((x),19) ^ ROTR64((x),61) ^ ((x) >> 6))
			
			// Prepare the message schedule.
			for (unsigned int i = 0, j = 0; i < 16; i++, j += 8) {
				m[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j+1] << 48) |
					((uint64_t)data[j+2] << 40) | ((uint64_t)data[j+3] << 32) |
					((uint64_t)data[j+4] << 24) | ((uint64_t)data[j+5] << 16) |
					((uint64_t)data[j+6] << 8)  | ((uint64_t)data[j+7]);
			}
			for (unsigned int i = 16; i < 80; i++) {
				m[i] = sigma1(m[i-2]) + m[i-7] + sigma0(m[i-15]) + m[i-16];
			}
	
			uint64_t a = m_state[0];
			uint64_t b = m_state[1];
			uint64_t c = m_state[2];
			uint64_t d = m_state[3];
			uint64_t e = m_state[4];
			uint64_t f = m_state[5];
			uint64_t g = m_state[6];
			uint64_t h = m_state[7];
	
			static const uint64_t k[80] = {
				0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
				0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
				0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
				0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
				0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
				0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
				0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
				0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
				0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
				0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
				0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
				0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
				0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
				0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
				0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
				0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
				0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
				0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
				0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
				0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
				0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
				0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
				0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
				0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
				0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
				0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
				0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
				0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
				0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
				0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
				0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
				0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
				0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
				0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
				0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
				0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
				0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
				0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
				0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
				0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
			};
	
			for (unsigned int i = 0; i < 80; i++) {
				uint64_t t1 = h + SIGMA1(e) + CH(e, f, g) + k[i] + m[i];
				uint64_t t2 = SIGMA0(a) + MAJ(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}
	
			m_state[0] += a;
			m_state[1] += b;
			m_state[2] += c;
			m_state[3] += d;
			m_state[4] += e;
			m_state[5] += f;
			m_state[6] += g;
			m_state[7] += h;
	
			#undef ROTR64
			#undef CH
			#undef MAJ
			#undef SIGMA0
			#undef SIGMA1
			#undef sigma0
			#undef sigma1
		}
	
		// Helper to update the 128-bit length (stored as two 64-bit words).
		void addBitLength(uint64_t bits) {
			m_bitlen[1] += bits;
			if (m_bitlen[1] < bits) {
				m_bitlen[0]++;
			}
		}
	
		unsigned char m_data[BlockSize];
		size_t m_datalen;
		uint64_t m_bitlen[2]; // m_bitlen[0]: high 64 bits, m_bitlen[1]: low 64 bits.
		uint64_t m_state[8];
	};
	
	inline std::string hmac_sha512(const std::string &key, const std::string &data) {
		const size_t blockSize = SHA512::BlockSize;
		std::vector<unsigned char> keyBytes(key.begin(), key.end());
	
		// If key is longer than blockSize, shorten it by hashing.
		if (keyBytes.size() > blockSize) keyBytes = SHA512::hash(key);
		
		// Pad keyBytes with zeros if needed.
		keyBytes.resize(blockSize, 0x00);
	
		// Create inner and outer padded keys.
		std::vector<unsigned char> o_key_pad(blockSize);
		std::vector<unsigned char> i_key_pad(blockSize);
		for (size_t i = 0; i < blockSize; i++) {
			o_key_pad[i] = keyBytes[i] ^ 0x5c;
			i_key_pad[i] = keyBytes[i] ^ 0x36;
		}
	
		// Compute inner hash: SHA512(i_key_pad || data)
		SHA512 innerCtx;
		innerCtx.update(i_key_pad.data(), i_key_pad.size());
		innerCtx.update(reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
		unsigned char innerDigest[SHA512::DigestSize];
		innerCtx.final(innerDigest);
	
		// Compute outer hash: SHA512(o_key_pad || innerDigest)
		SHA512 outerCtx;
		outerCtx.update(o_key_pad.data(), o_key_pad.size());
		outerCtx.update(innerDigest, SHA512::DigestSize);
		unsigned char hmacDigest[SHA512::DigestSize];
		outerCtx.final(hmacDigest);
	
		return SHA512::toHexString(hmacDigest);
	}
}

#endif