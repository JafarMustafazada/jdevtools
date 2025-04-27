#ifndef JDEVTOOLS_SHA256HMAC_HPP
#define JDEVTOOLS_SHA256HMAC_HPP

#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>

namespace jdevtools {
	class SHA256 {
	public:
		static const size_t BlockSize = 64;   // 512 bits
		static const size_t DigestSize = 32;  // 256 bits
	
		SHA256() { init(); }
	
		// Process input data in chunks.
		void update(const unsigned char* data, size_t len) {
			for (size_t i = 0; i < len; i++) {
				m_data[m_datalen] = data[i];
				m_datalen++;
				if (m_datalen == BlockSize) {
					transform(m_data);
					m_bitlen += 512;
					m_datalen = 0;
				}
			}
		}
	
		// Finalize the hash and produce the digest.
		void final(unsigned char hash[DigestSize]) {
			size_t i = m_datalen;
	
			// Pad whatever data is left in the buffer.
			if (m_datalen < 56) {
				m_data[i++] = 0x80;
				while (i < 56)
					m_data[i++] = 0x00;
			} else {
				m_data[i++] = 0x80;
				while (i < BlockSize)
					m_data[i++] = 0x00;
				transform(m_data);
				memset(m_data, 0, 56);
			}
	
			// Append to the padding the total message's length in bits as a 64-bit big-endian integer.
			m_bitlen += m_datalen * 8;
			// Write m_bitlen as big-endian into the last 8 bytes.
			for (int j = 0; j < 8; ++j) {
				m_data[63 - j] = (m_bitlen >> (j * 8)) & 0xff;
			}
			transform(m_data);
	
			// Convert state to big-endian output.
			for (int i = 0; i < 4; i++) {
				hash[i]      = (m_state[0] >> (24 - i * 8)) & 0xff;
				hash[i + 4]  = (m_state[1] >> (24 - i * 8)) & 0xff;
				hash[i + 8]  = (m_state[2] >> (24 - i * 8)) & 0xff;
				hash[i + 12] = (m_state[3] >> (24 - i * 8)) & 0xff;
				hash[i + 16] = (m_state[4] >> (24 - i * 8)) & 0xff;
				hash[i + 20] = (m_state[5] >> (24 - i * 8)) & 0xff;
				hash[i + 24] = (m_state[6] >> (24 - i * 8)) & 0xff;
				hash[i + 28] = (m_state[7] >> (24 - i * 8)) & 0xff;
			}
		}
	
		// Utility: compute SHA256 of a string.
		static std::vector<unsigned char> hash(const std::string &input) {
			SHA256 ctx;
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
		void init() {
			m_datalen = 0;
			m_bitlen = 0;
			// Initialize state (first 32 bits of the fractional parts of the square roots of the first 8 primes)
			m_state[0] = 0x6a09e667;
			m_state[1] = 0xbb67ae85;
			m_state[2] = 0x3c6ef372;
			m_state[3] = 0xa54ff53a;
			m_state[4] = 0x510e527f;
			m_state[5] = 0x9b05688c;
			m_state[6] = 0x1f83d9ab;
			m_state[7] = 0x5be0cd19;
		}
	
		void transform(const unsigned char data[]) {
			// Macros for bit operations.
			#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
			#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
			#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
			#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
			#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
			#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
			#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
			#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
	
			uint32_t m[64];
			uint32_t a, b, c, d, e, f, g, h;
			// Initialize message schedule array.
			for (unsigned int i = 0, j = 0; i < 16; i++, j += 4) {
				m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
			}
			for (unsigned int i = 16; i < 64; i++) {
				m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
			}
	
			// Initialize working variables with current state.
			a = m_state[0];
			b = m_state[1];
			c = m_state[2];
			d = m_state[3];
			e = m_state[4];
			f = m_state[5];
			g = m_state[6];
			h = m_state[7];
	
			static const uint32_t k[64] = {
				0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
				0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
				0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
				0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
				0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
				0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
				0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
				0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
				0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
				0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
				0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
				0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
				0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
				0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
				0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
				0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
			};
	
			for (unsigned int i = 0; i < 64; i++) {
				uint32_t t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
				uint32_t t2 = EP0(a) + MAJ(a, b, c);
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
	
			#undef ROTLEFT
			#undef ROTRIGHT
			#undef CH
			#undef MAJ
			#undef EP0
			#undef EP1
			#undef SIG0
			#undef SIG1
		}
	
		unsigned char m_data[BlockSize];
		uint32_t m_datalen;
		uint64_t m_bitlen;
		uint32_t m_state[8];
	};
	
	inline std::string hmac_sha256(const std::string &key, const std::string &data) {
		const size_t blockSize = SHA256::BlockSize;
		std::vector<unsigned char> keyBytes(key.begin(), key.end());
	
		// If key is longer than blockSize, shorten it by hashing.
		if (keyBytes.size() > blockSize) keyBytes = SHA256::hash(key);
		
		// Pad keyBytes with zeros if needed.
		keyBytes.resize(blockSize, 0x00);
	
		// Create inner and outer padded keys.
		std::vector<unsigned char> o_key_pad(blockSize);
		std::vector<unsigned char> i_key_pad(blockSize);
		for (size_t i = 0; i < blockSize; i++) {
			o_key_pad[i] = keyBytes[i] ^ 0x5c;
			i_key_pad[i] = keyBytes[i] ^ 0x36;
		}
	
		// Compute inner hash: hash(i_key_pad || data)
		SHA256 innerCtx;
		innerCtx.update(i_key_pad.data(), i_key_pad.size());
		innerCtx.update(reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
		unsigned char innerDigest[SHA256::DigestSize];
		innerCtx.final(innerDigest);
	
		// Compute outer hash: hash(o_key_pad || innerDigest)
		SHA256 outerCtx;
		outerCtx.update(o_key_pad.data(), o_key_pad.size());
		outerCtx.update(innerDigest, SHA256::DigestSize);
		unsigned char hmacDigest[SHA256::DigestSize];
		outerCtx.final(hmacDigest);
	
		return SHA256::toHexString(hmacDigest);
	}
}

#endif