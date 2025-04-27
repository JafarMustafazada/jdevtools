#ifndef JDEVTOOLS_JDEVSTRING_HPP
#define JDEVTOOLS_JDEVSTRING_HPP

#include <string>
#include <unordered_map>
#include <vector>

namespace jdevtools {
	typedef unsigned char BYTE;
	inline const char BASE64_URL_ALPHABET[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789-_"
	;

	inline std::string strTokenize(const std::string &str, const char *delim, size_t &prev);
	inline std::vector<std::string> split(const std::string &str, const char *delimiter);

	inline std::string base64urlEncode(const std::vector<BYTE> &data);
	inline std::string base64urlEncode(const std::string &input);
	inline std::string base64urlDecode(const std::string &input);

	inline std::string createJWT(const char *secret, const char *payload,
	const char *header, std::string (&hmac_sha)(const char *, const char *));
	inline std::string createJWT(const std::string &secret, const std::string &payload,
	const std::string &header, std::string (&hmac_sha2)(const std::string &, const std::string &));
	inline std::string createJWT(const std::string &secret, const std::string &payload);


	std::string strTokenize(const std::string &str, const char *delim, size_t &prev) {
		size_t pos = str.find(delim, prev), temp = prev;
		if (pos == std::string::npos) pos = str.length();
		prev = pos + strlen(delim);
		return str.substr(temp, pos - temp);
	}

	std::vector<std::string> split(const std::string &str, const char *delim) {
		std::vector<std::string> tokens;
		size_t prev = 0, pos;

		while (prev < str.length()) {
			pos = str.find(delim, prev);
			if (pos == std::string::npos) pos = str.length();
			tokens.push_back(str.substr(prev, pos - prev));
			prev = pos + strlen(delim);
		}

		return tokens;
	}

	std::string base64urlEncode(const std::vector<BYTE> &data) {
		std::string encoded;
		int val = 0, valb = -6;
		for (BYTE c : data) {
			val = (val << 8) + c;
			valb += 8;
			while (valb >= 0) {
				encoded.push_back(BASE64_URL_ALPHABET[(val >> valb) & 0x3F]);
				valb -= 6;
			}
		}
		return encoded;
	}

	std::string base64urlEncode(const std::string &input) {
		std::string encoded;
		int val = 0, valb = -6;

		for (BYTE c : input) {
			val = (val << 8) | c;
			valb += 8;
			while (valb >= 0) {
				encoded.push_back(BASE64_URL_ALPHABET[(val >> valb) & 0x3F]);
				valb -= 6;
			}
		}

		if (valb > -6) {
			encoded.push_back(BASE64_URL_ALPHABET[((val << 8) >> (valb + 8)) & 0x3F]);
		}

		return encoded; // No padding per RFC 4648
	}

	std::string base64urlDecode(const std::string &input) {
		std::vector<int> T(256, -1);

		for (size_t i = 0; i < std::strlen(BASE64_URL_ALPHABET); i++) {
			T[BASE64_URL_ALPHABET[i]] = i;
		}

		std::string decoded;
		int val = 0, valb = -8;

		for (BYTE c : input) {
			if (T[c] == -1) break; // Ignore invalid characters
			val = (val << 6) | T[c];
			valb += 6;
			if (valb >= 0) {
				decoded.push_back(char((val >> valb) & 0xFF));
				valb -= 8;
			}
		}

		return decoded;
	}

	// class jdevjson {
	// public:
	//     class jsonode {
	//         bool isarray = false;
	//         bool isnumber = false;
	//     };
	// private:
	//     std::unordered_map<std::std::string, jsonode> raw;
	// };

	std::string createJWT(const char *secret, const char *payload, const char *header,
	std::string (&hmac_sha)(const char *, const char *)) {
		std::string encodedHeader = base64urlEncode(header);
		std::string encodedPayload = base64urlEncode(payload);
		std::string message = encodedHeader + "." + encodedPayload;
		std::string signature = hmac_sha(secret, message.data());
		return message + "." + signature;
	}

	std::string createJWT(const std::string &secret, const std::string &payload,
	const std::string &header, std::string (&signature_encode)(const std::string &, const std::string &)) {
		std::string encodedHeader = base64urlEncode(header);
		std::string encodedPayload = base64urlEncode(payload);
		std::string message = encodedHeader + "." + encodedPayload;
		std::string encodedSignature = signature_encode(secret, message);
		return message + "." + encodedSignature;
	}

	#ifdef JDEVTOOLS_SHA256HMAC_HPP
	#include "jdevtools/sha256hmac.hpp"
	std::string createJWT(const std::string &secret, const std::string &payload) {
		std::string header = R"({"alg":"HS256","typ":"JWT"})";
		return createJWT(secret.data(), payload.data(), header.data(), jdevtools::hmac_sha256);
	}
	#endif
}

#endif