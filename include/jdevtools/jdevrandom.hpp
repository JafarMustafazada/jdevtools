#ifndef JDEVTOOLS_JDEVRANDOM_HPP
#define JDEVTOOLS_JDEVRANDOM_HPP

#include <random>
#include <string.h>
#include <vector>

namespace jdevtools {
	inline int rando(int end, int start = 1, unsigned seed = 0);
	inline int randi(const int probs[], int size, unsigned seed = 0);
	inline int randi(const std::vector<int> &probs, unsigned seed = 0);


	int rando(int end, int start, unsigned seed) {
		static std::random_device rd;
		static std::mt19937 gen(rd());
		if (seed) gen = std::mt19937(seed);
		std::uniform_int_distribution<> dis(start, end);
		return dis(gen);
	}

	int randi(const int probs[], int size, unsigned seed) {
		if (size < 1) return -1; // input error
		if (size == 1) return 0;

		int temp = 0;
		std::vector<int> prefixSum(size);

		for (int i = 0; i < size; i++) {
			temp += probs[i];
			prefixSum[i] = temp;
		}

		temp = rando(temp, 1, seed);

		// auto it = std::upper_bound(prefixSum.begin(), prefixSum.end(), temp);
		// return std::distance(prefixSum.begin(), it);
		for (int i = 0; i < size; i++) {
			if (temp <= prefixSum[i]) return i;
		}
		return -2; // function error
	}

	int randi(const std::vector<int> &probs, unsigned seed) {
		return randi(probs.data(), probs.size(), seed);
	}
}

#endif