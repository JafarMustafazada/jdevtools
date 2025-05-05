#ifndef JDEVTOOLS_JDEVRANDOM_HPP
#define JDEVTOOLS_JDEVRANDOM_HPP

#include <random>
#include <string.h>
#include <vector>
#include <thread>

namespace jdevtools {
	// + each call generates next random number
	// + each time seed is set it will reset random generator
	// static variables of this function is thread safe bc of `thread_local`
	inline int rando(int end, int start = 1, unsigned seed = 0);

	// return value is index of array. Each value of array `probs` indicates frequency of index
	// + each call generates next random index
	// + each time seed is set it will reset random generator
	inline int randi(const int probs[], int size, unsigned seed = 0);

	// return value is index of array `probs` where each value of array indicates frequency of index
	// + each call generates next random index
	// + each time seed is set it will reset random generator
	inline int randi(const std::vector<int> &probs, unsigned seed = 0);


	int rando(int end, int start, unsigned seed) {
		static thread_local std::random_device rd;
		static thread_local std::mt19937 gen(rd());
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