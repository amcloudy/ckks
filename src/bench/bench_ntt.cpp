#include <iostream>
#include <vector>
#include <chrono>
#include <random>

#include "core/rns.hpp"
#include "core/ntt.hpp"

using namespace ckks::core;

int main() {
  std::size_t N = 1 << 12; // 4096
  // q should be prime and q ≡ 1 (mod 2N).
  // For real benchmarks, you'll pick a proper 60-bit NTT prime.
  std::uint64_t q = 18446744069414584321ULL; // 2^64 - 2^32 + 1, NTT-friendly

  std::vector<std::uint64_t> qs{q};
  RNSContext ctx(N, qs);
  const auto& mod = ctx.moduli()[0];

  std::vector<std::uint64_t> a(N);
  std::mt19937_64 rng(42);
  std::uniform_int_distribution<std::uint64_t> dist(0, q - 1);
  for (std::size_t i = 0; i < N; ++i) {
    a[i] = dist(rng);
  }

  auto start = std::chrono::high_resolution_clock::now();
  ntt_inplace(a.data(), mod, N);
  auto mid = std::chrono::high_resolution_clock::now();
  intt_inplace(a.data(), mod, N);
  auto end = std::chrono::high_resolution_clock::now();

  auto dt_ntt = std::chrono::duration<double, std::micro>(mid - start).count();
  auto dt_intt = std::chrono::duration<double, std::micro>(end - mid).count();

  std::cout << "N = " << N << "\n";
  std::cout << "NTT time:  " << dt_ntt << " us\n";
  std::cout << "INTT time: " << dt_intt << " us\n";

  return 0;
}
