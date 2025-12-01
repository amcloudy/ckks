#include <iostream>
#include <vector>
#include <cstdint>
#include <random>
#include <cassert>

#include "core/rns.hpp"
#include "core/ntt.hpp"

using namespace ckks::core;

static std::mt19937_64 rng(123456);

std::uint64_t rand_mod(std::uint64_t q) {
  std::uniform_int_distribution<std::uint64_t> dist(0, q - 1);
  return dist(rng);
}

void test_rns_and_ntt_roundtrip() {
  std::size_t N = 8;
  std::uint64_t q = 97;

  std::vector<std::uint64_t> qs{q};
  RNSContext ctx(N, qs);
  const auto& mod = ctx.moduli()[0];

  std::vector<std::uint64_t> a(N);
  for (std::size_t i = 0; i < N; ++i)
    a[i] = rand_mod(q);

  auto b = a;

  ntt_inplace(b.data(), mod, N);
  intt_inplace(b.data(), mod, N);

  for (std::size_t i = 0; i < N; ++i)
    assert(a[i] == b[i]);

  std::cout << "[OK] NTT roundtrip test passed\n";
}
