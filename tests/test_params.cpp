#include <iostream>
#include <vector>
#include <cassert>

#include "core/params.hpp"

using namespace ckks::core;

void test_modulus_chain()
{
  std::size_t N = 8192;
  SecurityLevel sec = SecurityLevel::SL128;

  ChainDesign chain{ .depth = 4, .log_scale = 37, .margin_bits = 30 };

  auto qi = generate_modulus_chain(N, sec, chain);

  for (auto q : qi)
    assert(q % (2 * N) == 1);

  int max_logQ = max_logq_classical_ternary(N, sec);
  int tot = (chain.depth + 1) * chain.log_scale + chain.margin_bits;
  assert(tot <= max_logQ);

  std::cout << "[OK] modulus-chain test passed\n";
}
