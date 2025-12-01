#include "core/paramgen.hpp"
#include <iostream>
#include <cassert>

using namespace ckks::core;

void test_paramgen() {
  ChainDesign chain{4, 37, 30};
  RNSContext cc = make_rns_context(8192, SecurityLevel::SL128, chain);

  assert(cc.degree() == 8192);
  assert(cc.num_moduli() == static_cast<std::size_t>(chain.depth + 1));

  std::cout << "[OK] paramgen test passed\n";
}

