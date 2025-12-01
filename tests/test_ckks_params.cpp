#include "ckks.hpp"
#include "core/params.hpp"
#include "core/paramgen.hpp"
#include <cassert>
#include <iostream>

using namespace ckks;
using namespace ckks::core;

void test_ckks_params()
{
  ChainDesign cd{3, 40, 30};
  auto qi = generate_modulus_chain(8192, SecurityLevel::SL128, cd);

  CKKSParams p(8192, qi, 40, 3);
  CKKSContext ctx(p);

  assert(ctx.N() == 8192);
  assert(ctx.slots() == 4096);
  assert(p.qi.size() == 4); // depth=3 → 4 moduli

  std::cout << "[OK] CKKS params/context test passed\n";
}
