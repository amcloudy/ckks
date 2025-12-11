#include "crypto/ckks.hpp"
#include "core/params.hpp"
#include <cassert>
#include <iostream>

using namespace ckks;
using namespace ckks::core;

void test_ckks_params()
{
  CKKSParams p;

  p.set_poly_degree(8192);
  p.set_depth(3);
  p.set_scale(40);
  p.set_security(core::SecurityLevel::SL128);

  CKKSContext ctx(p);

  assert(ctx.N() == 8192);
  assert(ctx.slots() == 4096);
  assert(p.qi().size() == 4); // depth=3 → 4 moduli

  std::cout << "[OK] CKKS params/context test passed\n";
}
