#include "crypto/ckks.hpp"
#include "core/params.hpp"
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include <cassert>
#include <iostream>

using namespace ckks;
using namespace ckks::core;
using namespace ckks::crypto;

void test_plaintext_ciphertext_basic()
{
  CKKSParams p;

  p.set_poly_degree(8192);
  p.set_depth(3);
  p.set_scale(40);
  p.set_security(core::SecurityLevel::SL128);

  CKKSContext ctx(p);

  Plaintext pt(ctx);
  assert(!pt.empty());
  assert(pt.N() == 8192);
  assert(pt.num_slots == 4096);
  assert(pt.level >= 0);

  Ciphertext ct(ctx, 2);
  assert(ct.size() == 2);
  assert(ct.is_valid(ctx));
  assert(ct.num_slots == 4096);

  ct.resize_like(ctx, 3);
  assert(ct.size() == 3);
  assert(ct.is_valid(ctx));

  std::cout << "[OK] Plaintext/Ciphertext basic tests passed\n";
}
