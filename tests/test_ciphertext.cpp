#include "ckks.hpp"
#include "core/params.hpp"
#include "core/paramgen.hpp"
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include <cassert>
#include <iostream>

using namespace ckks;
using namespace ckks::core;
using namespace ckks::crypto;

void test_plaintext_ciphertext_basic()
{
  ChainDesign cd{3, 40, 30};
  auto qi = generate_modulus_chain(8192, SecurityLevel::SL128, cd);

  CKKSParams p(8192, qi, 40, 3);
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
