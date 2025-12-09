#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <cmath>

#include "crypto/ckks.hpp"
#include "crypto/encoder.hpp"
#include "crypto/encrypt.hpp"
#include "crypto/decrypt.hpp"
#include "crypto/evaluator.hpp"
#include "crypto/keygen.hpp"
#include "core/poly.hpp"

using namespace ckks;
using namespace ckks::crypto;
using namespace ckks::core;

static void check_close(const std::vector<double>& a,
                        const std::vector<double>& b,
                        double tol = 1e-1)
{
  assert(a.size() == b.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    double d = std::fabs(a[i] - b[i]);
    if (d > tol) {
      std::cerr << "Mismatch at " << i
                << ": " << a[i] << " vs " << b[i]
                << " (diff=" << d << ")\n";
      assert(false);
    }
  }
}

// Manual degree-2 decrypt: m ≈ e0 + e1*s + e2*s^2 (mod Q)
static void manual_decrypt_deg2(const CKKSContext& ctx,
                                const SecretKey& sk,
                                const Ciphertext& ct3,
                                core::PolyRNS& m_poly)
{
  const auto& rns = ctx.rns();
  const auto& qi  = ctx.params().qi;

  std::size_t N = ctx.params().N;
  std::size_t L = rns.num_moduli();

  const PolyRNS& e0 = ct3[0];
  const PolyRNS& e1 = ct3[1];
  const PolyRNS& e2 = ct3[2];
  const PolyRNS& s  = sk.poly;

  // Compute s^2 via NTT
  PolyRNS s_ntt = s;
  poly_to_ntt(s_ntt, rns);
  PolyRNS s2_ntt(N, L);
  poly_pointwise_mul(s2_ntt, s_ntt, s_ntt, rns);
  PolyRNS s2(N, L);
  poly_from_ntt(s2_ntt, rns);

  // e1*s
  PolyRNS e1_ntt = e1;
  poly_to_ntt(e1_ntt, rns);
  PolyRNS e1s_ntt(N, L);
  poly_pointwise_mul(e1s_ntt, e1_ntt, s_ntt, rns);
  PolyRNS e1s(N, L);
  poly_from_ntt(e1s_ntt, rns);

  // e2*s^2
  PolyRNS e2_ntt = e2;
  PolyRNS s2_ntt2 = s2_ntt;
  PolyRNS e2s2_ntt(N, L);
  poly_to_ntt(e2_ntt, rns);
  poly_pointwise_mul(e2s2_ntt, e2_ntt, s2_ntt2, rns);
  PolyRNS e2s2(N, L);
  poly_from_ntt(e2s2_ntt, rns);

  // m = e0 + e1*s + e2*s^2
  m_poly = PolyRNS(N, L);

  // tmp = e0 + e1s
  PolyRNS tmp(N, L);
  poly_add(tmp, e0, e1s, rns);

  // m = tmp + e2s2
  poly_add(m_poly, tmp, e2s2, rns);
}

// ------------------------ Test 1: multiply_raw ------------------------------

void test_multiply_raw()
{
  std::size_t N = 16;
  std::vector<std::uint64_t> qi = {97, 193};
  int log_scale = 20;
  int depth = static_cast<int>(qi.size()) - 1;

  CKKSParams params(N, qi, log_scale, depth);
  CKKSContext ctx(params);

  Encoder encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 111);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  std::vector<double> x = {1.0, 2.0, -0.5};
  std::vector<double> y = {0.5, -1.0, 3.0};

  Plaintext px(ctx), py(ctx);
  encoder.encode(x, params.default_scale, depth, px);
  encoder.encode(y, params.default_scale, depth, py);

  Ciphertext cx(ctx, 2), cy(ctx, 2);
  encryptor.encrypt(pk, px, cx);
  encryptor.encrypt(pk, py, cy);

  Ciphertext cprod(ctx, 3);
  evaluator.multiply_raw(cx, cy, cprod);

  // Manually decrypt degree-2 ciphertext
  PolyRNS m_poly;
  manual_decrypt_deg2(ctx, sk, cprod, m_poly);

  Plaintext pm(ctx);
  pm.poly      = m_poly;
  pm.scale     = cx.scale * cy.scale;
  pm.level     = cx.level;
  pm.num_slots = std::min(px.num_slots, py.num_slots);
  pm.is_ntt    = false;

  std::vector<double> decoded;
  encoder.decode(pm, decoded);
  decoded.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = x[i] * y[i];
  }

  check_close(expected, decoded, 2e-1); // noise larger
  std::cout << "[OK] multiply_raw (no relinearization) test passed\n";
}

// ------------------------ Test 2: multiply_relinearize ----------------------

void test_multiply_relinearize()
{
  std::size_t N = 16;
  std::vector<std::uint64_t> qi = {97, 193};
  int log_scale = 20;
  int depth = static_cast<int>(qi.size()) - 1;

  CKKSParams params(N, qi, log_scale, depth);
  CKKSContext ctx(params);

  Encoder encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 222);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);
  RelinKey  rlk = keygen.generate_relin_key(sk);

  std::vector<double> x = {1.0, 2.0, -0.5};
  std::vector<double> y = {0.5, -1.0, 3.0};

  Plaintext px(ctx), py(ctx);
  encoder.encode(x, params.default_scale, depth, px);
  encoder.encode(y, params.default_scale, depth, py);

  Ciphertext cx(ctx, 2), cy(ctx, 2);
  encryptor.encrypt(pk, px, cx);
  encryptor.encrypt(pk, py, cy);

  Ciphertext cprod(ctx, 2);
  evaluator.multiply_relinearize(cx, cy, rlk, cprod);

  Plaintext pm(ctx);
  decryptor.decrypt(sk, cprod, pm);

  std::vector<double> decoded;
  encoder.decode(pm, decoded);
  decoded.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = x[i] * y[i];
  }

  check_close(expected, decoded, 2e-1);
  std::cout << "[OK] multiply_relinearize test passed\n";
}
