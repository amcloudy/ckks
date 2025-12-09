#include <iostream>
#include <vector>
#include <cassert>
#include <cmath>

#include "crypto/ckks.hpp"
#include "crypto/encoder.hpp"
#include "crypto/encrypt.hpp"
#include "crypto/decrypt.hpp"
#include "crypto/evaluator.hpp"
#include "crypto/keygen.hpp"

using namespace ckks;
using namespace ckks::crypto;

static void check_close(const std::vector<double>& a,
                        const std::vector<double>& b,
                        double tol = 3e-1)
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

void test_rescale_metadata()
{
  std::size_t N = 16;
  std::vector<std::uint64_t> qi = {97, 193, 257};
  int log_scale = 20;
  int depth = static_cast<int>(qi.size()) - 1; // 2

  CKKSParams params(N, qi, log_scale, depth);
  CKKSContext ctx(params);

  Encoder   encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 123);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  std::vector<double> v = {1.0, 2.0, 3.0};

  Plaintext pt(ctx);
  encoder.encode(v, params.default_scale, depth, pt); // level = 2

  Ciphertext ct(ctx, 2);
  encryptor.encrypt(pk, pt, ct);

  assert(ct.level == depth);

  Ciphertext ct_res(ctx, 2);
  evaluator.rescale_to_next(ct, ct_res);

  // level must drop by 1
  assert(ct_res.level == ct.level - 1);

  double expected_scale = ct.scale / static_cast<double>(qi.back());
  double rel_err = std::fabs(ct_res.scale - expected_scale) / expected_scale;
  assert(rel_err < 0.2); // rough check

  std::cout << "[OK] rescale_to_next metadata test passed\n";
}

void test_rescale_after_mul()
{
  std::size_t N = 16;
  std::vector<std::uint64_t> qi = {97, 193, 257};
  int log_scale = 20;
  int depth = static_cast<int>(qi.size()) - 1;

  CKKSParams params(N, qi, log_scale, depth);
  CKKSContext ctx(params);

  Encoder   encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 456);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);
  RelinKey  rlk = keygen.generate_relin_key(sk);

  std::vector<double> x = {1.0, 2.0, -0.5};
  std::vector<double> y = {0.5, -1.0, 3.0};

  Plaintext px(ctx), py(ctx);
  encoder.encode(x, params.default_scale, depth, px); // highest level
  encoder.encode(y, params.default_scale, depth, py);

  Ciphertext cx(ctx, 2), cy(ctx, 2);
  encryptor.encrypt(pk, px, cx);
  encryptor.encrypt(pk, py, cy);

  // multiply + relinearize (still at level=2)
  Ciphertext cprod(ctx, 2);
  evaluator.multiply_relinearize(cx, cy, rlk, cprod);

  // then rescale once (drop last prime)
  Ciphertext cprod_res(ctx, 2);
  evaluator.rescale_to_next(cprod, cprod_res);

  Plaintext pm(ctx);
  decryptor.decrypt(sk, cprod_res, pm);

  std::vector<double> decoded;
  encoder.decode(pm, decoded);
  decoded.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = x[i] * y[i];
  }

  check_close(expected, decoded, 3e-1);

  std::cout << "[OK] rescale_after_mul test passed\n";
}