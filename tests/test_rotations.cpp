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
                        double tol = 2e-1)
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

// left rotation by step: new[i] = v[(i + step) mod m]
static std::vector<double> rotate_left_plain(const std::vector<double>& v,
                                             int step)
{
  std::size_t m = v.size();
  std::vector<double> out(m);
  step %= static_cast<int>(m);
  if (step < 0) step += static_cast<int>(m);

  for (std::size_t i = 0; i < m; ++i) {
    out[i] = v[(i + step) % m];
  }
  return out;
}

void test_single_step_rotation()
{
  std::size_t N = 16;
  std::vector<std::uint64_t> qi = { 97, 193, 257 };
  int log_scale = 20;
  int depth = static_cast<int>(qi.size()) - 1;

  CKKSParams params(N, qi, log_scale, depth);
  CKKSContext ctx(params);

  Encoder   encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 10101);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  // rotation key for step = 1 (left 1)
  GaloisKey rk1 = keygen.generate_rotation_key(sk, 1);

  std::vector<double> v = {1.0, 2.0, 3.0, 4.0};
  auto expected = rotate_left_plain(v, 1);

  Plaintext pt(ctx);
  encoder.encode(v, params.default_scale, depth, pt);

  Ciphertext ct(ctx, 2);
  encryptor.encrypt(pk, pt, ct);

  Ciphertext ct_rot(ctx, 2);
  evaluator.rotate(ct, rk1, ct_rot);

  Plaintext pt_rot(ctx);
  decryptor.decrypt(sk, ct_rot, pt_rot);

  std::vector<double> decoded;
  encoder.decode(pt_rot, decoded);
  decoded.resize(v.size());

  check_close(expected, decoded, 2e-1);
  std::cout << "[OK] single-step rotation test passed\n";
}

void test_multi_step_rotation()
{
  std::size_t N = 16;
  std::vector<std::uint64_t> qi = { 97, 193, 257 };
  int log_scale = 20;
  int depth = static_cast<int>(qi.size()) - 1;

  CKKSParams params(N, qi, log_scale, depth);
  CKKSContext ctx(params);

  Encoder   encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 20202);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  // rotation key for step = 2 (left 2)
  GaloisKey rk2 = keygen.generate_rotation_key(sk, 2);

  std::vector<double> v = {10.0, -1.5, 0.25, 7.75};
  auto expected = rotate_left_plain(v, 2);

  Plaintext pt(ctx);
  encoder.encode(v, params.default_scale, depth, pt);

  Ciphertext ct(ctx, 2);
  encryptor.encrypt(pk, pt, ct);

  Ciphertext ct_rot(ctx, 2);
  evaluator.rotate(ct, rk2, ct_rot);

  Plaintext pt_rot(ctx);
  decryptor.decrypt(sk, ct_rot, pt_rot);

  std::vector<double> decoded;
  encoder.decode(pt_rot, decoded);
  decoded.resize(v.size());

  check_close(expected, decoded, 2e-1);
  std::cout << "[OK] multi-step rotation test passed\n";
}
