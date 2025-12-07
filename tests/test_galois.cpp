#include <iostream>
#include <vector>
#include <cassert>
#include <cmath>

#include "ckks.hpp"
#include "crypto/encoder.hpp"
#include "crypto/encrypt.hpp"
#include "crypto/decrypt.hpp"
#include "crypto/evaluator.hpp"
#include "crypto/keygen.hpp"

using namespace ckks;
using namespace ckks::crypto;

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

void test_conjugation_galois()
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
  KeyGenerator keygen(ctx, 777);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  // Conjugation key (X -> X^{-1})
  GaloisKey gk_conj = keygen.generate_conjugation_key(sk);

  // purely real slots
  std::vector<double> v = {1.0, -2.5, 0.75};

  Plaintext pt(ctx);
  encoder.encode(v, params.default_scale, depth, pt);

  Ciphertext ct(ctx, 2);
  encryptor.encrypt(pk, pt, ct);

  Ciphertext ct_conj(ctx, 2);
  evaluator.apply_galois(ct, gk_conj, ct_conj);

  Plaintext pt_conj(ctx);
  decryptor.decrypt(sk, ct_conj, pt_conj);

  std::vector<double> v2;
  encoder.decode(pt_conj, v2);
  v2.resize(v.size());

  check_close(v, v2, 2e-1);

  std::cout << "[OK] Galois conjugation test passed\n";
}