#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <cmath>

#include "ckks_lib.hpp"
// #include "crypto/encoder.hpp"
// #include "crypto/encrypt.hpp"
// #include "crypto/decrypt.hpp"
// #include "crypto/evaluator.hpp"
// #include "crypto/plaintext.hpp"
// #include "crypto/ciphertext.hpp"
// #include "crypto/keygen.hpp"

// using namespace ckks;
// using namespace ckks::crypto;

// simple vector comparison
static void check_close(const std::vector<double>& a,
                        const std::vector<double>& b,
                        double tol = 1e-2)
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

// ----------------- ct + ct -----------------

void test_eval_add()
{
    CKKSParams p;

    p.set_poly_degree(8192);
    p.set_depth(3);
    p.set_scale(40);
    p.set_security(core::SecurityLevel::SL128);

    CKKSContext ctx(p);

  Encoder encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 1234);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  std::vector<double> x = {1.0, -2.0, 3.0};
  std::vector<double> y = {0.5, 4.0, -1.0};

  Plaintext px(ctx), py(ctx);
  encoder.encode(x, p.log_scale(), p.depth(), px);
  encoder.encode(y, p.log_scale(), p.depth(), py);

  Ciphertext cx(ctx, 2), cy(ctx, 2);
  encryptor.encrypt(pk, px, cx);
  encryptor.encrypt(pk, py, cy);

  Ciphertext cz(ctx, 2);
  evaluator.add(cx, cy, cz);

  Plaintext pz(ctx);
  decryptor.decrypt(sk, cz, pz);

  std::vector<double> z;
  encoder.decode(pz, z);
  z.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = x[i] + y[i];
  }

  check_close(expected, z, 1e-2);
  std::cout << "[OK] Evaluator add (ct+ct) test passed\n";
}

// ----------------- ct - ct -----------------

void test_eval_sub()
{
  CKKSParams p;

  p.set_poly_degree(8192);
  p.set_depth(3);
  p.set_scale(40);
  p.set_security(core::SecurityLevel::SL128);

  CKKSContext ctx(p);

  Encoder encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 5678);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  std::vector<double> x = {1.0, -2.0, 3.0};
  std::vector<double> y = {0.5, 4.0, -1.0};

  Plaintext px(ctx), py(ctx);
  encoder.encode(x, p.log_scale(), p.depth(), px);
  encoder.encode(y, p.log_scale(), p.depth(), py);

  Ciphertext cx(ctx, 2), cy(ctx, 2);
  encryptor.encrypt(pk, px, cx);
  encryptor.encrypt(pk, py, cy);

  Ciphertext cz(ctx, 2);
  evaluator.sub(cx, cy, cz);

  Plaintext pz(ctx);
  decryptor.decrypt(sk, cz, pz);

  std::vector<double> z;
  encoder.decode(pz, z);
  z.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = x[i] - y[i];
  }

  check_close(expected, z, 1e-2);
  std::cout << "[OK] Evaluator sub (ct-ct) test passed\n";
}

// ----------------- -ct -----------------

void test_eval_neg()
{
  CKKSParams p;

  p.set_poly_degree(8192);
  p.set_depth(3);
  p.set_scale(40);
  p.set_security(core::SecurityLevel::SL128);

  CKKSContext ctx(p);

  Encoder encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 42);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  std::vector<double> x = {1.25, -0.75, 2.5};

  Plaintext px(ctx);
  encoder.encode(x, p.log_scale(), p.depth(), px);

  Ciphertext cx(ctx, 2);
  encryptor.encrypt(pk, px, cx);

  Ciphertext cn(ctx, 2);
  evaluator.negate(cx, cn);

  Plaintext pn(ctx);
  decryptor.decrypt(sk, cn, pn);

  std::vector<double> z;
  encoder.decode(pn, z);
  z.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = -x[i];
  }

  check_close(expected, z, 1e-2);
  std::cout << "[OK] Evaluator negation test passed\n";
}

// ----------------- ct + pt -----------------

void test_eval_add_plain()
{
  CKKSParams p;

  p.set_poly_degree(8192);
  p.set_depth(3);
  p.set_scale(40);
  p.set_security(core::SecurityLevel::SL128);

  CKKSContext ctx(p);

  Encoder encoder(ctx);
  Encryptor encryptor(ctx);
  Decryptor decryptor(ctx);
  Evaluator evaluator(ctx);
  KeyGenerator keygen(ctx, 999);

  SecretKey sk = keygen.generate_secret_key();
  PublicKey pk = keygen.generate_public_key(sk);

  std::vector<double> x = {1.0, 2.0, 3.0};
  std::vector<double> y = {0.5, -1.0, 4.0};

  Plaintext px(ctx), py(ctx);
  encoder.encode(x, p.log_scale(), p.depth(), px);
  encoder.encode(y, p.log_scale(), p.depth(), py);

  Ciphertext cx(ctx, 2);
  encryptor.encrypt(pk, px, cx);

  Ciphertext cz(ctx, 2);
  evaluator.add_plain(cx, py, cz);

  Plaintext pz(ctx);
  decryptor.decrypt(sk, cz, pz);

  std::vector<double> z;
  encoder.decode(pz, z);
  z.resize(x.size());

  std::vector<double> expected(x.size());
  for (std::size_t i = 0; i < x.size(); ++i) {
    expected[i] = x[i] + y[i];
  }

  check_close(expected, z, 1e-2);
  std::cout << "[OK] Evaluator add_plain (ct+pt) test passed\n";
}
