#pragma once

#include "ckks.hpp"
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include "crypto/keys.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

/// CKKS public-key encryption.
/// Implements: c0 = b*u + e1 + m,  c1 = a*u + e2.
class Encryptor {
public:
  explicit Encryptor(const ckks::CKKSContext& ctx)
      : ctx_(&ctx)
  {}

  /// Encrypt plaintext pt into ciphertext ct using public key pk.
  void encrypt(const PublicKey& pk,
               const Plaintext& pt,
               Ciphertext& ct);

private:
  const ckks::CKKSContext* ctx_;
};

} // namespace ckks::crypto
