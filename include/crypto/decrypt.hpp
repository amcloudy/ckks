#pragma once

#include "ckks.hpp"
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include "crypto/keys.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

/// CKKS decryption: m = c0 + c1*s (mod Q)
class Decryptor {
public:
  explicit Decryptor(const ckks::CKKSContext& ctx)
      : ctx_(&ctx)
  {}

  /// Decrypt ciphertext ct into plaintext pt_out using secret key sk.
  void decrypt(const SecretKey& sk,
               const Ciphertext& ct,
               Plaintext& pt_out);

private:
  const ckks::CKKSContext* ctx_;
};

} // namespace ckks::crypto
