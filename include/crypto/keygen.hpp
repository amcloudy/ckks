#pragma once

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "ckks.hpp"
#include "crypto/keys.hpp"

namespace ckks::crypto {

/// KeyGenerator:
///  - owns RNG
///  - generates secret/public/relin/galois keys at top level
class KeyGenerator {
public:
  /// Construct with context and optional seed.
  explicit KeyGenerator(const ckks::CKKSContext& ctx,
                        std::uint64_t seed = 0);

  /// Get the context.
  const ckks::CKKSContext& context() const noexcept { return *ctx_; }

  /// Generate a fresh secret key s(x) with small coefficients.
  SecretKey generate_secret_key();

  /// Generate a fresh public key (a, b) for a given secret key.
  ///
  /// b = -a*s + e   (mod Q)
  ///
  /// where:
  ///  - a is uniform in R_q
  ///  - e is small error
  PublicKey generate_public_key(const SecretKey& sk);

  /// Generate a (simple) relinearization key for s^2.
  ///
  /// This produces a key that allows switching from ciphertext encrypted
  /// under s^2 back to s.
  ///
  /// The exact KS scheme is simplified for now; it will be upgraded to
  /// hybrid key-switching in Phase 6 without changing the outer API.
  RelinKey generate_relin_key(const SecretKey& sk);

  /// Generate Galois/rotation keys for a list of rotation steps.
  ///
  /// `steps` are logical slot-rotation amounts (e.g. +1, -1, +k).
  /// We internally map them to Galois elements and generate a key for each.
  // GaloisKeys generate_galois_keys(const SecretKey& sk,
  //                                 const std::vector<int>& steps);

    // Generate Galois key for automorphism X -> X^{galois_elt} (mod 2N).
  GaloisKey generate_galois_key(const SecretKey& sk,
                                int galois_elt) const;

  // Convenience: conjugation key (X -> X^{-1}) = galois_elt = 2N-1.
  GaloisKey generate_conjugation_key(const SecretKey& sk) const;

  // Generate rotation key for "rotate by step slots" (left rotation).
  // step can be positive; we reduce it modulo num_slots.
  GaloisKey generate_rotation_key(const SecretKey& sk,
                                  int step) const;


private:
  const ckks::CKKSContext* ctx_;
  mutable std::mt19937_64          rng_;

  // ===== Sampling primitives =====

  /// Sample secret key coefficients in {-1, 0, 1}, at top level.
  void sample_secret_ternary(core::PolyRNS& out);

  /// Sample small error polynomial:
  ///  - may start as centered discrete Gaussian or small uniform.
  ///  - parameterized by a standard deviation sigma.
  void sample_error(core::PolyRNS& out, double sigma) const;

  /// Sample a uniform polynomial modulo Q at top level.
  /// Uses all moduli in ctx_->params().qi.
  void sample_uniform(core::PolyRNS& out) const;

  /// Helper: ensure 'out' is sized as (N, L) at top level.
  void resize_poly_top(core::PolyRNS& out) const;
};

} // namespace ckks::crypto
