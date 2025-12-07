#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ckks.hpp"
#include "core/poly.hpp"

namespace ckks::crypto {

/// Secret key: a small polynomial s(x) in R_q
/// - coefficients small (e.g., in {-1,0,1} or small Gaussian)
/// - stored at top level with all moduli active
struct SecretKey {
  core::PolyRNS poly;   // s(x)
  int           level;  // usually top-level index (L-1)
  bool          is_ntt; // normally false

  SecretKey() : level(0), is_ntt(false) {}

  explicit SecretKey(const ckks::CKKSContext& ctx);
};

/// Public key: (a(x), b(x)) with
///   a <- uniform
///   e <- small error
///   b = -a*s + e  (mod Q)
/// Encryption then uses m + Δ * u * pk, etc.
struct PublicKey {
  core::PolyRNS a;
  core::PolyRNS b;
  int           level;   // top level
  bool          is_ntt;  // typically false here for now

  PublicKey() : level(0), is_ntt(false) {}

  explicit PublicKey(const ckks::CKKSContext& ctx);
};

/// Relinearization key:
///  - For now we design the "standard" relinearization key of size 2,
///    suitable for squaring (ct^2).
///  - Later we extend for larger powers and hybrid key-switching.
///  - Conceptually holds arrays of (a_i(x), b_i(x)).
struct RelinKey {
  // For now: one "stage" for s^2, with two polys (a, b)
  // Later this can become vector<vector<PolyRNS>> for decomposition.
  core::PolyRNS a;
  core::PolyRNS b;
  int           level;
  bool          is_ntt;

  RelinKey() : level(0), is_ntt(false) {}

  explicit RelinKey(const ckks::CKKSContext& ctx);
};

/// Galois / rotation key:
///  - Each rotation (or Galois element) has its own switching key (a,b).
///  - We'll store a small struct for each and a container on top.
///  - Actual hybrid switching logic will be Phase 6.
// struct GaloisKeyElement {
//   int           galois_elt; // e.g. element of Gal(R) corresponding to rotation
//   core::PolyRNS a;
//   core::PolyRNS b;
//   int           level;
//   bool          is_ntt;

//   GaloisKeyElement() : galois_elt(0), level(0), is_ntt(false) {}
// };

struct GaloisKey {
  core::PolyRNS a;
  core::PolyRNS b;
  int           galois_elt = 1;  ///< X -> X^{galois_elt} (mod 2N), must be odd
  int           level      = 0;
  bool          is_ntt     = false;

  GaloisKey() = default;

  explicit GaloisKey(const ckks::CKKSContext& ctx,
                     int galois_elt = 1);
};


} // namespace ckks::crypto
