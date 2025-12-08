#pragma once

// ============================================================================
// CKKS Public Umbrella Header
// Users include <ckks.hpp> to access the entire CKKS API.
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cmath>

// ============================================================================
// 1. CORE HEADERS (always safe: no dependency on crypto)
// ============================================================================
#include "core/rns.hpp"
#include "core/params.hpp"
#include "core/paramgen.hpp"
#include "core/poly.hpp"
#include "core/ntt.hpp"
#include "core/rotation.hpp"

namespace ckks {

// ============================================================================
// 2. CKKSParams & CKKSContext (MUST appear BEFORE crypto headers)
// ============================================================================

/// High-level CKKS parameter container.
struct CKKSParams {
    std::size_t N = 0;
    std::size_t num_slots = 0;

    int log_scale = 0;
    int max_depth = 0;

    double default_scale = 0.0;

    std::vector<std::uint64_t> qi;  // modulus chain

    CKKSParams() = default;

    CKKSParams(std::size_t N,
               const std::vector<std::uint64_t>& qi,
               int log_scale,
               int depth)
        : N(N),
          num_slots(N / 2),
          log_scale(log_scale),
          max_depth(depth),
          default_scale(std::pow(2.0, log_scale)),
          qi(qi)
    {}
};

/// CKKS global context = (params + RNSContext)
class CKKSContext {
public:
    CKKSContext() = default;
    explicit CKKSContext(const CKKSParams& p);

    const CKKSParams& params() const noexcept { return params_; }
    const core::RNSContext& rns() const noexcept { return rns_; }

    std::size_t N() const noexcept { return params_.N; }
    std::size_t slots() const noexcept { return params_.num_slots; }

private:
    CKKSParams params_;
    core::RNSContext rns_;
};

} // namespace ckks


// ============================================================================
// 3. CRYPTO API HEADERS (must appear AFTER CKKSContext is defined)
// ============================================================================
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include "crypto/keys.hpp"
#include "crypto/keygen.hpp"
#include "crypto/encoder.hpp"
#include "crypto/encrypt.hpp"
#include "crypto/decrypt.hpp"
#include "crypto/evaluator.hpp"

// evaluator components
#include "crypto/eval_add.hpp"
#include "crypto/eval_mul.hpp"
#include "crypto/eval_rescale.hpp"
#include "crypto/eval_rotate.hpp"

// bootstrap (stub placeholder for now)
#include "crypto/bootstrap_api.hpp"

// serialization (optional but public)
#include "crypto/serialization.hpp"
