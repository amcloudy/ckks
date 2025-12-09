#pragma once

// ============================================================================
// CKKS Public Umbrella Header
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cmath>

// ---------------------------------------------------------------------------
// 1. Include core headers FIRST (these have no dependencies on crypto types)
// ---------------------------------------------------------------------------
#include "core/rns.hpp"
#include "core/params.hpp"
#include "core/paramgen.hpp"
#include "core/poly.hpp"
#include "core/ntt.hpp"
#include "core/rotation.hpp"
#include "core/keyswitch.hpp"
#include "core/mul_rescale.hpp"
#include "core/bootstrap.hpp"

namespace ckks {

// ---------------------------------------------------------------------------
// 2. Forward declarations of CKKSContext and CKKSParams BEFORE crypto headers
// ---------------------------------------------------------------------------
struct CKKSParams;
class CKKSContext;

} // namespace ckks

// ---------------------------------------------------------------------------
// 3. Now include crypto headers — they depend on forward declarations
// ---------------------------------------------------------------------------
#include "crypto/plaintext.hpp"
#include "crypto/ciphertext.hpp"
#include "crypto/keys.hpp"
#include "crypto/keygen.hpp"
#include "crypto/encoder.hpp"
#include "crypto/encrypt.hpp"
#include "crypto/decrypt.hpp"
#include "crypto/evaluator.hpp"
#include "crypto/eval_add.hpp"
#include "crypto/eval_mul.hpp"
#include "crypto/eval_rescale.hpp"
#include "crypto/eval_rotate.hpp"
#include "crypto/bootstrap_api.hpp"
#include "crypto/serialization.hpp"

namespace ckks {

// ---------------------------------------------------------------------------
// 4. Now define CKKSParams and CKKSContext AFTER all crypto types are known
// ---------------------------------------------------------------------------
struct CKKSParams {
    std::size_t N = 0;
    std::size_t num_slots = 0;

    int log_scale = 0;
    int max_depth = 0;

    double default_scale = 0.0;
    std::vector<std::uint64_t> qi;

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

// ---------------------------------------------------------------------------
// 5. Export CKKS crypto API symbols (optional convenience aliases)
// ---------------------------------------------------------------------------
// These MUST come after crypto headers are included.
using crypto::Plaintext;
using crypto::Ciphertext;

using crypto::SecretKey;
using crypto::PublicKey;
using crypto::RelinKey;
using crypto::GaloisKey;

using crypto::KeyGenerator;

using crypto::Encryptor;
using crypto::Decryptor;

using crypto::Encoder;
using crypto::Evaluator;

} // namespace ckks
