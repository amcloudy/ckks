// #pragma once

// #include <cstddef>
// #include <cstdint>
// #include <vector>
// #include <cmath>

// #include "core/rns.hpp"
// #include "core/params.hpp"

// namespace ckks {

// /// High-level CKKS parameter container.
// struct CKKSParams {
//   std::size_t N = 0;
//   std::size_t num_slots = 0;

//   int log_scale = 0;
//   int max_depth = 0;

//   double default_scale = 0.0;

//   std::vector<std::uint64_t> qi;   // modulus chain

//   CKKSParams() = default;

//   CKKSParams(std::size_t N,
//              const std::vector<std::uint64_t>& qi,
//              int log_scale,
//              int depth)
//       : N(N),
//         num_slots(N / 2),
//         log_scale(log_scale),
//         max_depth(depth),
//         default_scale(std::pow(2.0, log_scale)),
//         qi(qi)
//   {}
// };


// /// CKKS global context = (params + RNSContext)
// class CKKSContext {
// public:
//   CKKSContext() = default;
//   explicit CKKSContext(const CKKSParams& p);

//   const CKKSParams& params() const noexcept { return params_; }
//   const core::RNSContext& rns() const noexcept { return rns_; }

//   std::size_t N() const noexcept { return params_.N; }
//   std::size_t slots() const noexcept { return params_.num_slots; }

// private:
//   CKKSParams params_;
//   core::RNSContext rns_;
// };

// } // namespace ckks

#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include <cmath>

#include "core/params.hpp"
#include "core/rns.hpp"

namespace ckks {

/**
 * CKKSParams:
 * - A lightweight user-facing parameter container.
 * - User sets high-level parameters (N, depth, scale, security).
 * - CKKSContext fills in: modulus chain qi[], default_scale.
 */
class CKKSParams {
public:
    CKKSParams() = default;

    // -----------------------
    // User-facing setters
    // -----------------------
    void set_poly_degree(std::size_t n) {
        N_ = n;
        slots_ = n / 2;
    }

    void set_depth(int d) { depth_ = d; }
    void set_scale(int log_scale) { log_scale_ = log_scale; }
    void set_security(core::SecurityLevel s) { sec_ = s; }

    // -----------------------
    // Getters
    // -----------------------
    std::size_t N() const noexcept { return N_; }
    std::size_t slots() const noexcept { return slots_; }
    int depth() const noexcept { return depth_; }
    int log_scale() const noexcept { return log_scale_; }
    core::SecurityLevel security() const noexcept { return sec_; }

    const std::vector<std::uint64_t>& qi() const noexcept { return qi_; }
    double default_scale() const noexcept { return default_scale_; }

private:
    // CKKSContext needs access to fill qi_ and default_scale_
    friend class CKKSContext;

    // User-configured parameters
    std::size_t N_ = 0;
    std::size_t slots_ = 0;
    int depth_ = 0;
    int log_scale_ = 0;
    core::SecurityLevel sec_ = core::SecurityLevel::SL128;

    // Values computed automatically inside CKKSContext
    std::vector<std::uint64_t> qi_;
    double default_scale_ = 0.0;
};


/**
 * CKKSContext:
 * - Finalized homomorphic encryption context.
 * - Takes CKKSParams, auto-builds modulus chain & RNSContext.
 * - Provides validated, ready-to-use parameters.
 */
class CKKSContext {
public:
    CKKSContext() = default;
    explicit CKKSContext(const CKKSParams& user);

    const CKKSParams& params() const noexcept { return params_; }
    const core::RNSContext& rns() const noexcept { return rns_; }

    std::size_t N() const noexcept { return params_.N(); }
    std::size_t slots() const noexcept { return params_.slots(); }

private:
    CKKSParams params_;       // finalized parameters (with qi + default_scale)
    core::RNSContext rns_;    // built from params_.qi()
};

} // namespace ckks
