#pragma once

#include <cstdint>
#include <vector>
#include "core/rns.hpp"

namespace ckks::core {

/// Compute twiddle tables for forward & inverse NTT
void compute_twiddle_tables(
    std::uint64_t q,
    std::uint64_t root,
    std::uint64_t root_inv,
    std::size_t N,
    std::vector<std::uint64_t>& tw,
    std::vector<std::uint64_t>& tw_inv);

/// In-place forward NTT
void ntt_inplace(std::uint64_t* a,
                 const RNSModulus& mod,
                 std::size_t N);

/// In-place inverse NTT
void intt_inplace(std::uint64_t* a,
                  const RNSModulus& mod,
                  std::size_t N);

} // namespace ckks::core
