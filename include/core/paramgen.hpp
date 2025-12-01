#pragma once

#include "core/rns.hpp"
#include "core/params.hpp"

namespace ckks::core {

/// High-level utility to generate RNSContext
/// from security level + chain design.
RNSContext make_rns_context(std::size_t N,
                            SecurityLevel sec,
                            const ChainDesign& d);

} // namespace ckks::core
