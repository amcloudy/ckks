#include "crypto/ckks.hpp"
#include <cmath>

namespace ckks {

CKKSContext::CKKSContext(const CKKSParams& user)
    : params_(user)
{
    // 1. Construct chain design
    core::ChainDesign d{
        params_.depth(),
        params_.log_scale(),
        20  // margin bits
    };

    // 2. Generate modulus chain and write INSIDE params_
    params_.qi_ = core::generate_modulus_chain(
        params_.N(),
        params_.security(),
        d
    );

    // 3. Set default scale
    params_.default_scale_ = std::pow(2.0, params_.log_scale());

    // 4. Build RNS context
    rns_ = core::RNSContext(params_.N(), params_.qi_);
}

} // namespace ckks
