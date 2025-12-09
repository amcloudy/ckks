#include "crypto/ckks.hpp"
#include <stdexcept>

namespace ckks {

CKKSContext::CKKSContext(const CKKSParams& p)
    : params_(p),
      rns_(p.N, p.qi)
{
  if (p.N == 0 || (p.N & (p.N - 1)) != 0)
    throw std::invalid_argument("CKKSContext: N must be power of 2");

  if (p.qi.empty())
    throw std::invalid_argument("CKKSContext: modulus chain is empty");

  if ((int)p.qi.size() != p.max_depth + 1)
    throw std::invalid_argument("CKKSContext: qi size != max_depth+1");
}

} // namespace ckks
