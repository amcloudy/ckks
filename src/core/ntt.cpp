#include "core/ntt.hpp"
#include <stdexcept>

namespace ckks::core {

// ====================== twiddle table generator ====================== //

void compute_twiddle_tables(
    std::uint64_t q,
    std::uint64_t root,
    std::uint64_t root_inv,
    std::size_t N,
    std::vector<std::uint64_t>& tw,
    std::vector<std::uint64_t>& tw_inv)
{
    if (tw.size() != N || tw_inv.size() != N)
        throw std::runtime_error("twiddle tables not sized correctly");

    auto modexp = [&](std::uint64_t base, std::uint64_t exp) {
        __uint128_t r = 1, b = base;
        while (exp) {
            if (exp & 1)
                r = (r * b) % q;
            b = (b * b) % q;
            exp >>= 1;
        }
        return (std::uint64_t)r;
    };

    // log2(N)
    std::size_t logN = 0;
    while ((1ULL << logN) < N) logN++;

    // fill tables: index uses bit-reversed exponent
    for (std::size_t i = 0; i < N; ++i) {
        std::size_t rev = 0;
        for (std::size_t b = 0; b < logN; ++b) {
            if (i & (1ULL << b))
                rev |= (1ULL << (logN - 1 - b));
        }

        tw[i]     = modexp(root,     rev);
        tw_inv[i] = modexp(root_inv, rev);
    }
}

// ====================== forward NTT ====================== //

void ntt_inplace(std::uint64_t* a,
                 const RNSModulus& mod,
                 std::size_t N)
{
    const std::uint64_t q = mod.q;
    const auto& W = mod.twiddle;

    for (std::size_t len = 1; len < N; len <<= 1) {
        std::size_t step = N / (len << 1);

        for (std::size_t start = 0; start < len; ++start) {
            std::uint64_t w = W[start * step];

            for (std::size_t j = start; j < N; j += (len << 1)) {
                std::uint64_t u = a[j];
                std::uint64_t v = (__uint128_t)a[j + len] * w % q;

                std::uint64_t t = u + v;
                if (t >= q) t -= q;

                std::uint64_t s = u + q - v;
                if (s >= q) s -= q;

                a[j]       = t;
                a[j+len] = s;
            }
        }
    }
}

// ====================== inverse NTT ====================== //

void intt_inplace(std::uint64_t* a,
                  const RNSModulus& mod,
                  std::size_t N)
{
    const std::uint64_t q = mod.q;
    const auto& W = mod.twiddle_inv;

    for (std::size_t len = N; len > 1; len >>= 1) {
        std::size_t half = len >> 1;
        std::size_t step = N / len;

        for (std::size_t start = 0; start < half; ++start) {
            std::uint64_t w = W[start * step];

            for (std::size_t j = start; j < N; j += len) {
                std::uint64_t u = a[j];
                std::uint64_t v = a[j + half];

                std::uint64_t t = u + v;
                if (t >= q) t -= q;

                std::uint64_t s = u + q - v;
                if (s >= q) s -= q;

                a[j]        = t;
                a[j + half] = (__uint128_t)s * w % q;
            }
        }
    }

    // multiply by N^{-1}
    const std::uint64_t n_inv = mod.n_inv;
    for (std::size_t i = 0; i < N; i++) {
        a[i] = (__uint128_t)a[i] * n_inv % q;
    }
}

} // namespace ckks::core
