#include <random>
#include <limits>
#include "core/params.hpp"
#include <stdexcept>
#include <iostream>

namespace ckks::core {

// ================= SECURITY TABLE ================= //

struct SecEntry {
    std::size_t N;
    SecurityLevel sec;
    int max_logq;
};

// HE Standard v1.1 classical model (ternary secret), extended conservatively
static constexpr SecEntry sec_table[] = {
    {4096,   SecurityLevel::SL128, 109},
    {4096,   SecurityLevel::SL192, 75},
    {4096,   SecurityLevel::SL256, 58},

    {8192,   SecurityLevel::SL128, 218},
    {8192,   SecurityLevel::SL192, 152},
    {8192,   SecurityLevel::SL256, 118},

    {16384,  SecurityLevel::SL128, 438},
    {16384,  SecurityLevel::SL192, 305},
    {16384,  SecurityLevel::SL256, 237},

    {32768,  SecurityLevel::SL128, 881},
    {32768,  SecurityLevel::SL192, 611},
    {32768,  SecurityLevel::SL256, 476},

    // conservative for larger N
    {65536,  SecurityLevel::SL128, 881},
    {65536,  SecurityLevel::SL192, 611},
    {65536,  SecurityLevel::SL256, 476},

    {131072, SecurityLevel::SL128, 881},
    {131072, SecurityLevel::SL192, 611},
    {131072, SecurityLevel::SL256, 476},
};

static std::size_t clamp_N(std::size_t N) {
    if (N <= 4096)   return 4096;
    if (N <= 8192)   return 8192;
    if (N <= 16384)  return 16384;
    if (N <= 32768)  return 32768;
    if (N <= 65536)  return 65536;
    return 131072;
}

int max_logq_classical_ternary(std::size_t N, SecurityLevel sec)
{
    std::size_t Nc = clamp_N(N);
    for (const auto& e : sec_table) {
        if (e.N == Nc && e.sec == sec)
            return e.max_logq;
    }
    throw std::runtime_error("Security entry missing (unexpected)");
}

// ======== Forward declarations (helpers) ======== //
static bool is_probable_prime(std::uint64_t n);
static std::uint64_t next_prime_congruent_1_mod(std::uint64_t start,
                                                std::uint64_t mod);

std::vector<std::uint64_t>
generate_modulus_chain(std::size_t N,
                       SecurityLevel sec,
                       const ChainDesign& d)
{
    // Number of primes = depth + 1 (typical CKKS chain model)
    const int levels = d.depth + 1;
    const int required_logQ = levels * d.log_scale + d.margin_bits;

    const int max_logQ = max_logq_classical_ternary(N, sec);

    if (required_logQ > max_logQ) {
        std::cerr << "[generate_modulus_chain] N=" << N
                  << " sec=" << static_cast<int>(sec)
                  << " depth=" << d.depth
                  << " log_scale=" << d.log_scale
                  << " margin=" << d.margin_bits
                  << " required_logQ=" << required_logQ
                  << " max_logQ=" << max_logQ << "\n";

        throw std::runtime_error(
            "generate_modulus_chain: requested chain exceeds security bound");
    }

    std::vector<std::uint64_t> qi_list;
    qi_list.reserve(static_cast<std::size_t>(levels));

    const std::uint64_t approx_bits = static_cast<std::uint64_t>(d.log_scale);
    const std::uint64_t low = (approx_bits >= 63)
        ? (std::numeric_limits<std::uint64_t>::max() >> 1)
        : (std::uint64_t(1) << approx_bits);

    const std::uint64_t mod = 2 * N;

    // Align starting point to 1 (mod 2N)
    std::uint64_t start = low;
    if (start % mod != 1) {
        start += (mod - (start % mod)) + 1;
    }

    for (int i = 0; i < levels; ++i) {
        std::uint64_t q = next_prime_congruent_1_mod(start, mod);
        qi_list.push_back(q);
        // Move forward for next prime
        start = q + mod;
    }

    return qi_list;
}

// ================= HELPER FUNCTIONS ================= //

static bool is_probable_prime(std::uint64_t n)
{
    if (n < 2) return false;
    for (std::uint64_t p : {2ULL,3ULL,5ULL,7ULL,11ULL,13ULL,17ULL,19ULL,23ULL,29ULL}) {
        if (n % p == 0) return n == p;
    }

    // write n-1 = d * 2^s with d odd
    std::uint64_t d = n - 1;
    std::uint64_t s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }

    auto check = [&](std::uint64_t a) {
        if (a % n == 0) return true;
        __uint128_t x = 1;
        __uint128_t base = a % n;
        std::uint64_t e = d;
        while (e > 0) {
            if (e & 1) x = (x * base) % n;
            base = (base * base) % n;
            e >>= 1;
        }
        std::uint64_t x64 = static_cast<std::uint64_t>(x);
        if (x64 == 1 || x64 == n - 1) return true;
        for (std::uint64_t r = 1; r < s; ++r) {
            x = (x * x) % n;
            x64 = static_cast<std::uint64_t>(x);
            if (x64 == n - 1) return true;
        }
        return false;
    };

    for (std::uint64_t a : {2ULL, 325ULL, 9375ULL, 28178ULL,
                            450775ULL, 9780504ULL, 1795265022ULL}) {
        if (a % n == 0) return true;
        if (!check(a)) return false;
    }
    return true;
}

static std::uint64_t next_prime_congruent_1_mod(std::uint64_t start,
                                                std::uint64_t mod)
{
    std::uint64_t x = start;
    if (x % mod != 1) {
        x += (mod - (x % mod)) + 1;
    }
    while (true) {
        if (is_probable_prime(x)) return x;
        x += mod;
    }
}

} // namespace ckks::core
