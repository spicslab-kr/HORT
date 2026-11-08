#pragma once

#include <algorithm>
#include <numeric>
#include <random>
#include <stdexcept>
#include <vector>

struct SevMaskingContext {
    std::mt19937_64 rng;

    SevMaskingContext() {
        std::random_device rd;
        std::seed_seq seed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
        rng.seed(seed);
    }
};

static std::vector<uint64_t> rlwe_coeff_moduli(CryptoContext<DCRTPoly> cc) {
    auto elemParams         = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    const size_t ringDim    = elemParams->GetRingDimension();
    const size_t numTowers  = towerParams.size();

    std::vector<uint64_t> moduli;
    moduli.reserve(2 * numTowers * ringDim);
    for (size_t comp = 0; comp < 2; ++comp) {
        for (size_t t = 0; t < numTowers; ++t) {
            const uint64_t q = towerParams[t]->GetModulus().ConvertToInt<uint64_t>();
            for (size_t i = 0; i < ringDim; ++i) {
                moduli.push_back(q);
            }
        }
    }
    return moduli;
}

static std::vector<uint64_t> sample_additive_mask(const std::vector<uint64_t>& moduli, SevMaskingContext& masking) {
    std::vector<uint64_t> mask(moduli.size(), 0);
    for (size_t i = 0; i < moduli.size(); ++i) {
        std::uniform_int_distribution<uint64_t> dist(0, moduli[i] - 1);
        mask[i] = dist(masking.rng);
    }
    return mask;
}

static void add_mask_mod(std::vector<uint64_t>& coeffs, const std::vector<uint64_t>& mask,
                         const std::vector<uint64_t>& moduli) {
    if (coeffs.size() != mask.size() || coeffs.size() != moduli.size()) {
        throw std::runtime_error("SEV mask size mismatch");
    }
    for (size_t i = 0; i < coeffs.size(); ++i) {
        uint64_t a = coeffs[i] % moduli[i];
        uint64_t r = mask[i] % moduli[i];
        uint64_t s = a + r;
        coeffs[i]  = (s >= moduli[i]) ? (s - moduli[i]) : s;
    }
}

static void sub_mask_mod(std::vector<uint64_t>& coeffs, const std::vector<uint64_t>& mask,
                         const std::vector<uint64_t>& moduli) {
    if (coeffs.size() != mask.size() || coeffs.size() != moduli.size()) {
        throw std::runtime_error("SEV mask size mismatch");
    }
    for (size_t i = 0; i < coeffs.size(); ++i) {
        uint64_t a = coeffs[i] % moduli[i];
        uint64_t r = mask[i] % moduli[i];
        coeffs[i]  = (a >= r) ? (a - r) : (moduli[i] - (r - a));
    }
}

static std::vector<size_t> sample_permutation(size_t n, SevMaskingContext& masking) {
    std::vector<size_t> pi(n);
    std::iota(pi.begin(), pi.end(), 0);
    std::shuffle(pi.begin(), pi.end(), masking.rng);
    return pi;
}

static std::vector<size_t> invert_permutation(const std::vector<size_t>& pi) {
    std::vector<size_t> inv(pi.size());
    for (size_t i = 0; i < pi.size(); ++i) {
        inv[pi[i]] = i;
    }
    return inv;
}

static void permute_rlwe_prefix_coefficients(CryptoContext<DCRTPoly> cc, std::vector<uint64_t>& coeffs,
                                             const std::vector<size_t>& pi) {
    auto elemParams         = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    const size_t ringDim    = elemParams->GetRingDimension();
    const size_t numTowers  = towerParams.size();
    if (pi.size() > ringDim || coeffs.size() != 2 * numTowers * ringDim) {
        throw std::runtime_error("SEV prefix shuffle size mismatch");
    }

    std::vector<uint64_t> tmp(pi.size());
    for (size_t comp = 0; comp < 2; ++comp) {
        for (size_t t = 0; t < numTowers; ++t) {
            const size_t base = (comp * numTowers + t) * ringDim;
            for (size_t i = 0; i < pi.size(); ++i) {
                tmp[i] = coeffs[base + pi[i]];
            }
            std::copy(tmp.begin(), tmp.end(), coeffs.begin() + base);
        }
    }
}

static void permute_lwe_slot_blocks(std::vector<uint64_t>& lweCoeffs, size_t slotCount, size_t perSlot,
                                    const std::vector<size_t>& pi) {
    if (pi.size() != slotCount || lweCoeffs.size() < slotCount * perSlot) {
        throw std::runtime_error("SEV generic LWE shuffle size mismatch");
    }

    std::vector<uint64_t> tmpLwe(lweCoeffs.size(), 0);
    for (size_t dst = 0; dst < slotCount; ++dst) {
        const size_t src = pi[dst];
        std::copy_n(lweCoeffs.begin() + src * perSlot, perSlot, tmpLwe.begin() + dst * perSlot);
    }

    lweCoeffs.swap(tmpLwe);
}

static void permute_lwe_slot_blocks(std::vector<uint64_t>& lweCoeffs, std::vector<double>& slots, size_t slotCount,
                                    size_t perSlot, const std::vector<size_t>& pi) {
    if (pi.size() != slotCount || slots.size() < slotCount || lweCoeffs.size() < slotCount * perSlot) {
        throw std::runtime_error("SEV LWE/slot shuffle size mismatch");
    }

    std::vector<uint64_t> tmpLwe(lweCoeffs.size(), 0);
    std::vector<double> tmpSlots(slots.size(), 0.0);
    for (size_t dst = 0; dst < slotCount; ++dst) {
        const size_t src = pi[dst];
        std::copy_n(lweCoeffs.begin() + src * perSlot, perSlot, tmpLwe.begin() + dst * perSlot);
        tmpSlots[dst] = slots[src];
    }

    lweCoeffs.swap(tmpLwe);
    slots.swap(tmpSlots);
}
