//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Examples for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#include "openfhe.h"
#include "binfhecontext.h"
#include "binfhe-base-scheme.h"
#include <fstream>

#include "key/keypair.h"
#include "key/privatekey.h"
#include "key/publickey.h"

#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"
#include "binfhecontext-ser.h"

#include <iostream>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <type_traits>
#include <utility>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include <omp.h>

using namespace lbcrypto;

#include "sev_masking.h"

// Time-Checker
#define TIC_FHE(t) t = omp_get_wtime();
#define TOC_FHE(t, acc) acc += (omp_get_wtime() - t);

// LOG Macro
#define LOG_STEP(msg) std::cout << "[LOG] " << msg << std::endl

struct RuntimeProfile {
    double pbsSec = 0.0;
    uint64_t pbsCalls = 0;
    double ckksBootstrapSec = 0.0;
    uint64_t ckksBootstrapCalls = 0;
    double ckksToFhewSec = 0.0;
    uint64_t ckksToFhewCalls = 0;
    double fhewToCkksSec = 0.0;
    uint64_t fhewToCkksCalls = 0;
    double otherCkksSec = 0.0;
    uint64_t otherCkksCalls = 0;
    double sevCkksRefreshSec = 0.0;
    uint64_t sevCkksRefreshCalls = 0;
    double sevLweRefreshSec = 0.0;
    uint64_t sevLweRefreshCalls = 0;
    double lweLinearGateSec = 0.0;
    uint64_t lweLinearGateCalls = 0;
};

static RuntimeProfile g_runtime_profile;
static double g_sev_remote_time_sec = 0.0;

static void add_profile_time(double& total_sec, uint64_t& calls, double delta_sec) {
#pragma omp atomic update
    total_sec += delta_sec;
#pragma omp atomic update
    ++calls;
}

struct ScopedProfileTimer {
    double& total_sec;
    uint64_t& calls;
    double start_sec;

    ScopedProfileTimer(double& total, uint64_t& call_count)
        : total_sec(total), calls(call_count), start_sec(omp_get_wtime()) {}
    ScopedProfileTimer(const ScopedProfileTimer&) = delete;
    ScopedProfileTimer& operator=(const ScopedProfileTimer&) = delete;
    ~ScopedProfileTimer() {
        add_profile_time(total_sec, calls, omp_get_wtime() - start_sec);
    }
};

template <typename Fn>
auto timed_call(double& total_sec, uint64_t& calls, Fn&& fn) -> std::invoke_result_t<Fn> {
    ScopedProfileTimer timer(total_sec, calls);
    if constexpr (std::is_void_v<std::invoke_result_t<Fn>>) {
        std::forward<Fn>(fn)();
    } else {
        return std::forward<Fn>(fn)();
    }
}

static void print_runtime_profile() {
    const auto oldFlags = std::cout.flags();
    const auto oldPrecision = std::cout.precision();
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "[TIME] Operation category totals (s):" << std::endl;
    std::cout << "  PBS (OpenFHE EvalFunc/EvalBinGate): "
              << g_runtime_profile.pbsSec << " s, calls=" << g_runtime_profile.pbsCalls << std::endl;
    std::cout << "  CKKS Bootstrapping (EvalBootstrap): "
              << g_runtime_profile.ckksBootstrapSec << " s, calls=" << g_runtime_profile.ckksBootstrapCalls << std::endl;
    std::cout << "  Scheme switching CKKStoFHEW (OpenFHE/SEV RLWE->LWE): "
              << g_runtime_profile.ckksToFhewSec << " s, calls=" << g_runtime_profile.ckksToFhewCalls << std::endl;
    std::cout << "  Scheme switching FHEWtoCKKS (OpenFHE/SEV LWE->RLWE): "
              << g_runtime_profile.fhewToCkksSec << " s, calls=" << g_runtime_profile.fhewToCkksCalls << std::endl;
    std::cout << "  Other CKKS functions: "
              << g_runtime_profile.otherCkksSec << " s, calls=" << g_runtime_profile.otherCkksCalls << std::endl;
    std::cout << "  SEV CKKS refresh/rescale: "
              << g_runtime_profile.sevCkksRefreshSec << " s, calls=" << g_runtime_profile.sevCkksRefreshCalls << std::endl;
    std::cout << "  SEV LWE refresh/reenc: "
              << g_runtime_profile.sevLweRefreshSec << " s, calls=" << g_runtime_profile.sevLweRefreshCalls << std::endl;
    std::cout << "  LWE linear gate eval (EvalBinGateSEV, no PBS): "
              << g_runtime_profile.lweLinearGateSec << " s, calls=" << g_runtime_profile.lweLinearGateCalls << std::endl;
    std::cout.flags(oldFlags);
    std::cout.precision(oldPrecision);
}

static void sev_add_remote_time(double delta_sec) {
#pragma omp critical(sev_time_accum)
    {
        g_sev_remote_time_sec += delta_sec;
    }
}

struct SevRemoteTimer {
    double start_sec;
    SevRemoteTimer() : start_sec(omp_get_wtime()) {}
    ~SevRemoteTimer() { sev_add_remote_time(omp_get_wtime() - start_sec); }
};

static double now_ms() {
    using clock = std::chrono::high_resolution_clock;
    return std::chrono::duration<double, std::milli>(clock::now().time_since_epoch()).count();
}

void parameterSetupAndKeyLoadOrGen(CryptoContext<DCRTPoly>& cc, std::shared_ptr<lbcrypto::BinFHEContext>& ccLWE, KeyPair<DCRTPoly>& keys, LWEPrivateKey& privateKeyFHEW, const std::vector<uint64_t>& sevSecretCoeffs);

std::vector<uint64_t> extractCiphertextCoeffs(ConstCiphertext<DCRTPoly> ciphertext) {
    std::vector<uint64_t> buffer;
    
    // A ciphertext typically consists of 2 polynomials: c0 and c1.
    const std::vector<DCRTPoly>& elements = ciphertext->GetElements();

    for (const auto& poly : elements) {
        // Each DCRTPoly is composed of multiple RNS towers (NativePoly).
        const std::vector<NativePoly>& towers = poly.GetAllElements();
        
        for (const auto& tower : towers) {
            // Iterate through the coefficients of the current tower.
            // std::cout << "Tower degree: " << tower.GetLength() << std::endl;
            for (size_t i = 0; i < tower.GetLength(); i++) {
                // Convert the internal BigInt type to uint64_t and store it.
                buffer.push_back(tower[i].ConvertToInt<uint64_t>()); 
            }
        }
    }
    return buffer;
}

std::vector<uint64_t> extractLWECiphertextCoeffs(ConstLWECiphertext ct) {
    std::vector<uint64_t> buffer;

    size_t n = ct->GetLength();
    buffer.reserve(n + 1);

    const NativeVector& a = ct->GetA();
    for (size_t i = 0; i < n; ++i) {
        buffer.push_back(a[i].ConvertToInt<uint64_t>());
    }
    buffer.push_back(ct->GetB().ConvertToInt<uint64_t>());

    return buffer;
}

Ciphertext<DCRTPoly> makeCiphertextFromCoeffs(CryptoContext<DCRTPoly> cc,
                                              const std::vector<uint64_t>& buffer) {
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers = towerParams.size();
    size_t ringDim   = elemParams->GetRingDimension();

    for (const auto& p : elemParams->GetParams())
    std::cout << p->GetModulus() << std::endl;


    size_t expectedSize = 2 * numTowers * ringDim;
    if (buffer.size() != expectedSize) {
        throw std::runtime_error("Coefficient buffer size does not match ciphertext dimensions, expected " + std::to_string(expectedSize) + ", got " + std::to_string(buffer.size()));
    }

    auto ciphertextImpl = std::make_shared<CiphertextImpl<DCRTPoly>>(cc);
    std::vector<DCRTPoly> elements;
    elements.reserve(2);
    // std::cout << "makecoeff1" << std::endl;
    size_t offset = 0;
    for (size_t comp = 0; comp < 2; ++comp) {
        DCRTPoly poly(elemParams, Format::EVALUATION, true);
        // std::cout << "makecoeff2" << std::endl;
        for (size_t t = 0; t < numTowers; ++t) {
            NativePoly tower(towerParams[t], Format::EVALUATION, true);
            for (size_t i = 0; i < ringDim; ++i) {
                tower[i] = NativeInteger(buffer[offset++]);
            }
            poly.SetElementAtIndex(t, std::move(tower));
        }
        //poly.SetFormat(Format::EVALUATION);
        elements.push_back(poly);
    }
    // std::cout << "makecoeff3" << std::endl;
    
    ciphertextImpl->SetElements(std::move(elements));
    ciphertextImpl->SetEncodingType(PlaintextEncodings::CKKS_PACKED_ENCODING);
    ciphertextImpl->SetLevel(0);
    ciphertextImpl->SetNoiseScaleDeg(1);

    static const double kSevScale = std::pow(2.0, 40);
    ciphertextImpl->SetScalingFactor(kSevScale);
    ciphertextImpl->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(kSevScale)));
    ciphertextImpl->SetSlots(ringDim / 2);

    return ciphertextImpl;
}

LWECiphertext makeLWECiphertextFromCoeffs(const std::shared_ptr<BinFHEContext>& ccLWE,
                                          const std::vector<uint64_t>& buffer) {
    auto lweParams = ccLWE->GetParams()->GetLWEParams();
    size_t n = lweParams->Getn();
    NativeInteger q = lweParams->Getq();
    size_t expectedSize = n + 1;

    if (buffer.size() != expectedSize) {
        throw std::runtime_error("LWE coefficient buffer size mismatch, expected " +
                                 std::to_string(expectedSize) + ", got " + std::to_string(buffer.size()));
    }

    NativeVector a(n, q);
    for (size_t i = 0; i < n; ++i) {
        NativeInteger val(buffer[i]);
        if (val >= q)
            val.ModEq(q);
        a[i] = val;
    }
    NativeInteger b(buffer[n]);
    if (b >= q)
        b.ModEq(q);

    auto ct = std::make_shared<LWECiphertextImpl>(std::move(a), b);
    ct->SetptModulus(ccLWE->GetMaxPlaintextSpace());
    return ct;
}

static PrivateKey<DCRTPoly> makeSecretKeyFromCoeffs(CryptoContext<DCRTPoly> cc,
                                                    const std::vector<uint64_t>& coeffs,
                                                    const PublicKey<DCRTPoly>& pk) {
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers = towerParams.size();
    size_t ringDim   = elemParams->GetRingDimension();

    if (coeffs.size() != numTowers * ringDim) {
        throw std::runtime_error("SEV secret key size mismatch with current crypto parameters, expected " + std::to_string(numTowers * ringDim) + ", got " + std::to_string(coeffs.size()));
    }

    DCRTPoly poly(elemParams, Format::COEFFICIENT, true);
    size_t offset = 0;
    for (size_t t = 0; t < numTowers; ++t) {
        NativePoly tower(towerParams[t], Format::COEFFICIENT, true);
        auto modulus = towerParams[t]->GetModulus();
        for (size_t i = 0; i < ringDim; ++i) {
            NativeInteger val(coeffs[offset++]);
            if (val >= modulus)
                val.ModEq(modulus);
            tower[i] = val;
        }
        poly.SetElementAtIndex(t, std::move(tower));
    }
    poly.SetFormat(Format::EVALUATION);

    auto skImpl = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
    skImpl->SetPrivateElement(poly);
    if (pk)
        skImpl->SetKeyTag(pk->GetKeyTag());
    return skImpl;
}

static LWEPrivateKey makeLweSecretKeyFromCoeffs(const std::shared_ptr<BinFHEContext>& ccLWE,
                                                const std::vector<uint64_t>& coeffs) {
    auto lweParams = ccLWE->GetParams()->GetLWEParams();
    size_t n = lweParams->Getn();
    NativeInteger q = lweParams->Getq();
    if (coeffs.size() != n) {
        throw std::runtime_error("SEV LWE key size mismatch, expected " +
                                 std::to_string(n) + ", got " + std::to_string(coeffs.size()));
    }
    NativeVector s(n, q);
    for (size_t i = 0; i < n; ++i) {
        NativeInteger val(coeffs[i]);
        if (val >= q)
            val.ModEq(q);
        s[i] = val;
    }
    return std::make_shared<LWEPrivateKeyImpl>(s);
}

static LWECiphertext EvalBinGateSEV(const std::shared_ptr<BinFHEContext>& ccLWE,
                                    BINGATE gate,
                                    ConstLWECiphertext& ct1,
                                    ConstLWECiphertext& ct2) {
    ScopedProfileTimer profileTimer(g_runtime_profile.lweLinearGateSec,
                                    g_runtime_profile.lweLinearGateCalls);
    if (!ccLWE)
        throw std::runtime_error("BinFHEContext is empty");
    if (!ct1)
        throw std::runtime_error("Ciphertext1 is empty");
    if (!ct2)
        throw std::runtime_error("Ciphertext2 is empty");
    if (ct1 == ct2)
        throw std::runtime_error("Input ciphertexts should be independent");

    const auto& params = ccLWE->GetParams();
    const auto& lweParams = params->GetLWEParams();
    NativeInteger Q{lweParams->GetQ()};
    auto lweScheme = ccLWE->GetLWEScheme();

    auto cct1 = (Q == ct1->GetModulus())
                    ? lweScheme->SwitchCTtoqn(lweParams, ccLWE->GetSwitchKey(), ct1)
                    : std::make_shared<LWECiphertextImpl>(*ct1);
    const auto cct2 = (Q == ct2->GetModulus())
                          ? lweScheme->SwitchCTtoqn(lweParams, ccLWE->GetSwitchKey(), ct2)
                          : ct2;

    if ((gate == XOR) || (gate == XNOR) || (gate == XOR_FAST) || (gate == XNOR_FAST)) {
        lweScheme->EvalAddEq(cct1, cct2);
        lweScheme->EvalAddEq(cct1, cct1);
    } else {
        lweScheme->EvalAddEq(cct1, cct2);
    }

    return cct1;
}


// === SEV VM connection settings ===
static const char* SEV_VM_IP   = "192.168.100.2"; // replace with the actual SEV VM IP
//static const char* SEV_VM_IP   = "127.0.0.1"; // replace with the actual SEV VM IP
static const int   SEV_VM_PORT = 8080;        // port where reenc_e2e is listening
    // Must match the N and LEVEL used to build reenc_e2e
static const size_t SEV_LEVEL  = 2;
static const size_t SEV_N      = 16384;       // example: if reenc_e2e was built with N=16384
static const size_t SEV_LWE_N  = 630;
static const size_t SEV_LWE_BIT_WIDTH = 15;
static constexpr double SEV_SCALE = static_cast<double>(uint64_t(1) << 40);

static const uint32_t SEV_REENC_MAGIC = 0x52454e43; // "RENC"
enum SevReencRequest : uint32_t {
    SEV_REQ_RLWE_COEFF_ENC  = 1,
    SEV_REQ_RLWE_COEFF_DEC  = 2,
    SEV_REQ_RLWE_COEFF_REENC  = 3,
    SEV_REQ_RLWE_SLOT_ENC  = 4,
    SEV_REQ_RLWE_SLOT_DEC  = 5,
    SEV_REQ_RLWE_SLOT_REENC = 6,
    SEV_REQ_LWE_ENC        = 7,
    SEV_REQ_LWE_DEC        = 8,
    SEV_REQ_LWE_REENC       = 9,
    SEV_REQ_RLWE_SLOT_DEC_LWE_CT = 10,
    SEV_REQ_LWE_DEC_SLOT_ENC = 11,
};

static ssize_t write_full(int fd, const void* buf, size_t count);
static ssize_t read_full(int fd, void* buf, size_t count);
static bool sev_send_header(int sockfd, uint32_t req_type, uint64_t payload_bytes);

[[maybe_unused]] static bool sev_remote_reenc_rescale(int sockfd,
                                     const uint64_t* in_buf,
                                     size_t coeff_count,
                                     long double input_scale,
                                     long double output_scale,
                                     uint64_t* out_buf) {
    ScopedProfileTimer profileTimer(g_runtime_profile.sevCkksRefreshSec,
                                    g_runtime_profile.sevCkksRefreshCalls);
    SevRemoteTimer timer;

/*
    Goal: Re-scale a ciphertext under SEV remote re-encryption service.
    Remote re-encrypt with explicit input/output scales prepended to the request.
    Layout: [input_scale (long double)][output_scale (long double)][coefficients...]
*/
    const size_t byte_count = coeff_count * sizeof(uint64_t);
    long double scales[2]   = {input_scale, output_scale};
    const size_t payload_bytes = sizeof(scales) + byte_count;


    if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_REENC, payload_bytes)) {
        return false;
    }
    // send scales
    if (write_full(sockfd, scales, sizeof(scales)) != (ssize_t)sizeof(scales)) {
        perror("write_full (scales)");
        return false;
    }

    // send ciphertext coefficients
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full (ciphertext)");
        return false;
    }

    // receive re-encrypted coefficients
    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    return true;
}

// RLWE -> LWE

[[maybe_unused]] static bool sev_remote_reenc_slot_dec_lwe_ct(int sockfd,
                             const uint64_t* in_buf,
                             size_t coeff_count,
                             long double input_scale,
                             uint64_t* out_buf) {
    ScopedProfileTimer profileTimer(g_runtime_profile.ckksToFhewSec,
                                    g_runtime_profile.ckksToFhewCalls);
    SevRemoteTimer timer;
    size_t byte_count = coeff_count * sizeof(uint64_t);
    size_t msg_count = (SEV_N / 2) * SEV_LWE_BIT_WIDTH * (SEV_LWE_N + 1) * sizeof(uint64_t);
    const size_t payload_bytes = sizeof(input_scale) + byte_count;

    if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_DEC_LWE_CT, payload_bytes)) {
        return false;
    }
    if (write_full(sockfd, &input_scale, sizeof(input_scale)) != (ssize_t)sizeof(input_scale)) {
        perror("write_full (scale)");
        return false;
    }
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full");
        return false;
    }

    ssize_t r = read_full(sockfd, out_buf, msg_count);
    if (r != (ssize_t)msg_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    return true;
}

// LWE -> RLWE

[[maybe_unused]] static bool sev_remote_lwe_dec_slot_enc(int sockfd,
                             const uint64_t* in_buf,
                             size_t in_u64_count,
                             uint64_t* out_buf,
                             size_t out_u64_count) {
    ScopedProfileTimer profileTimer(g_runtime_profile.fhewToCkksSec,
                                    g_runtime_profile.fhewToCkksCalls);
    SevRemoteTimer timer;
    size_t in_bytes = in_u64_count * sizeof(uint64_t);
    size_t out_bytes = out_u64_count * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_LWE_DEC_SLOT_ENC, in_bytes)) {
        return false;
    }
    if (write_full(sockfd, in_buf, in_bytes) != (ssize_t)in_bytes) {
        perror("write_full");
        return false;
    }
    ssize_t r = read_full(sockfd, out_buf, out_bytes);
    if (r != (ssize_t)out_bytes) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    return true;
}

static bool sev_remote_reenc_lwe(int sockfd,
                                 const uint64_t* in_buf,
                                 size_t coeff_count,
                                 uint64_t* out_buf) {
    ScopedProfileTimer profileTimer(g_runtime_profile.sevLweRefreshSec,
                                    g_runtime_profile.sevLweRefreshCalls);
    SevRemoteTimer timer;
    const size_t byte_count = coeff_count * sizeof(uint64_t);

    if (!sev_send_header(sockfd, SEV_REQ_LWE_REENC, byte_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full (lwe reenc)");
        return false;
    }
    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full (lwe reenc)");
        else
            fprintf(stderr, "short read (lwe reenc): %zd bytes\n", r);
        return false;
    }
    return true;
}

static LWECiphertext sev_refresh_lwe(const std::shared_ptr<BinFHEContext>& ccLWE,
                                     ConstLWECiphertext ct,
                                     int sev_sock) {
    static SevMaskingContext masking;
    auto coeffs = extractLWECiphertextCoeffs(ct);
    std::vector<uint64_t> out(coeffs.size(), 0);
    const uint64_t q = ccLWE->GetParams()->GetLWEParams()->Getq().ConvertToInt<uint64_t>();
    std::uniform_int_distribution<uint64_t> dist(0, q - 1);
    const uint64_t mask = dist(masking.rng);
    uint64_t maskedB = coeffs.back() + mask;
    coeffs.back() = (maskedB >= q) ? (maskedB - q) : maskedB;
    if (!sev_remote_reenc_lwe(sev_sock, coeffs.data(), coeffs.size(), out.data())) {
        throw std::runtime_error("SEV LWE reenc failed");
    }
    out.back() = (out.back() >= mask) ? (out.back() - mask) : (q - (mask - out.back()));
    return makeLWECiphertextFromCoeffs(ccLWE, out);
}

/*
    Goal: given a ciphertext ct, perform SEV remote re-encryption and rescaling,
          return the refreshed ciphertext
    Extracts the coefficients from ct, sends them to SEV VM for re-encryption and rescaling,
    receives the new coefficients, constructs a new ciphertext and returns it
    
*/
[[maybe_unused]] static Ciphertext<DCRTPoly> sev_refresh_ciphertext(Ciphertext<DCRTPoly> ct,
                                                   int sev_sock,
                                                   size_t coeffCount,
                                                   const std::string& keyTag,
                                                   double targetScale = SEV_SCALE,
                                                   const char* label = "sev_refresh_ciphertext") {

    auto cc = ct->GetCryptoContext();
    std::vector<uint64_t> in_coeff = extractCiphertextCoeffs(ct);
    std::vector<uint64_t> out_coeff(coeffCount, 0);
    // 
    double inputScale = ct->GetScalingFactor();
    if (!sev_remote_reenc_rescale(sev_sock, in_coeff.data(), coeffCount,
                                  static_cast<long double>(inputScale),
                                  static_cast<long double>(targetScale),
                                  out_coeff.data())) {
        throw std::runtime_error("SEV reenc (refresh) failed");
    }
    // Make new ciphertext from received coefficients  
    auto refreshed = makeCiphertextFromCoeffs(cc, out_coeff);
    refreshed->SetScalingFactor(targetScale);
    refreshed->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(targetScale)));
    refreshed->SetLevel(ct->GetLevel());
    // Set noise scale degree to 0 since it's been refreshed
    // forecing level to 0 is not available in OpenFHE API
    refreshed->SetNoiseScaleDeg(0);
    refreshed->SetKeyTag(keyTag);
    return refreshed;
}


// Write exactly "count" bytes, blocking until all data is sent or an error occurs
static ssize_t write_full(int fd, const void* buf, size_t count) {
    size_t left = count;
    const char* ptr = static_cast<const char*>(buf);

    while (left > 0) {
        ssize_t w = ::write(fd, ptr, left);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0)
            break;
        left -= w;
        ptr  += w;
    }
    return static_cast<ssize_t>(count - left);
}

// Read exactly "count" bytes, blocking until all data is received or an error occurs
static ssize_t read_full(int fd, void* buf, size_t count) {
    size_t left = count;
    char* ptr = static_cast<char*>(buf);

    while (left > 0) {
        ssize_t r = ::read(fd, ptr, left);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        left -= r;
        ptr  += r;
    }
    return static_cast<ssize_t>(count - left);
}


static std::vector<uint64_t> recv_sev_secret_key(int sockfd) {
    uint64_t count = 0;
    if (read_full(sockfd, &count, sizeof(count)) != sizeof(count)) {
        throw std::runtime_error("Failed to read SEV secret key header");
    }
    size_t totalBytes = static_cast<size_t>(count) * sizeof(uint64_t);
    std::vector<uint64_t> coeffs(count);
    if (read_full(sockfd, coeffs.data(), totalBytes) != static_cast<ssize_t>(totalBytes)) {
        throw std::runtime_error("Failed to read SEV secret key payload");
    }
    return coeffs;
}

// Open a TCP connection to the SEV VM running reenc_e2e
static int connect_to_sev(const char* ip, int port) {
    int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);
    
    if (::inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        ::close(sockfd);
        return -1;
    }
    
    if (::connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        ::close(sockfd);
        return -1;
    }
    
    return sockfd;
}

static bool sev_send_header(int sockfd, uint32_t req_type, uint64_t payload_bytes) {
    if (write_full(sockfd, &SEV_REENC_MAGIC, sizeof(SEV_REENC_MAGIC)) != sizeof(SEV_REENC_MAGIC)) {
        perror("write_full (magic)");
        return false;
    }
    if (write_full(sockfd, &req_type, sizeof(req_type)) != sizeof(req_type)) {
        perror("write_full (req_type)");
        return false;
    }
    if (write_full(sockfd, &payload_bytes, sizeof(payload_bytes)) != sizeof(payload_bytes)) {
        perror("write_full (payload_bytes)");
        return false;
    }
    return true;
}

[[maybe_unused]] static bool sev_remote_reenc_slot_enc(int sockfd,
                             const double* in_buf,
                             size_t coeff_count,
                             uint64_t* out_buf) {
    SevRemoteTimer timer;
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
    if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_ENC, msg_count)) {
        return false;
    }
    if (write_full(sockfd, in_buf, msg_count) != (ssize_t)msg_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_enc" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_enc" << std::endl;
    return true;
}

// static bool sev_remote_reenc_slot_dec(int sockfd,
//                              const uint64_t* in_buf,
//                              size_t coeff_count,
//                              double* out_buf) {
//         size_t byte_count = coeff_count * sizeof(uint64_t);
//         size_t msg_count = SEV_N / 2 * sizeof(double);
    
//         if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_DEC, byte_count)) {
//                 return false;
//             }
//             if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
//         perror("write_full");
//         return false;
//     }
//     //std::cout << "write done in sev_remote_reenc_slot_dec" << std::endl;

//     ssize_t r = read_full(sockfd, out_buf, msg_count);
//     if (r != (ssize_t)msg_count) {
//         if (r < 0)
//             perror("read_full");
//         else
//             fprintf(stderr, "short read: %zd bytes\n", r);
//         return false;
//     }
//     //std::cout << "read done in sev_remote_reenc_slot_dec" << std::endl;
//     return true;
// }

// static bool sev_remote_reenc_coeff_enc(int sockfd,
//                              const double* in_buf,
//                              size_t coeff_count,
//                              uint64_t* out_buf) {
//         size_t byte_count = coeff_count * sizeof(uint64_t);
//         size_t msg_count = SEV_N / 2 * sizeof(double);
    
//     if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_ENC, msg_count)) {
//         return false;
//     }
//     if (write_full(sockfd, in_buf, msg_count) != (ssize_t)msg_count) {
//         perror("write_full");
//         return false;
//     }
//     std::cout << "write done in sev_remote_reenc_slot_enc" << std::endl;

//     ssize_t r = read_full(sockfd, out_buf, byte_count);
//     if (r != (ssize_t)byte_count) {
//         if (r < 0)
//             perror("read_full");
//         else
//             fprintf(stderr, "short read: %zd bytes\n", r);
//         return false;
//     }
//     //std::cout << "read done in sev_remote_reenc_slot_enc" << std::endl;
//     return true;
// }

// static bool sev_remote_reenc_coeff_dec(int sockfd,
//                              const uint64_t* in_buf,
//                              size_t coeff_count,
//                              double* out_buf) {
//         size_t byte_count = coeff_count * sizeof(uint64_t);
//         size_t msg_count = SEV_N / 2 * sizeof(double);
    
//         if (!sev_send_header(sockfd, SEV_REQ_RLWE_COEFF_DEC, byte_count)) {
//                 return false;
//             }
//             if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
//         perror("write_full");
//         return false;
//     }
//     //std::cout << "write done in sev_remote_reenc_slot_dec" << std::endl;

//     ssize_t r = read_full(sockfd, out_buf, msg_count);
//     if (r != (ssize_t)msg_count) {
//         if (r < 0)
//             perror("read_full");
//         else
//             fprintf(stderr, "short read: %zd bytes\n", r);
//         return false;
//     }
//     //std::cout << "read done in sev_remote_reenc_slot_dec" << std::endl;
//     return true;
// }

// // Remote re-encrypt with explicit input/output scales prepended to the request.
// // Layout: [input_scale (long double)][output_scale (long double)][coefficients...]
// static bool sev_remote_reenc_slot_rescale(int sockfd,
//                                      const uint64_t* in_buf,
//                                      size_t coeff_count,
//                                      long double input_scale,
//                                      long double output_scale,
//                                      uint64_t* out_buf) {
//     const size_t byte_count = coeff_count * sizeof(uint64_t);
//     long double scales[2]   = {input_scale, output_scale};
//     const size_t payload_bytes = sizeof(scales) + byte_count;

//     if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_REENC, payload_bytes)) {
//         return false;
//     }
//     // send scales
//     if (write_full(sockfd, scales, sizeof(scales)) != (ssize_t)sizeof(scales)) {
//         perror("write_full (scales)");
//         return false;
//     }

//     // send ciphertext coefficients
//     if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
//         perror("write_full (ciphertext)");
//         return false;
//     }

//     // receive re-encrypted coefficients
//     ssize_t r = read_full(sockfd, out_buf, byte_count);
//     if (r != (ssize_t)byte_count) {
//         if (r < 0)
//             perror("read_full");
//         else
//             fprintf(stderr, "short read: %zd bytes\n", r);
//         return false;
//     }
//     return true;
// }

// static bool sev_remote_reenc_lwe_enc(int sockfd,
//                                       const uint64_t* in_buf,
//                                       size_t coeff_count,
//                                       uint64_t* out_buf) {
//     const size_t byte_count = coeff_count * sizeof(uint64_t);

//     if (!sev_send_header(sockfd, SEV_REQ_LWE_ENC, byte_count)) {
//         return false;
//     }
//     if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
//         perror("write_full (lwe enc)");
//         return false;
//     }
//     ssize_t r = read_full(sockfd, out_buf, byte_count);
//     if (r != (ssize_t)byte_count) {
//         if (r < 0)
//             perror("read_full (lwe enc)");
//         else
//             fprintf(stderr, "short read (lwe enc): %zd bytes\n", r);
//         return false;
//     }
//     return true;
// }

// static bool sev_remote_reenc_lwe(int sockfd,
//                                  const uint64_t* in_buf,
//                                  size_t coeff_count,
//                                  uint64_t* out_buf) {
//     const size_t byte_count = coeff_count * sizeof(uint64_t);

//     if (!sev_send_header(sockfd, SEV_REQ_LWE_REENC, byte_count)) {
//         return false;
//     }
//     if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
//         perror("write_full (lwe)");
//         return false;
//     }
//     ssize_t r = read_full(sockfd, out_buf, byte_count);
//     if (r != (ssize_t)byte_count) {
//         if (r < 0)
//             perror("read_full (lwe)");
//         else
//             fprintf(stderr, "short read (lwe): %zd bytes\n", r);
//         return false;
//     }
//     return true;
// }

uint32_t CheckInputFunctionLocal(const std::vector<NativeInteger>& lut, NativeInteger mod) {
    size_t mid{lut.size() / 2};
    if (lut[0] == (mod - lut[mid])) {
        for (size_t i = 1; i < mid; ++i)
            if (lut[i] != (mod - lut[mid + i]))
                return 2;
        return 0;
    }
    if (lut[0] == lut[mid]) {
        for (size_t i = 1; i < mid; ++i)
            if (lut[i] != lut[mid + i])
                return 2;
        return 1;
    }
    return 2;
}

// CKKS ciphertext 디버그 출력 (앞부분만)
// void DebugPrintCKKS(const CryptoContext<DCRTPoly>& cc,
//                     const PrivateKey<DCRTPoly>& sk,
//                     ConstCiphertext<DCRTPoly> ct,
//                     const std::string& label,
//                     size_t take = 8) {
//     Plaintext pt;
//     cc->Decrypt(sk, ct, &pt);
//     pt->SetLength(take);
//     auto vals = pt->GetRealPackedValue();
//     std::cout << "[DBG] " << label << " (first " << take << "): ";
//     for (size_t i = 0; i < std::min(take, vals.size()); ++i) {
//         std::cout << vals[i] << " ";
//     }
//     std::cout << std::endl;
// }


int main() {
    /*
        Database benchmark with Bit-encoded LWE Ciphertext
        1. Make LWE Ciphertext of Data / Make RLWE Ciphertext of DATA Packed all in one ciphertext
        2. Make LWE Ciphertext of Threshold
        3. Compare 1 and 2 by bits from MSB to LSB
            3-1. Comparing bits with BinFHEGate(AND). 
            
        4. Make Mask of Data, If data is smaller than Threshold mask filled with 0 and multiply
            4-1. i.e., 
                    DATA[0] = 3.0; DATA[1] = 8.2; DATA[2] = 1.0; DATA[3] = 10.0
                    THRESHOLD = 5
                Comparision
                    LWE(DATA[0]) = 0011 LWE(DATA[1]) = 1000.0 ..
                    LWE(THRESHOLD) = 0101  
                MASK = 0   | 1   | 0   | 1    | 0 | ... 
                RLWE = 3.0 | 8.2 | 1.0 | 10.0 | ...
                RLWE *= MASK = 0 | 8.2 | 0 | 10.0 | ...

        5. ADD Every Data with EvalSum
    */

    double t_total = now_ms();
    double t_stage = t_total;
    LOG_STEP("Stage 0: SEV connection and key load");
    // SEV Connect Initialization
    int sev_sock = connect_to_sev(SEV_VM_IP, SEV_VM_PORT);
    
    if (sev_sock < 0) {
        std::cerr << "Failed to connect to SEV VM" << std::endl;
        return 1;
    }
    std::vector<uint64_t> sevSecretCoeffs;
    try {
        sevSecretCoeffs = recv_sev_secret_key(sev_sock);
    } catch (const std::exception& e) {
        std::cerr << "Failed to receive SEV secret key: " << e.what() << std::endl;
        ::close(sev_sock);
        return 1;
    }
    std::cout << "SEV VM connected" << std::endl;
    std::cout << "[TIME] Stage 0: " << (now_ms() - t_stage) << " ms" << std::endl;
    // SEV Connect Initialization - Finished

    t_stage = now_ms();
    LOG_STEP("Stage 1: OpenFHE parameter setup");
    // OpenFHE Parameter Setup
    uint32_t scaleModSize = 40;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = SEV_N;
    SecurityLevel sl      = HEStd_NotSet;

    uint32_t slots          = ringDim >> 1;
    uint32_t batchSize      = slots;
    ScalingTechnique scTech = FLEXIBLEAUTO; // FLEXIBLEAUTOEXT --> FLEXIBLEAUTO for matching CKKS numTowers
    uint32_t multDepth = SEV_LEVEL - 1;

    const size_t coeffCount = 2 * SEV_LEVEL * SEV_N;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = timed_call(g_runtime_profile.otherCkksSec,
                                             g_runtime_profile.otherCkksCalls,
                                             [&] { return GenCryptoContext(parameters); });
    {
        auto elemParams = cc->GetCryptoParameters()->GetElementParams();
        size_t numTowers = elemParams->GetParams().size();
        if (numTowers != SEV_LEVEL) {
            throw std::runtime_error("CKKS tower count mismatch: numTowers=" + std::to_string(numTowers) +
                                     " (expected " + std::to_string(SEV_LEVEL) + ")");
        }
        std::cout << "[LOG] CKKS params (N=" << ringDim << "):" << std::endl;
        for (size_t i = 0; i < numTowers; ++i) {
            const auto& p = elemParams->GetParams()[i];
            std::cout << "  q[" << i << "]=" << p->GetModulus()
                      << " root=" << p->GetRootOfUnity() << std::endl;
        }
    }
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->Enable(PKE); });
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->Enable(KEYSWITCH); });
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->Enable(LEVELEDSHE); });
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->Enable(ADVANCEDSHE); });

    auto keys = timed_call(g_runtime_profile.otherCkksSec,
                           g_runtime_profile.otherCkksCalls,
                           [&] { return cc->KeyGen(); });
    try {
        keys.secretKey = makeSecretKeyFromCoeffs(cc, sevSecretCoeffs, keys.publicKey);
    } catch (const std::exception& e) {
        std::cerr << "SEV secret key load failed: " << e.what() << std::endl;
        return 1;
    }
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->EvalMultKeyGen(keys.secretKey); });
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->EvalSumKeyGen(keys.secretKey); });
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 4, 8, 16, 32, 64, 128, -1, -2, -4, -8, -16, -32, -64, -128}); });

    LOG_STEP("Stage 2: BinFHE context and keys");
    auto ccLWE = std::make_shared<BinFHEContext>();
    ccLWE->GenerateBinFHEContext(STD128, GINX);
    std::cout << "[LWE] q=" << ccLWE->GetParams()->GetLWEParams()->Getq()
              << " n=" << ccLWE->GetParams()->GetLWEParams()->Getn() << std::endl;
    std::vector<uint64_t> sevLweSecretCoeffs(SEV_LWE_N);
    for (size_t i = 0; i < SEV_LWE_N; ++i) {
        sevLweSecretCoeffs[i] = sevSecretCoeffs[i];
    }
    LWEPrivateKey privateKeyFHEW;
    try {
        privateKeyFHEW = makeLweSecretKeyFromCoeffs(ccLWE, sevLweSecretCoeffs);
    } catch (const std::exception& e) {
        std::cerr << "SEV LWE key load failed: " << e.what() << std::endl;
        return 1;
    }
    ccLWE->BTKeyGen(privateKeyFHEW);
    // OpenFHE Parameter Setup - Finished
    std::cout << "[TIME] Stage 1-2: " << (now_ms() - t_stage) << " ms" << std::endl;

    t_stage = now_ms();
    LOG_STEP("Stage 3: Input preparation");
    // Setting Up threshold and datas
    const uint32_t THRESH = 5; 

    std::vector<double> data(slots, 0.0); // 벡터에 slot 개수만큼 0을 집어넣음

    double acc_init = 2.5;

    std::vector<double> accVec(slots, 0.0);
    accVec[0] = acc_init;

    const size_t len = 2048; // 유효 데이터 길이
    const uint32_t pLWE = ccLWE->GetMaxPlaintextSpace().ConvertToInt();
    const NativeInteger qLWE = ccLWE->GetParams()->GetLWEParams()->Getq();

    const double scaleFactor = 1000.0;
    for (size_t i = 0; i < len; ++i)
        data[i] = 4.0 ;//+ 0.1 * static_cast<double>(i);
    double maxVal = static_cast<double>(THRESH);
    for (size_t i = 0; i < len; ++i)
        maxVal = std::max(maxVal, std::abs(data[i]));
    const uint32_t bitWidth = 64;

    auto toScaledInt = [&](double v) -> uint64_t {
        double scaled = std::round(v * scaleFactor);
        if (scaled < 0.0)
            scaled = 0.0;
        return static_cast<uint64_t>(scaled);
    };

    std::cout << "[TIME] Stage 3: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 4: CKKS encrypt packed data");
    // =================================
    // 1. Make LWE Ciphertext of Data / Make RLWE Ciphertext of DATA Packed all in one ciphertext
    // =================================
    Plaintext pData = timed_call(g_runtime_profile.otherCkksSec,
                                  g_runtime_profile.otherCkksCalls,
                                  [&] { return cc->MakeCKKSPackedPlaintext(data, 1, 0, nullptr, slots); });
    auto cData = timed_call(g_runtime_profile.otherCkksSec,
                            g_runtime_profile.otherCkksCalls,
                            [&] { return cc->Encrypt(keys.secretKey, pData); });


    std::cout << "[TIME] Stage 4: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 5: LWE bit encryption for data");
    std::vector<std::vector<LWECiphertext>> dataBits(len, std::vector<LWECiphertext>(bitWidth));
    for (size_t i = 0; i < len; ++i) {
        uint64_t val = toScaledInt(data[i]);
        for (uint32_t b = 0; b < bitWidth; ++b) {
            uint32_t shift = bitWidth - 1 - b;
            uint32_t bit = static_cast<uint32_t>((val >> shift) & 1ULL);
            dataBits[i][b] = ccLWE->Encrypt(privateKeyFHEW, bit, SMALL_DIM, pLWE, qLWE);
        }
    }

    // =================================
    // 2. Make LWE Ciphertext of Threshold
    // =================================
    std::cout << "[TIME] Stage 5: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 6: LWE bit encryption for threshold");
    uint64_t threshInt = toScaledInt(static_cast<double>(THRESH));
    std::vector<LWECiphertext> threshBits(bitWidth);
    for (uint32_t b = 0; b < bitWidth; ++b) {
        uint32_t shift = bitWidth - 1 - b;
        uint32_t bit = static_cast<uint32_t>((threshInt >> shift) & 1ULL);
        threshBits[b] = ccLWE->Encrypt(privateKeyFHEW, bit, SMALL_DIM, pLWE, qLWE);
    }

    // ===================================
    // 3. Compare 1 and 2 by bits from MSB to LSB
    // ===================================
    std::cout << "[TIME] Stage 6: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 7: LWE compare (MSB->LSB)");
    auto ctZero = ccLWE->Encrypt(privateKeyFHEW, 0, SMALL_DIM, pLWE, qLWE);
    auto ctOne = ccLWE->Encrypt(privateKeyFHEW, 1, SMALL_DIM, pLWE, qLWE);
    std::vector<LWECiphertext> maskBits(len);

    const uint32_t refreshInterval = 8;
    // #pragma omp parallel for schedule(static)
    for (size_t i = 0; i < len; ++i) {
        auto ctGt = ctZero;
        auto ctEq = ctOne;
    // #pragma omp parallel for
        for (uint32_t b = 0; b < bitWidth; ++b) {
            // Gate Logic for Comparision
            auto ctA = dataBits[i][b];
            auto ctB = threshBits[b];
            auto ctNotB = ccLWE->EvalNOT(ctB);
            auto ctNotGtPrev = ccLWE->EvalNOT(ctGt);
            auto ctAGtB = EvalBinGateSEV(ccLWE, AND, ctA, ctNotB);
            auto ctEqAndGt = EvalBinGateSEV(ccLWE, AND, ctEq, ctAGtB);
            ctGt = EvalBinGateSEV(ccLWE, OR, ctGt, ctEqAndGt);
            auto ctEqBit = EvalBinGateSEV(ccLWE, XNOR, ctA, ctB);
            ctEq = EvalBinGateSEV(ccLWE, AND, ctEq, ctEqBit);
            ctEq = EvalBinGateSEV(ccLWE, AND, ctEq, ctNotGtPrev);

            if (refreshInterval > 0 && ((b + 1) % refreshInterval == 0)) {
                ctGt = sev_refresh_lwe(ccLWE, ctGt, sev_sock);
                // ctEq = sev_refresh_lwe(ccLWE, ctEq, sev_sock); <-- 불필요
            }
        }
        maskBits[i] = ctGt;
    }

    // const uint32_t treeRefreshInterval = 2; // refresh every merge level
    // #pragma omp parallel for schedule(static)
    // for (size_t i = 0; i < len; ++i) {
    //     // 1. 초기 비트별 Greater(G) 및 Equal(E) 계산
    //     // G[b] = A[b] > B[b], E[b] = A[b] == B[b]
    //     std::vector<LWECiphertext> G(bitWidth);
    //     std::vector<LWECiphertext> E(bitWidth);

    //     // 이 부분은 비트별로 독립적이므로 병렬 처리가 가능합니다.
    //     for (uint32_t b = 0; b < bitWidth; ++b) {
    //         auto ctA = dataBits[i][b];
    //         auto ctB = threshBits[b];
            
    //         // G_b = A & !B
    //         G[b] = EvalBinGateSEV(ccLWE, AND, ctA, ccLWE->EvalNOT(ctB));
    //         // E_b = A XNOR B
    //         E[b] = EvalBinGateSEV(ccLWE, XNOR, ctA, ctB);
    //     }

    //     // 2. 트리 구조 병합 (Logarithmic Depth)
    //     // 두 구간 [High]와 [Low]를 합칠 때:
    //     // G_new = G_high OR (E_high AND G_low)
    //     // E_new = E_high AND E_low
    //     uint32_t step = 1;
    //     uint32_t level = 0;
    //     while (step < bitWidth) {
    //         for (uint32_t b = 0; b < bitWidth - step; b += 2 * step) {
    //             uint32_t low = b;
    //             uint32_t high = b + step;

    //             // 임시 변수에 저장하여 데이터 오염 방지
    //             // G[high]가 더 상위 비트(MSB 쪽)라고 가정
    //             auto tempAnd = EvalBinGateSEV(ccLWE, AND, E[high], G[low]);
    //             G[low] = EvalBinGateSEV(ccLWE, OR, G[high], tempAnd);
    //             E[low] = EvalBinGateSEV(ccLWE, AND, E[high], E[low]);
    //         }
    //         if (treeRefreshInterval > 0 && ((level + 1) % treeRefreshInterval == 0)) {
    //             for (uint32_t b = 0; b < bitWidth - step; b += 2 * step) {
    //                 uint32_t low = b;
    //                 G[low] = sev_refresh_lwe(ccLWE, G[low], sev_sock);
    //                 E[low] = sev_refresh_lwe(ccLWE, E[low], sev_sock);
    //             }
    //         }
    //         step *= 2;
    //         ++level;
    //     }

    //     // 최종 결과: 모든 비트 범위를 아우르는 G[0]가 A > B의 결과임
    //     maskBits[i] = G[0];
    // }

    // #pragma omp parallel for schedule(static)
    // for (size_t i = 0; i < len; ++i) {
    //     // 1. Thread-local 공간에 트리 연산을 위한 버퍼 준비
    //     std::vector<LWECiphertext> G(bitWidth);
    //     std::vector<LWECiphertext> E(bitWidth);

    //     // [Step 1] 비트별 초기 비교 (No Refresh)
    //     #pragma omp parallel for
    //     for (uint32_t b = 0; b < bitWidth; ++b) {
    //         auto ctA = dataBits[i][b];
    //         auto ctB = threshBits[b];
    //         G[b] = EvalBinGateSEV(ccLWE, AND, ctA, ccLWE->EvalNOT(ctB));
    //         E[b] = EvalBinGateSEV(ccLWE, XNOR, ctA, ctB);
    //     }

    //     // [Step 2] 트리 병합 (Depth: log N)
    //     uint32_t step = 1;
    //     while (step < bitWidth) {
    //         for (uint32_t b = 0; b < bitWidth - step; b += 2 * step) {
    //             uint32_t low = b;
    //             uint32_t high = b + step;
    //             // G_new = G_high | (E_high & G_low)
    //             auto tempAnd = EvalBinGateSEV(ccLWE, AND, E[high], G[low]);
    //             G[low] = EvalBinGateSEV(ccLWE, OR, G[high], tempAnd);
    //             E[low] = EvalBinGateSEV(ccLWE, AND, E[high], E[low]);
    //         }
    //         step *= 2;
    //     }

    //     // [Step 3] 최종 결과에 대해서만 Refresh 수행 (소켓 경합 최소화)
    //     // 연산이 끝난 후 한 번만 호출함으로써 소켓 충돌 리스크를 대폭 줄임
    //     auto finalGt = G[0];
    //     maskBits[i] = sev_refresh_lwe(ccLWE, finalGt, sev_sock);
    // }

    std::cout << "[TIME] Stage 7: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 8: LWE mask -> RLWE (SEV) and multiply");
    // =================================
    // 4. Make Mask of Data and multiply
    // =================================
    const size_t lwe_ct_u64 = static_cast<size_t>(ccLWE->GetParams()->GetLWEParams()->Getn()) + 1;
    const size_t sev_slots = SEV_N / 2;
    std::vector<uint64_t> lwe_batch(sev_slots * lwe_ct_u64, 0);
    auto zeroCoeffs = extractLWECiphertextCoeffs(ctZero);
    for (size_t s = 0; s < sev_slots; ++s) {
        std::copy(zeroCoeffs.begin(), zeroCoeffs.end(),
                  lwe_batch.begin() + (s * lwe_ct_u64));
    }
    for (size_t i = 0; i < len; ++i) {
        auto coeffs = extractLWECiphertextCoeffs(maskBits[i]);
        std::copy(coeffs.begin(), coeffs.end(),
                  lwe_batch.begin() + (i * lwe_ct_u64));
    }
    std::vector<uint64_t> out_coeff(coeffCount, 0);
    sev_remote_lwe_dec_slot_enc(sev_sock, lwe_batch.data(), lwe_batch.size(),
                                out_coeff.data(), out_coeff.size());
    auto cMask = makeCiphertextFromCoeffs(cc, out_coeff);
    cMask->SetKeyTag(cData->GetKeyTag());
    try {
        Plaintext pMaskDbg;
        timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
                   [&] { cc->Decrypt(keys.secretKey, cMask, &pMaskDbg); });
        pMaskDbg->SetLength(len);
        auto vals = pMaskDbg->GetRealPackedValue();
        // std::cout << "[DBG] dec cMask (first " << len << "): ";
        for (size_t i = 0; i < len && i < vals.size(); ++i)
            std::cout << vals[i] << " ";
        std::cout << std::endl;
    } catch (const std::exception& e) {
        std::cout << "[DBG] dec cMask failed: " << e.what() << std::endl;
    }
    auto cMaskedRaw = timed_call(g_runtime_profile.otherCkksSec,
                                 g_runtime_profile.otherCkksCalls,
                                 [&] { return cc->EvalMult(cData, cMask); });
    auto cMasked = sev_refresh_ciphertext(cMaskedRaw, sev_sock, coeffCount,
                                          cMaskedRaw->GetKeyTag(),
                                          cData->GetScalingFactor(), // 연산 대상과 Scale 정합성 맞춤
                                          "cMaskedRescale");

    std::cout << "[TIME] Stage 8: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 9: EvalSum and add acc");
    // =================================
    // 5. ADD Every Data with EvalSum
    // =================================
    auto cSum = timed_call(g_runtime_profile.otherCkksSec,
                           g_runtime_profile.otherCkksCalls,
                           [&] { return cc->EvalSum(cMasked, len); });
    Plaintext pAcc = timed_call(g_runtime_profile.otherCkksSec,
                                 g_runtime_profile.otherCkksCalls,
                                 [&] { return cc->MakeCKKSPackedPlaintext(accVec, 1, 0, nullptr, slots); });
    auto cAcc = timed_call(g_runtime_profile.otherCkksSec,
                           g_runtime_profile.otherCkksCalls,
                           [&] { return cc->Encrypt(keys.secretKey, pAcc); });
    LOG_STEP("Stage 9.1: Align scales for cAcc + cSum");
    Ciphertext<DCRTPoly> cAccAligned = cAcc;
    Ciphertext<DCRTPoly> cSumAligned = cSum;
    cAccAligned = sev_refresh_ciphertext(cAcc, sev_sock, coeffCount,
                                            cAcc->GetKeyTag(),
                                            cSum->GetScalingFactor(),
                                            "align-acc-to-sum");

    cSumAligned = cSum;
    auto cAccOut = timed_call(g_runtime_profile.otherCkksSec,
                              g_runtime_profile.otherCkksCalls,
                              [&] { return cc->EvalAdd(cAccAligned, cSumAligned); });
    std::cout << "[TIME] Stage 9-9.1: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 9.5: SEV refresh final ciphertext");
    auto cAccOutRef = sev_refresh_ciphertext(cAccOut, sev_sock, coeffCount,
                                             cAccOut->GetKeyTag(),
                                             cAccOut->GetScalingFactor(),
                                             "final-refresh");

    std::cout << "[TIME] Stage 9.5: " << (now_ms() - t_stage) << " ms" << std::endl;
    t_stage = now_ms();
    LOG_STEP("Stage 10: Decrypt result");
    Plaintext pRes;
    try {
        timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
                   [&] { cc->Decrypt(keys.secretKey, cAccOutRef, &pRes); });
    } catch (const std::exception& e) {
        std::cout << "[DBG] dec cAccOut failed: " << e.what() << std::endl;
        throw;
    }
    pRes->SetLength(1);
    std::cout << "[TIME] Stage 10: " << (now_ms() - t_stage) << " ms" << std::endl;

    std::cout << "Result (acc + sum_{i | data[i]>5} data[i]) = "
              << pRes->GetRealPackedValue()[0] << std::endl;
    std::cout << "[TIME] Total: " << (now_ms() - t_total) << " ms" << std::endl;
    std::cout << "Total wall clock (end-to-end): " << ((now_ms() - t_total) / 1000.0) << " s" << std::endl;
    std::cout << "SEV time (s): " << g_sev_remote_time_sec << std::endl;
    print_runtime_profile();

    return 0;
}

bool file_exists(const std::string &filename) {
    std::ifstream file(filename);
    return file.good();
}
