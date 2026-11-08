#include "openfhe.h"
#include "binfhecontext.h"
#include "cryptocontext.h"
#include <fstream>
#include <cstdlib>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

#include "key/keypair.h"
#include "key/privatekey.h"
#include "key/publickey.h"

#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"
#include "binfhecontext.h"
#include "binfhecontext-ser.h"

#include "resnet.h"
#include "dataset.h"
#include "packed_conv.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

using namespace lbcrypto;

static double g_sev_remote_time_sec = 0.0;
static double g_sev_conv_reencrypt_time_sec = 0.0;
static double g_ckks_bootstrap_time_sec = 0.0;
static double g_last_ckks_bootstrap_time_sec = 0.0;
static uint64_t g_ckks_bootstrap_calls = 0;
static double g_last_ckks_to_fhew_time_sec = 0.0;
static double g_last_fhew_to_ckks_time_sec = 0.0;
static const size_t MUEOC_SEV_LEVEL = 2;
static const uint32_t CKKS_BOOTSTRAP_MULT_DEPTH = 18;
static const uint32_t CKKS_BOOTSTRAP_CORRECTION_FACTOR = 20;
static const uint32_t MUEOC_MULT_DEPTH = CKKS_BOOTSTRAP_MULT_DEPTH;

static void log_ct_stats(const char* label, ConstCiphertext<DCRTPoly> ct) {
    if (!ct) {
        std::cerr << "[CT] " << label << ": null\n";
        return;
    }
    const auto& elements = ct->GetElements();
    size_t towers = elements.empty() ? 0 : elements[0].GetNumOfElements();
    std::cerr << "[CT] " << label
              << " level=" << ct->GetLevel()
              << " towers=" << towers
              << " noiseScaleDeg=" << ct->GetNoiseScaleDeg()
              << " scale=" << ct->GetScalingFactor()
              << " slots=" << ct->GetSlots()
              << " keyTag='" << ct->GetKeyTag() << "'\n";
}

static Ciphertext<DCRTPoly> normalize_sev_scale_metadata(ConstCiphertext<DCRTPoly> ct) {
    auto out = ct->Clone();
    static const double kSevScale = std::pow(2.0, 40);
    out->SetScalingFactor(kSevScale);
    out->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(kSevScale)));
    out->SetNoiseScaleDeg(1);
    return out;
}

static Ciphertext<DCRTPoly> compress_to_sev_towers(CryptoContext<DCRTPoly> cc, ConstCiphertext<DCRTPoly> ct) {
    if (!ct->GetElements().empty() && ct->GetElements()[0].GetNumOfElements() > MUEOC_SEV_LEVEL) {
        return cc->Compress(ct, MUEOC_SEV_LEVEL);
    }
    return ct->Clone();
}

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

Ciphertext<DCRTPoly> makeCiphertextFromCoeffs(CryptoContext<DCRTPoly> cc, const std::vector<uint64_t>& buffer,
                                              const std::string& keyTag = "") {
    auto elemParams         = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t fullNumTowers    = towerParams.size();
    size_t numTowers        = MUEOC_SEV_LEVEL;
    size_t ringDim          = elemParams->GetRingDimension();

    // for (const auto& p : elemParams->GetParams())
    //     std::cout << p->GetModulus() << std::endl;

    if (fullNumTowers < MUEOC_SEV_LEVEL) {
        throw std::runtime_error("CKKS context does not have enough towers for SEV ciphertext");
    }

    size_t expectedSize = 2 * MUEOC_SEV_LEVEL * ringDim;
    if (buffer.size() != expectedSize) {
        throw std::runtime_error("Coefficient buffer size does not match ciphertext dimensions");
    }

    auto ciphertextImpl = std::make_shared<CiphertextImpl<DCRTPoly>>(cc);
    std::vector<DCRTPoly> elements;
    elements.reserve(2);
    // std::cout << "makecoeff1" << std::endl;
    size_t offset = 0;
    for (size_t comp = 0; comp < 2; ++comp) {
        DCRTPoly poly(elemParams, Format::EVALUATION, true);
        if (fullNumTowers > MUEOC_SEV_LEVEL) {
            poly.DropLastElements(fullNumTowers - MUEOC_SEV_LEVEL);
        }
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
    ciphertextImpl->SetLevel(fullNumTowers - MUEOC_SEV_LEVEL);
    ciphertextImpl->SetNoiseScaleDeg(1);

    static const double kSevScale = std::pow(2.0, 40);
    ciphertextImpl->SetScalingFactor(kSevScale);
    ciphertextImpl->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(kSevScale)));
    ciphertextImpl->SetSlots(ringDim / 2);
    if (!keyTag.empty()) {
        ciphertextImpl->SetKeyTag(keyTag);
    }

    return ciphertextImpl;
}

LWECiphertext makeLWECiphertextFromCoeffs(const std::shared_ptr<BinFHEContext>& ccLWE,
                                          const std::vector<uint64_t>& buffer) {
    auto lweParams      = ccLWE->GetParams()->GetLWEParams();
    size_t n            = lweParams->Getn();
    NativeInteger q     = lweParams->Getq();
    size_t expectedSize = n + 1;

    if (buffer.size() != expectedSize) {
        throw std::runtime_error("LWE coefficient buffer size mismatch, expected " + std::to_string(expectedSize) +
                                 ", got " + std::to_string(buffer.size()));
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
// Fast add-only gate eval (no bootstrap), mirrors BinFHEScheme::EvalBinGate up to the accumulator.
static LWECiphertext EvalBinGateSEV(const std::shared_ptr<BinFHEContext>& ccLWE, BINGATE gate, ConstLWECiphertext& ct1,
                                    ConstLWECiphertext& ct2) {
    if (ccLWE == nullptr)
        OPENFHE_THROW("BinFHEContext is empty");
    const auto& params = ccLWE->GetParams();
    if (params == nullptr)
        OPENFHE_THROW("BinFHECryptoParams is empty");
    if (ct1 == nullptr)
        OPENFHE_THROW("Ciphertext1 is empty");
    if (ct2 == nullptr)
        OPENFHE_THROW("Ciphertext2 is empty");
    if (ct1 == ct2)
        OPENFHE_THROW("Input ciphertexts should be independant");

    const auto& LWEParams = params->GetLWEParams();
    NativeInteger Q{LWEParams->GetQ()};
    auto lweScheme = ccLWE->GetLWEScheme();
    if (lweScheme == nullptr)
        OPENFHE_THROW("LWE scheme is empty");

    auto cct1       = (Q == ct1->GetModulus()) ? lweScheme->SwitchCTtoqn(LWEParams, ccLWE->GetSwitchKey(), ct1) :
                                                 std::make_shared<LWECiphertextImpl>(*ct1);
    const auto cct2 = (Q == ct2->GetModulus()) ? lweScheme->SwitchCTtoqn(LWEParams, ccLWE->GetSwitchKey(), ct2) : ct2;

    if ((gate == XOR) || (gate == XNOR) || (gate == XOR_FAST) || (gate == XNOR_FAST)) {
        lweScheme->EvalAddEq(cct1, cct2);
        lweScheme->EvalAddEq(cct1, cct1);
    }
    else {
        lweScheme->EvalAddEq(cct1, cct2);
    }

    return cct1;
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

static LWEPrivateKey makeLweSecretKeyFromCoeffs(const std::shared_ptr<BinFHEContext>& ccLWE,
                                                const std::vector<uint64_t>& coeffs) {
    auto lweParams  = ccLWE->GetParams()->GetLWEParams();
    size_t n        = lweParams->Getn();
    NativeInteger q = lweParams->Getq();
    if (coeffs.size() != n) {
        throw std::runtime_error("SEV LWE key size mismatch, expected " + std::to_string(n) + ", got " +
                                 std::to_string(coeffs.size()));
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

static PrivateKey<DCRTPoly> makeSecretKeyFromCoeffs(CryptoContext<DCRTPoly> cc, const std::vector<uint64_t>& coeffs,
                                                    const PublicKey<DCRTPoly>& pk) {
    auto elemParams         = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers        = towerParams.size();
    size_t ringDim          = elemParams->GetRingDimension();

    if (coeffs.size() != numTowers * ringDim) {
        throw std::runtime_error("SEV secret key size mismatch with current crypto parameters");
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

void parameterSetupAndKeyLoadOrGen(CryptoContext<DCRTPoly>& cc, std::shared_ptr<lbcrypto::BinFHEContext>& ccLWE,
                                   KeyPair<DCRTPoly>& keys, LWEPrivateKey& privateKeyFHEW,
                                   const std::vector<uint64_t>& sevSecretCoeffs) {
    // Specify main parameters

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;

    // uint32_t levelsAvailableAfterBootstrap = 14;
    std::vector<uint32_t> levelBudget = {2, 2};
    //usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    // uint32_t depth = 2;

    uint32_t multDepth    = MUEOC_MULT_DEPTH;
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 40;
    uint32_t ringDim      = 65536;
    SecurityLevel sl      = HEStd_NotSet;
    //BINFHE_PARAMSET slBin = TOY;    //TODO : Change to large parameter... dont use toy parameter
    //SecurityLevel sl      = HEStd_128_classic;
    BINFHE_PARAMSET slBin = STD128;
    uint32_t logQ_ccLWE   = 11;
    uint32_t slots        = ringDim / 2;  // Uncomment for fully-packed
    //uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetNumLargeDigits(3);

    cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Dump the NTT base psi values for each RNS tower to compare with the SEV engine.
    auto elemParams    = cc->GetCryptoParameters()->GetElementParams();
    const auto& towers = elemParams->GetParams();
    for (size_t t = 0; t < towers.size(); ++t) {
        auto mod = towers[t]->GetModulus();
        auto psi = towers[t]->GetRootOfUnity();
        auto w   = psi.ModMul(psi, mod);  // w = psi^2 mod q
        std::cout << "[OpenFHE] tower " << t << " modulus " << mod.ToString() << " psi " << psi.ToString() << " w "
                  << w.ToString() << std::endl;
    }

    // Generate encryption keys
    std::string pkFile = "public.key";
    std::string skFile = "secret.key";
    std::string mkFile = "mult.key";
    std::string rkFile = "rot.key";

    std::string lweSkFile = "lwesk_mueoc_lut.key";

    //TFHE Evks
    std::string refKeyFile = "ref_mueoc_lut.key";
    std::string kswKeyFile = "ksw_mueoc_lut.key";

    //CryptoContext
    std::string ccFile = "cc.key";

    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;

    bool ccNotLoaded = true;
    std::cout << "Using freshly generated cc with CKKS bootstrap parameters" << std::endl;

    //Load or generate keys ...
    if (file_exists(pkFile) && file_exists(skFile) && file_exists(mkFile) && file_exists(rkFile)) {
        std::cout << "Public/evaluation keys found, loading from disk" << std::endl;
        try {
            std::ifstream pkif(pkFile, std::ios::binary);
            std::ifstream skif(skFile, std::ios::binary);
            std::ifstream multKeyIStream(mkFile, std::ios::in | std::ios::binary);
            std::ifstream rotKeyIStream(rkFile, std::ios::in | std::ios::binary);

            Serial::Deserialize(pk, pkif, SerType::BINARY);
            Serial::Deserialize(sk, skif, SerType::BINARY);
            cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY);
            cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY);

            keys.publicKey = pk;
            keys.secretKey = sk;
        }
        catch (const std::exception& e) {
            std::cout << "Failed to load key files" << std::endl;
            throw;
        }
    }
    else {
        throw std::runtime_error("public.key/secret.key/mult.key/rot.key not found. Regenerate keys with matching MUEOC depth.");
    }

    std::cout << "SEV secret key received for engine boundary (" << sevSecretCoeffs.size() << " coefficients)" << std::endl;

    std::vector<uint32_t> bootstrapLevelBudget = {2, 2};
    std::vector<uint32_t> bootstrapBsgsDim     = {0, 0};
    cc->EvalBootstrapSetup(bootstrapLevelBudget, bootstrapBsgsDim, slots, CKKS_BOOTSTRAP_CORRECTION_FACTOR);
    cc->EvalBootstrapKeyGen(keys.secretKey, slots);

    SchSwchParams params;
    params.SetSecurityLevelCKKS(sl);
    params.SetSecurityLevelFHEW(slBin);
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);

    privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
    //ccLWE  = (cc->GetBinCCForSchemeSwitch());

    bool haveLweSk = Serial::DeserializeFromFile(lweSkFile, privateKeyFHEW, SerType::BINARY);
    if (!haveLweSk) {
        //privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
        Serial::SerializeToFile(lweSkFile, privateKeyFHEW, SerType::BINARY);
    }
    ccLWE = (cc->GetBinCCForSchemeSwitch());
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    //bool haveSchemeSwitchData = false;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << "Ptxt Space :  " << ccLWE->GetMaxPlaintextSpace().ConvertToInt() << std::endl;

    // Compute the scaling factor to decrypt correctly in FHEW; under the hood, the LWE mod switch will performed on the ciphertext at the last level
    auto pLWE1 = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    // auto modulus_LWE = 1 << logQ_ccLWE;
    // auto beta        = ccLWE->GetBeta().ConvertToInt();
    // auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision

    double scale1 = 1.0 / pLWE1;
    // double scale2 = 1.0 / pLWE2;

    // Perform the precomputation for switching
    cc->EvalCKKStoFHEWPrecompute(scale1);
    if (ccNotLoaded) {
        std::cout << "Load cc failed, generating ..." << std::endl;
        Serial::SerializeToFile(ccFile, cc, SerType::BINARY);
    }

    RingGSWACCKey refreshKey;
    LWESwitchingKey ksKey;

    std::cout << "Loading TFHE Evks " << kswKeyFile << std::endl;
    try {
        if (Serial::DeserializeFromFile(refKeyFile, refreshKey, SerType::BINARY) == false) {
            throw std::invalid_argument("refKeyFile Error");
        }
        if (Serial::DeserializeFromFile(kswKeyFile, ksKey, SerType::BINARY) == false) {
            throw std::invalid_argument("kswKeyFile Error");
        }

        ccLWE->BTKeyLoad({refreshKey, ksKey});
        std::cout << "TFHE Evks Loaded " << kswKeyFile << std::endl;
    }
    catch (const std::exception& e) {
        std::cout << "Failed to load TFHE Evks" << kswKeyFile << std::endl;
        std::cout << "Generating ..." << std::endl;

        ccLWE->BTKeyGen(privateKeyFHEW);

        std::cout << "Saving TFHE Evks to " << kswKeyFile << std::endl;

        if (Serial::SerializeToFile(refKeyFile, ccLWE->GetRefreshKey(), SerType::BINARY) == false) {
            std::cerr << "Error serializing the refreshing key" << std::endl;
        }
        if (Serial::SerializeToFile(kswKeyFile, ccLWE->GetSwitchKey(), SerType::BINARY) == false) {
            std::cerr << "Error serializing the ksw key" << std::endl;
        }
    }
}

#include "sev_functions.h"
#include "cheetah_encrypted.h"

static const size_t CKKS_N = 32768;

#include "sev_masking.h"

struct FeatureMap {
    int H = 0, W = 0;
    int C      = 0;
    int chunkC = 1;
    std::vector<Ciphertext<DCRTPoly>> ct;
};

struct FeatureMapMeta {
    int H;
    int W;
    int C;
    int chunkC;
};

static Ciphertext<DCRTPoly> bootstrap_before_scheme_conversion(CryptoContext<DCRTPoly> cc,
                                                               ConstCiphertext<DCRTPoly> ct) {
    auto t0  = std::chrono::high_resolution_clock::now();
    auto out = cc->EvalBootstrap(ct);
    auto t1  = std::chrono::high_resolution_clock::now();
    double sec = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    g_ckks_bootstrap_time_sec += sec;
    g_last_ckks_bootstrap_time_sec += sec;
    ++g_ckks_bootstrap_calls;
    return out;
}

static inline int ceil_div(int a, int b) {
    return (a + b - 1) / b;
}

static inline int choose_chunk_by_hw(int H, int W, int C) {
    int maxChunk = static_cast<int>(CKKS_N / std::max(1, H * W));
    maxChunk     = std::max(1, maxChunk);
    return std::min(C, maxChunk);
}

static inline int choose_mchunk(int H, int W, int CinChunk, int K, int N, int maxWant) {
    long long extra = 1LL * W * (K - 1) + (K - 1);
    for (int m = maxWant; m >= 1; --m) {
        long long need = 1LL * H * W * (1LL * m * CinChunk) + extra;
        if (need <= N)
            return m;
    }
    return 1;
}

using Kernel4D = std::vector<std::vector<std::vector<std::vector<int>>>>;

static Kernel4D rand_kernel(int M, int C, int K, std::mt19937& rng, int lo = -1, int hi = 1) {
    std::uniform_int_distribution<int> dist(lo, hi);
    Kernel4D k(M,
               std::vector<std::vector<std::vector<int>>>(C, std::vector<std::vector<int>>(K, std::vector<int>(K, 0))));
    for (int m = 0; m < M; ++m)
        for (int c = 0; c < C; ++c)
            for (int kh = 0; kh < K; ++kh)
                for (int kw = 0; kw < K; ++kw)
                    k[m][c][kh][kw] = dist(rng);
    return k;
}

struct KernelPack {
    ConvParam cp_enc;
    Plaintext ptxt_kernel;
};

struct KernelCache {
    int H_in;
    int W_in;
    int CinChunk;
    int Cout;
    int K;
    int stride;
    int H_out;
    int W_out;
    int Mchunk;
    int inGroups;
    int outGroups;
    std::vector<KernelPack> kernel_packs;
};

struct KernelCacheKey {
    const Kernel4D* wptr;
    int H_in;
    int W_in;
    int CinChunk;
    int Cout;
    int K;
    int stride;

    bool operator==(const KernelCacheKey& other) const {
        return wptr == other.wptr && H_in == other.H_in && W_in == other.W_in && CinChunk == other.CinChunk &&
               Cout == other.Cout && K == other.K && stride == other.stride;
    }
};

static inline void hash_combine(std::size_t& seed, std::size_t v) {
    seed ^= v + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

struct KernelCacheKeyHash {
    std::size_t operator()(const KernelCacheKey& k) const {
        std::size_t seed = 0;
        hash_combine(seed, std::hash<const Kernel4D*>{}(k.wptr));
        hash_combine(seed, std::hash<int>{}(k.H_in));
        hash_combine(seed, std::hash<int>{}(k.W_in));
        hash_combine(seed, std::hash<int>{}(k.CinChunk));
        hash_combine(seed, std::hash<int>{}(k.Cout));
        hash_combine(seed, std::hash<int>{}(k.K));
        hash_combine(seed, std::hash<int>{}(k.stride));
        return seed;
    }
};

static std::unordered_map<KernelCacheKey, KernelCache, KernelCacheKeyHash> g_kernel_cache;

static KernelCache build_kernel_cache(CryptoContext<DCRTPoly> cc, const Kernel4D& Wfull, int Cout, int K, int stride,
                                      int H_in, int W_in, int CinChunk) {
    KernelCache cache;
    cache.H_in     = H_in;
    cache.W_in     = W_in;
    cache.CinChunk = CinChunk;
    cache.Cout     = Cout;
    cache.K        = K;
    cache.stride   = stride;

    const int Cin = static_cast<int>(Wfull[0].size());
    const int P   = (K == 3 ? 1 : 0);

    ConvParam cp;
    cp.H             = H_in;
    cp.W             = W_in;
    cp.inputChannel  = Cin;
    cp.outputChannel = Cout;
    cp.kernelSize    = K;
    cp.stride        = stride;
    cp.padding       = P;

    calculate_output_dimensions_pad(cp, cache.H_out, cache.W_out);

    ConvParam cp_local = cp;
    cp_local.padding   = 0;

    int maxWant     = choose_chunk_by_hw(cp.H, cp.W, Cout);
    cache.Mchunk    = choose_mchunk(cp.H, cp.W, CinChunk, K, CKKS_N, maxWant);
    cache.Mchunk    = std::max(1, std::min(cache.Mchunk, Cout));
    cache.inGroups  = ceil_div(Cin, CinChunk);
    cache.outGroups = ceil_div(Cout, cache.Mchunk);
    cache.kernel_packs.resize((size_t)cache.outGroups * cache.inGroups);

#pragma omp parallel for
    for (int og = 0; og < cache.outGroups; ++og) {
        const int m0    = og * cache.Mchunk;
        const int thisM = std::min(cache.Mchunk, Cout - m0);

        for (int ig = 0; ig < cache.inGroups; ++ig) {
            const int c0    = ig * CinChunk;
            const int thisC = std::min(CinChunk, Cin - c0);

            ConvParam cp_enc     = cp_local;
            cp_enc.inputChannel  = thisC;
            cp_enc.outputChannel = thisM;

            Kernel4D Wslice(thisM, std::vector<std::vector<std::vector<int>>>(
                                       thisC, std::vector<std::vector<int>>(K, std::vector<int>(K))));
            for (int mm = 0; mm < thisM; ++mm)
                for (int cc_i = 0; cc_i < thisC; ++cc_i)
                    for (int kh = 0; kh < K; ++kh)
                        for (int kw = 0; kw < K; ++kw)
                            Wslice[mm][cc_i][kh][kw] = Wfull[m0 + mm][c0 + cc_i][kh][kw];

            std::vector<double> encoded_kernel;
            cheetah_encode_kernel(cp_enc, CKKS_N, Wslice, encoded_kernel);

            KernelPack kp;
            kp.cp_enc      = cp_enc;
            kp.ptxt_kernel = cc->MakeCKKSPackedPlaintext(encoded_kernel, 1, 0, nullptr);
            cache.kernel_packs[(size_t)og * cache.inGroups + ig] = kp;
        }
    }

    return cache;
}

static const KernelCache& get_or_build_kernel_cache(CryptoContext<DCRTPoly> cc, const Kernel4D& Wfull, int Cout, int K,
                                                    int stride, int H_in, int W_in, int CinChunk) {
    KernelCacheKey key{&Wfull, H_in, W_in, CinChunk, Cout, K, stride};
    auto it = g_kernel_cache.find(key);
    if (it == g_kernel_cache.end()) {
        it = g_kernel_cache.emplace(key, build_kernel_cache(cc, Wfull, Cout, K, stride, H_in, W_in, CinChunk)).first;
    }
    return it->second;
}

static FeatureMapMeta precompute_conv_cache(CryptoContext<DCRTPoly> cc, const Kernel4D& Wfull, int Cout, int K,
                                            int stride, const FeatureMapMeta& x) {
    get_or_build_kernel_cache(cc, Wfull, Cout, K, stride, x.H, x.W, x.chunkC);
    FeatureMapMeta y;
    y.H         = x.H;
    y.W         = x.W;
    y.C         = Cout;
    y.chunkC    = x.chunkC;
    const int P = (K == 3 ? 1 : 0);
    ConvParam cp;
    cp.H             = x.H;
    cp.W             = x.W;
    cp.inputChannel  = x.C;
    cp.outputChannel = Cout;
    cp.kernelSize    = K;
    cp.stride        = stride;
    cp.padding       = P;
    calculate_output_dimensions_pad(cp, y.H, y.W);
    return y;
}

static FeatureMap build_input_featuremap_from_plain(int sev_sock, CryptoContext<DCRTPoly> cc,
                                                    const std::vector<double>& image_chw, int H, int W, int C,
                                                    int chunkC, const std::string& keyTag) {
    FeatureMap x;
    x.H      = H;
    x.W      = W;
    x.C      = C;
    x.chunkC = chunkC;

    int groups = ceil_div(C, chunkC);
    x.ct.resize(groups);

    std::vector<uint64_t> tmp_coeff(coeffCount, 0);

    for (int g = 0; g < groups; ++g) {
        int c0    = g * chunkC;
        int thisC = std::min(chunkC, C - c0);

        std::vector<double> plain;
        plain.assign((size_t)thisC * H * W, 0.0);

        for (int ch = 0; ch < thisC; ++ch) {
            for (int i = 0; i < H * W; ++i) {
                plain[(size_t)ch * H * W + i] = image_chw[(size_t)(c0 + ch) * H * W + i];
            }
        }

        std::vector<double> buf(coeffCount, 0.0);
        size_t used = std::min(buf.size(), plain.size());
        std::copy(plain.begin(), plain.begin() + used, buf.begin());
        auto t0 = std::chrono::high_resolution_clock::now();
        sev_remote_reenc_coeff_enc(sev_sock, buf.data(), coeffCount, tmp_coeff.data());
        auto t1 = std::chrono::high_resolution_clock::now();
        g_sev_remote_time_sec += std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
        x.ct[g] = makeCiphertextFromCoeffs(cc, tmp_coeff, keyTag);
    }

    return x;
}

static Ciphertext<DCRTPoly> sev_reencrypt_ciphertext_masked(int sev_sock, CryptoContext<DCRTPoly> cc,
                                                            ConstCiphertext<DCRTPoly> ct, uint64_t maskSeed) {
    auto ctForSev = compress_to_sev_towers(cc, ct);

    std::vector<double> mask(CKKS_N, 0.0);
    std::mt19937_64 rng(maskSeed);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    for (double& v : mask) {
        v = dist(rng);
    }

    auto pMask = cc->MakeCKKSPackedPlaintext(mask, ctForSev->GetNoiseScaleDeg(), ctForSev->GetLevel(), nullptr, CKKS_N);
    auto masked = cc->EvalAdd(ctForSev, pMask);
    auto maskedForSev = compress_to_sev_towers(cc, masked);

    std::vector<uint64_t> in_coeff = extractCiphertextCoeffs(maskedForSev);
    std::vector<uint64_t> out_coeff(coeffCount, 0);

    bool ok = false;
    double remoteSeconds = 0.0;
#pragma omp critical(sev_remote_reencrypt_masked)
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        ok = sev_remote_reenc_coeff_rescale(sev_sock, in_coeff.data(), coeffCount,
                                            static_cast<long double>(maskedForSev->GetScalingFactor()),
                                            static_cast<long double>(maskedForSev->GetScalingFactor()),
                                            out_coeff.data());
        auto t1 = std::chrono::high_resolution_clock::now();
        remoteSeconds = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    }
#pragma omp atomic
    g_sev_remote_time_sec += remoteSeconds;
#pragma omp atomic
    g_sev_conv_reencrypt_time_sec += remoteSeconds;
    if (!ok) {
        throw std::runtime_error("SEV masked RLWE reencrypt failed");
    }

    auto reenced = makeCiphertextFromCoeffs(cc, out_coeff, ct->GetKeyTag());
    reenced->SetScalingFactor(maskedForSev->GetScalingFactor());
    reenced->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(maskedForSev->GetScalingFactor())));
    reenced->SetNoiseScaleDeg(maskedForSev->GetNoiseScaleDeg());
    reenced->SetSlots(maskedForSev->GetSlots());

    auto unmasked = cc->EvalSub(reenced, pMask);
    unmasked->SetKeyTag(ct->GetKeyTag());
    return normalize_sev_scale_metadata(unmasked);
}

// =========================
// SEV + LWE ReLU on one CKKS ciphertext (your MSB-masking method)
// =========================
static NativeInteger scheme_switch_sign_lut_small_precision(NativeInteger m, NativeInteger p) {
    return (m < (p >> 1)) ? (p - 1) : NativeInteger(1);
}

static Ciphertext<DCRTPoly> relu_sev_lwe_one_ct(int sev_sock, CryptoContext<DCRTPoly> cc,
                                                std::shared_ptr<lbcrypto::BinFHEContext> ccLWE,
                                                const Ciphertext<DCRTPoly>& x,
                                                std::vector<uint64_t>& tmp_rlwe_coeff,  // coeffCount
                                                std::vector<double>& tmp_dec,           // CKKS_N
                                                std::vector<uint64_t>& tmp_lwe_coeffs,  // CKKS_N*SEV_LWE_CT*64
                                                std::vector<LWECiphertext>& ct_lwe      // CKKS_N*64
) {
    (void)sev_sock;
    (void)tmp_rlwe_coeff;
    (void)tmp_dec;
    (void)tmp_lwe_coeffs;
    (void)ct_lwe;

    try {
        log_ct_stats("relu input", x);
        auto xForCompare = normalize_sev_scale_metadata(x);
        log_ct_stats("relu xForCompare", xForCompare);
        auto zero = cc->EvalSub(xForCompare, xForCompare);
        log_ct_stats("relu zero", zero);
        auto cDiff = cc->EvalSub(zero, xForCompare);
        log_ct_stats("relu diff", cDiff);

        cc->EvalCKKStoFHEWPrecompute(1.0 / 4.0);
        constexpr uint32_t numSchemeSwitchSlots = 16384;
        std::cerr << "[DBG] relu EvalCKKStoFHEW start num=" << numSchemeSwitchSlots << "\n";
        auto ckksToFhewStart = std::chrono::high_resolution_clock::now();
        auto lweCiphertexts = cc->EvalCKKStoFHEW(cDiff, numSchemeSwitchSlots);
        auto ckksToFhewEnd = std::chrono::high_resolution_clock::now();
        g_last_ckks_to_fhew_time_sec +=
            std::chrono::duration_cast<std::chrono::duration<double>>(ckksToFhewEnd - ckksToFhewStart).count();
        std::cerr << "[DBG] relu EvalCKKStoFHEW done count=" << lweCiphertexts.size() << "\n";
        if (!lweCiphertexts.empty()) {
            auto lweQ = ccLWE->GetParams()->GetLWEParams()->Getq();
            auto beta = ccLWE->GetBeta();
            auto mod  = lweCiphertexts[0]->GetModulus();
            auto pLWE = mod.ConvertToInt() / (2 * beta.ConvertToInt());
            std::cerr << "[DBG] relu LWE ct_mod=" << mod
                      << " ccLWE_q=" << lweQ
                      << " beta=" << beta
                      << " pLWE=" << pLWE << "\n";
        }

        auto signLUT = ccLWE->GenerateLUTviaFunction(scheme_switch_sign_lut_small_precision, 4);
        std::vector<LWECiphertext> cSigns(lweCiphertexts.size());
        for (uint32_t i = 0; i < lweCiphertexts.size(); ++i) {
            try {
                cSigns[i] = ccLWE->EvalFunc(lweCiphertexts[i], signLUT);
            }
            catch (const std::exception& e) {
                std::cerr << "[ERR] relu EvalFunc sign LUT failed at i=" << i << ": " << e.what() << "\n";
                throw;
            }
        }
        std::cerr << "[DBG] relu EvalFunc sign LUT done\n";

        auto fhewToCkksStart = std::chrono::high_resolution_clock::now();
        auto mask = cc->EvalFHEWtoCKKS(cSigns, numSchemeSwitchSlots, CKKS_N, 4, -1.0, 1.0, 0);
        auto fhewToCkksEnd = std::chrono::high_resolution_clock::now();
        g_last_fhew_to_ckks_time_sec +=
            std::chrono::duration_cast<std::chrono::duration<double>>(fhewToCkksEnd - fhewToCkksStart).count();
        log_ct_stats("relu mask", mask);
        auto xAligned = xForCompare->Clone();
        cc->GetScheme()->AdjustLevelsAndDepthInPlace(xAligned, mask);
        log_ct_stats("relu xAligned", xAligned);
        auto out = cc->EvalMult(xAligned, mask);
        log_ct_stats("relu mult", out);
        auto res = normalize_sev_scale_metadata(out);
        log_ct_stats("relu output", res);
        return res;
    }
    catch (const std::exception& e) {
        std::cerr << "[ERR] relu_sev_lwe_one_ct failed: " << e.what() << "\n";
        log_ct_stats("relu failed input", x);
        throw;
    }
}

static FeatureMap relu_featuremap(int sev_sock, CryptoContext<DCRTPoly> cc,
                                  std::shared_ptr<lbcrypto::BinFHEContext> ccLWE, const FeatureMap& x) {
    FeatureMap y = x;
    g_last_ckks_bootstrap_time_sec = 0.0;
    g_last_ckks_to_fhew_time_sec = 0.0;
    g_last_fhew_to_ckks_time_sec = 0.0;

    std::vector<uint64_t> tmp_rlwe_coeff(coeffCount);
    std::vector<double> tmp_dec(CKKS_N);
    std::vector<uint64_t> tmp_lwe_coeffs;
    std::vector<LWECiphertext> ct_lwe;

    for (auto& ct : y.ct) {
        ct = bootstrap_before_scheme_conversion(cc, ct);
        ct = relu_sev_lwe_one_ct(sev_sock, cc, ccLWE, ct, tmp_rlwe_coeff, tmp_dec, tmp_lwe_coeffs, ct_lwe);
    }
    return y;
}

static FeatureMap conv_featuremap_cheetah(int sev_sock, CryptoContext<DCRTPoly> cc, const FeatureMap& x,
                                          const Kernel4D& Wfull, int Cout, int K, int stride) {
    const KernelCache& cache = get_or_build_kernel_cache(cc, Wfull, Cout, K, stride, x.H, x.W, x.chunkC);

    FeatureMap y;
    y.H      = cache.H_out;
    y.W      = cache.W_out;
    y.C      = Cout;
    y.chunkC = cache.Mchunk;
    y.ct.resize(cache.outGroups);

    std::cout << "CT count: in=" << cache.inGroups << " out=" << cache.outGroups << " (Cin=" << x.C << " Cout=" << Cout
              << " CinChunk=" << x.chunkC << " Mchunk=" << cache.Mchunk << " HxW=" << x.H << "x" << x.W << ")"
              << std::endl;

#pragma omp parallel for
    for (int og = 0; og < cache.outGroups; ++og) {
        Ciphertext<DCRTPoly> acc = nullptr;

        for (int ig = 0; ig < cache.inGroups; ++ig) {
            const KernelPack& kp = cache.kernel_packs[(size_t)og * cache.inGroups + ig];
            auto cr              = cc->EvalMult(x.ct[ig], kp.ptxt_kernel);

            auto cr_shift1  = cc->GetScheme()->MultByMonomial(cr, 1);
            cr              = cc->EvalAdd(cr, cr_shift1);
            auto cr_shift_W = cc->GetScheme()->MultByMonomial(cr, cache.W_out);
            cr              = cc->EvalAdd(cr, cr_shift_W);

            auto part = cheetah_extract_conv(cc, kp.cp_enc, CKKS_N, cr);
            acc       = acc ? cc->EvalAdd(acc, part) : part;
        }

        y.ct[og] = sev_reencrypt_ciphertext_masked(sev_sock, cc, acc,
                                                   0x9e3779b97f4a7c15ULL ^ static_cast<uint64_t>(og));
    }

    return y;
}

static FeatureMap avgpool_featuremap(CryptoContext<DCRTPoly> cc, const FeatureMap& x, int k, int stride) {
    FeatureMap y = x;
    y.H          = (x.H - k) / stride + 1;
    y.W          = (x.W - k) / stride + 1;
    y.ct.resize(x.ct.size());

    ConvParam cp;
    cp.kernelSize = k;
    cp.stride     = stride;
    cp.padding    = 0;

    for (size_t i = 0; i < x.ct.size(); ++i) {
        int c0           = static_cast<int>(i) * x.chunkC;
        int thisC        = std::min(x.chunkC, x.C - c0);
        cp.H             = x.H;
        cp.W             = x.W;
        cp.inputChannel  = thisC;
        cp.outputChannel = thisC;
        y.ct[i]          = cheetah_extract_avgpool(cc, cp, CKKS_N, x.ct[i], x.H, x.W, thisC, k, stride);
    }

    return y;
}

static FeatureMap adaptive_avgpool_2x2(CryptoContext<DCRTPoly> cc, const FeatureMap& x) {
    if (x.H < 2 || x.W < 2 || x.H != x.W || (x.H % 2) != 0) {
        OPENFHE_THROW("adaptive_avgpool_2x2 expects square even spatial dims");
    }
    int k = x.H / 2;
    return avgpool_featuremap(cc, x, k, k);
}

int main() {
    int sev_sock = connect_to_sev(SEV_VM_IP, SEV_VM_PORT);
    if (sev_sock < 0) {
        std::cerr << "Failed to connect to SEV VM\n";
        return 1;
    }
    std::vector<uint64_t> sevSecretCoeffs;
    try {
        sevSecretCoeffs = recv_sev_secret_key(sev_sock);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to receive SEV secret key: " << e.what() << "\n";
        ::close(sev_sock);
        return 1;
    }
    std::cout << "SEV VM connected\n";

    CryptoContext<DCRTPoly> cc;
    std::shared_ptr<lbcrypto::BinFHEContext> ccLWE1;
    KeyPair<DCRTPoly> keys;
    LWEPrivateKey privateKeyFHEW;

    LOG_STEP("Starting parameter setup and key load/gen");
    parameterSetupAndKeyLoadOrGen(cc, ccLWE1, keys, privateKeyFHEW, sevSecretCoeffs);
    LOG_STEP("Finished parameter setup and key load/gen");
    (void)keys;

    auto ccLWE = std::make_shared<BinFHEContext>();
    ccLWE->GenerateBinFHEContext(STD128, GINX);
    std::cout << "[LWE] q=" << ccLWE->GetParams()->GetLWEParams()->Getq()
              << " n=" << ccLWE->GetParams()->GetLWEParams()->Getn() << std::endl;
    std::vector<uint64_t> sevLweSecretCoeffs(SEV_LWE_N);
    for (size_t i = 0; i < SEV_LWE_N; ++i) {
        sevLweSecretCoeffs[i] = sevSecretCoeffs[i];
    }
    try {
        privateKeyFHEW = makeLweSecretKeyFromCoeffs(ccLWE, sevLweSecretCoeffs);
    }
    catch (const std::exception& e) {
        std::cerr << "SEV LWE key load failed: " << e.what() << std::endl;
        ::close(sev_sock);
        return 1;
    }
    uint32_t logQFHEW = static_cast<uint32_t>(std::llround(
        std::log2(ccLWE->GetParams()->GetLWEParams()->Getq().ConvertToDouble())));
    cc->EvalFHEWtoCKKSSetup(ccLWE, CKKS_N, logQFHEW);
    cc->EvalFHEWtoCKKSKeyGen(keys, privateKeyFHEW, CKKS_N, CKKS_N);
    ccLWE->BTKeyGen(privateKeyFHEW);

    const int H0 = 32, W0 = 32, C0 = 3;
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(-2, 2);

    std::vector<double> image_chw((size_t)C0 * H0 * W0, 0.0);
    for (size_t i = 0; i < image_chw.size(); ++i)
        image_chw[i] = (double)dist(rng);

    int inChunkC = choose_chunk_by_hw(H0, W0, C0);
    FeatureMap x = build_input_featuremap_from_plain(sev_sock, cc, image_chw, H0, W0, C0, inChunkC,
                                                     keys.publicKey->GetKeyTag());

    std::vector<int> cfg = {64, -1, 192, -1, 384, 256, 256, -2};
    std::vector<Kernel4D> weights;
    weights.reserve(6);

    int Cin = C0;
    for (int v : cfg) {
        if (v > 0) {
            weights.push_back(rand_kernel(v, Cin, 3, rng));
            Cin = v;
        }
    }

    std::cout << "Precompute AlexNet kernels\n";
    FeatureMapMeta meta{H0, W0, C0, inChunkC};
    size_t widx = 0;
    for (int v : cfg) {
        if (v > 0) {
            meta = precompute_conv_cache(cc, weights[widx], v, 3, 1, meta);
            widx++;
        }
        else if (v == -1) {
            meta.H = (meta.H - 2) / 2 + 1;
            meta.W = (meta.W - 2) / 2 + 1;
        }
        else if (v == -2) {
            meta.H = 2;
            meta.W = 2;
        }
    }

    std::cout << "Start AlexNet Eval\n";
    auto t0 = std::chrono::high_resolution_clock::now();

    widx = 0;
    for (int v : cfg) {
        if (v > 0) {
            auto conv_start = std::chrono::high_resolution_clock::now();
            x               = conv_featuremap_cheetah(sev_sock, cc, x, weights[widx], v, 3, 1);
            auto conv_end   = std::chrono::high_resolution_clock::now();
            std::cout << "Conv " << widx << " : "
                      << std::chrono::duration_cast<std::chrono::duration<double>>(conv_end - conv_start).count()
                      << " s" << std::endl;

            auto relu_start = std::chrono::high_resolution_clock::now();
            x               = relu_featuremap(sev_sock, cc, ccLWE, x);
            auto relu_end   = std::chrono::high_resolution_clock::now();
            std::cout << "CKKStoFHEW " << widx << " : "
                      << g_last_ckks_to_fhew_time_sec << " s" << std::endl;
            std::cout << "FHEWtoCKKS " << widx << " : "
                      << g_last_fhew_to_ckks_time_sec << " s" << std::endl;
            std::cout << "ReLU " << widx << " : "
                      << std::chrono::duration_cast<std::chrono::duration<double>>(relu_end - relu_start).count()
                      << " s" << std::endl;
            widx++;
        }
        else if (v == -1) {
            x = avgpool_featuremap(cc, x, 2, 2);
        }
        else if (v == -2) {
            x = adaptive_avgpool_2x2(cc, x);
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    std::cout << "AlexNet forward (wired) elapsed: "
              << std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count() << " s\n";
    {
        auto flags = std::cout.flags();
        auto prec  = std::cout.precision();
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "SEV remote total time (excluding connect): " << g_sev_remote_time_sec << " s\n";
        std::cout << "SEV conv reencrypt time: " << g_sev_conv_reencrypt_time_sec << " s\n";
        std::cout << "CKKS bootstrap total time: " << g_ckks_bootstrap_time_sec
                  << " s, calls=" << g_ckks_bootstrap_calls << "\n";
        std::cout.flags(flags);
        std::cout.precision(prec);
    }

    // ---- TODO: FC layers for CIFAR-10 (1024 -> 4096 -> 4096 -> 10)
    // 구조만 맞춘 버전이므로 FC/분류는 필요에 따라 추가하세요.

    return 0;
}
