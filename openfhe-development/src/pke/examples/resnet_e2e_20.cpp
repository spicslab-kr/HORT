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
#include <numeric>
#include <unordered_map>
#include <stdexcept>

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

Ciphertext<DCRTPoly> makeCiphertextFromCoeffs(CryptoContext<DCRTPoly> cc, const std::vector<uint64_t>& buffer) {
    auto elemParams         = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers        = towerParams.size();
    size_t ringDim          = elemParams->GetRingDimension();

    // for (const auto& p : elemParams->GetParams())
    //     std::cout << p->GetModulus() << std::endl;

    size_t expectedSize = 2 * numTowers * ringDim;
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
static LWECiphertext EvalBinGateSEV(const std::shared_ptr<BinFHEContext>& ccLWE, BINGATE gate,
                                    ConstLWECiphertext& ct1, ConstLWECiphertext& ct2) {
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

    uint32_t multDepth    = 1;
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
    std::string mkFile = "mult.key";
    std::string rkFile = "rot.key";

    std::string lweSkFile = "lwesk.key";

    //TFHE Evks
    std::string refKeyFile = "ref.key";
    std::string kswKeyFile = "ksw.key";

    //CryptoContext
    std::string ccFile = "cc.key";

    PublicKey<DCRTPoly> pk;

    bool ccNotLoaded = false;
    if (!Serial::DeserializeFromFile(ccFile, cc, SerType::BINARY)) {
        std::cout << "Load cc failed, generating ..." << std::endl;
        ccNotLoaded = true;
    }

    //Load or generate keys ...
    if (file_exists(pkFile) && file_exists(mkFile) && file_exists(rkFile)) {
        std::cout << "Public/evaluation keys found, loading from disk" << std::endl;
        try {
            std::ifstream pkif(pkFile, std::ios::binary);
            std::ifstream multKeyIStream(mkFile, std::ios::in | std::ios::binary);
            std::ifstream rotKeyIStream(rkFile, std::ios::in | std::ios::binary);

            Serial::Deserialize(pk, pkif, SerType::BINARY);
            cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY);
            cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY);

            keys.publicKey = pk;
        }
        catch (const std::exception& e) {
            std::cout << "Failed to load key files" << std::endl;
            throw;
        }
    }
    else {
        throw std::runtime_error("public.key/mult.key/rot.key not found. Provision keys exported from SEV VM.");
    }

    keys.secretKey = makeSecretKeyFromCoeffs(cc, sevSecretCoeffs, keys.publicKey);
    std::cout << "SEV secret key applied (" << sevSecretCoeffs.size() << " coefficients)" << std::endl;

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
    //cc->EvalCKKStoFHEWPrecompute(scale1);
    if (ccNotLoaded) {
        std::cout << "Load cc failed, generating ..." << std::endl;
        cc->EvalCKKStoFHEWPrecompute(scale1);
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

// ======================================================
// ====== ResNet building blocks ========================
// ======================================================

// FeatureMap: output channels are stored as a vector of ciphertexts, each contains Mchunk channels.
// Layout inside ciphertext coefficients (per your convention):
// index = ch * (H*W) + h*W + w, for ch in [0, Mchunk)
struct FeatureMap {
    int H = 0, W = 0;
    int C      = 0;                        // logical total channels
    int chunkC = 1;                        // channels per ciphertext (Mchunk)
    std::vector<Ciphertext<DCRTPoly>> ct;  // size = ceil(C/chunkC)
};

static inline int ceil_div(int a, int b) {
    return (a + b - 1) / b;
}

// Choose a safe output-channel chunk (Mchunk) so that CHEETAH indexing doesn't wrap/overwrite.
// Need roughly: H*W*(Mchunk*CinChunk) + W*(K-1)+(K-1) <= N
static inline int choose_mchunk(int H, int W, int CinChunk, int K, int N, int maxWant) {
    long long extra = 1LL * W * (K - 1) + (K - 1);
    for (int m = maxWant; m >= 1; --m) {
        long long need = 1LL * H * W * (1LL * m * CinChunk) + extra;
        if (need <= N)
            return m;
    }
    return 1;
}

static inline int fixed_chunk_by_hw(int H, int W) {
    if (H >= 64)
        return 3;
    if (H >= 32)
        return 15;
    if (H >= 16)
        return 63;
    return 255;
}

// Random weight kernel [M][C][K][K]
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

// Slice kernel chunk: [Mchunk][CinChunk][K][K] from full [M][C][K][K]
[[maybe_unused]] static Kernel4D slice_kernel(const Kernel4D& full, int m0, int Mchunk, int c0, int CinChunk, int K) {
    Kernel4D chunk(Mchunk, std::vector<std::vector<std::vector<int>>>(
                               CinChunk, std::vector<std::vector<int>>(K, std::vector<int>(K, 0))));
    for (int dm = 0; dm < Mchunk; ++dm)
        for (int dc = 0; dc < CinChunk; ++dc)
            for (int kh = 0; kh < K; ++kh)
                for (int kw = 0; kw < K; ++kw)
                    chunk[dm][dc][kh][kw] = full[m0 + dm][c0 + dc][kh][kw];
    return chunk;
}

struct FeatureMapMeta {
    int H;
    int W;
    int C;
    int chunkC;
};

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
static bool g_randomize_kernel_cache = false;

static KernelCache build_kernel_cache(CryptoContext<DCRTPoly> cc,
                                      const Kernel4D& Wfull,  // [Cout][Cin][K][K]
                                      int Cout, int K, int stride, int H_in, int W_in, int CinChunk) {
    KernelCache cache;
    cache.H_in     = H_in;
    cache.W_in     = W_in;
    cache.CinChunk = CinChunk;
    cache.Cout     = Cout;
    cache.K        = K;
    cache.stride   = stride;

    const int Cin = (int)Wfull[0].size();

    // ResNet same padding: 3x3 -> P=1, 1x1 -> P=0
    const int P = (K == 3 ? 1 : 0);

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
    cp_local.H         = H_in;
    cp_local.W         = W_in;
    cp_local.padding   = 0;

    cache.Mchunk    = fixed_chunk_by_hw(cp.H, cp.W);
    cache.Mchunk    = std::max(1, std::min(cache.Mchunk, Cout));
    cache.inGroups  = ceil_div(Cin, CinChunk);
    cache.outGroups = ceil_div(Cout, cache.Mchunk);
    cache.kernel_packs.resize((size_t)cache.outGroups * cache.inGroups);

    static std::mt19937 rng(12345);
    static std::uniform_real_distribution<double> dist(-1.0, 1.0);

    std::cout << " Caching conv: H=" << cp.H << " W=" << cp.W << " Cin=" << Cin << " CinChunk=" << cache.CinChunk
              << " => inGroups=" << cache.inGroups << " Cout=" << Cout << " Mchunk=" << cache.Mchunk
              << " => outGroups=" << cache.outGroups << " EvalMult~=" << (long long)cache.inGroups * cache.outGroups
              << " (pad=" << P << ", paddedHW=" << cp_local.H << "x" << cp_local.W << ")"
              << "\n";

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

            std::vector<double> encoded_kernel;
            if (g_randomize_kernel_cache) {
                encoded_kernel.assign(CKKS_N, 0.0);
                for (size_t i = 0; i < CKKS_N; ++i) {
                    encoded_kernel[i] = dist(rng);
                }
            }
            else {
                Kernel4D Wslice(thisM, std::vector<std::vector<std::vector<int>>>(
                                           thisC, std::vector<std::vector<int>>(K, std::vector<int>(K))));
                for (int mm = 0; mm < thisM; ++mm)
                    for (int cc_i = 0; cc_i < thisC; ++cc_i)
                        for (int kh = 0; kh < K; ++kh)
                            for (int kw = 0; kw < K; ++kw)
                                Wslice[mm][cc_i][kh][kw] = Wfull[m0 + mm][c0 + cc_i][kh][kw];

                cheetah_encode_kernel(cp_enc, CKKS_N, Wslice, encoded_kernel);
            }

            KernelPack kp;
            kp.cp_enc      = cp_enc;
            kp.ptxt_kernel = cc->MakeCKKSPackedPlaintext(encoded_kernel, 1, 0, nullptr);
            cache.kernel_packs[(size_t)og * cache.inGroups + ig] = kp;
        }
    }

    return cache;
}

static void precompute_kernel_cache(CryptoContext<DCRTPoly> cc, const Kernel4D& Wfull, int Cout, int K, int stride,
                                    int H_in, int W_in, int CinChunk) {
    KernelCacheKey key{&Wfull, H_in, W_in, CinChunk, Cout, K, stride};
    if (g_kernel_cache.find(key) != g_kernel_cache.end()) {
        return;
    }
    g_kernel_cache.emplace(key, build_kernel_cache(cc, Wfull, Cout, K, stride, H_in, W_in, CinChunk));
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

static FeatureMapMeta infer_conv_meta(const FeatureMapMeta& x, int Cout, int K, int stride) {
    const int P = (K == 3 ? 1 : 0);
    ConvParam cp;
    cp.H             = x.H;
    cp.W             = x.W;
    cp.inputChannel  = x.C;
    cp.outputChannel = Cout;
    cp.kernelSize    = K;
    cp.stride        = stride;
    cp.padding       = P;

    int H_out, W_out;
    calculate_output_dimensions_pad(cp, H_out, W_out);

    FeatureMapMeta y;
    y.H      = H_out;
    y.W      = W_out;
    y.C      = Cout;
    y.chunkC = fixed_chunk_by_hw(cp.H, cp.W);
    return y;
}

static FeatureMapMeta precompute_conv_cache(CryptoContext<DCRTPoly> cc, const Kernel4D& Wfull, int Cout, int K,
                                            int stride, const FeatureMapMeta& x) {
    precompute_kernel_cache(cc, Wfull, Cout, K, stride, x.H, x.W, x.chunkC);
    return infer_conv_meta(x, Cout, K, stride);
}

static FeatureMapMeta precompute_basic_block_cache(CryptoContext<DCRTPoly> cc, const FeatureMapMeta& x,
                                                   const Kernel4D& W1, const Kernel4D& W2, bool useDownsample,
                                                   const Kernel4D& Wdown, int Cout, int strideFirst) {
    FeatureMapMeta y = precompute_conv_cache(cc, W1, Cout, /*K=*/3, strideFirst, x);
    y                = precompute_conv_cache(cc, W2, Cout, /*K=*/3, /*stride=*/1, y);
    if (useDownsample) {
        precompute_conv_cache(cc, Wdown, Cout, /*K=*/1, strideFirst, x);
    }
    return y;
}

// Pack plaintext feature chunk into one ciphertext using SEV encrypt.
// plain layout must match coeff layout: ch*(H*W)+h*W+w in [0, chunkC*H*W)
static Ciphertext<DCRTPoly> sev_encrypt_feature_chunk(
    int sev_sock, CryptoContext<DCRTPoly> cc,
    const std::vector<double>& plainChunk,  // size <= CKKS_N (we fill only first used coeffs)
    std::vector<uint64_t>& tmp_coeff_out    // size coeffCount
) {
    // SEV expects coeffCount doubles? In your code you used coeffCount + data() sized as coeffCount.
    // You should ensure plainChunk has length == coeffCount (or SEV-side reads only coeffCount).
    // We'll create a coeffCount-length vector and copy used prefix.
    std::vector<double> buf(coeffCount, 0.0);
    size_t used = std::min(buf.size(), plainChunk.size());
    std::copy(plainChunk.begin(), plainChunk.begin() + used, buf.begin());

    auto t0 = std::chrono::high_resolution_clock::now();
    sev_remote_reenc_coeff_enc(sev_sock, buf.data(), coeffCount, tmp_coeff_out.data());
    auto t1 = std::chrono::high_resolution_clock::now();
    g_sev_remote_time_sec +=
        std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    return makeCiphertextFromCoeffs(cc, tmp_coeff_out);
}

// =========================
// SEV + LWE ReLU on one CKKS ciphertext (your MSB-masking method)
// =========================
static Ciphertext<DCRTPoly> relu_sev_lwe_one_ct(int sev_sock, CryptoContext<DCRTPoly> cc,
                                                std::shared_ptr<lbcrypto::BinFHEContext> ccLWE,
                                                const Ciphertext<DCRTPoly>& x,
                                                std::vector<uint64_t>& tmp_rlwe_coeff,  // coeffCount
                                                std::vector<double>& tmp_dec,           // CKKS_N
                                                std::vector<uint64_t>& tmp_lwe_coeffs,  // CKKS_N*SEV_LWE_CT*64
                                                std::vector<LWECiphertext>& ct_lwe      // CKKS_N*64
) {
    // 1) RLWE coeff dec + LWE bitwise enc (SEV)
    static SevMaskingContext masking;
    tmp_rlwe_coeff = extractCiphertextCoeffs(x);
    const auto rlweModuli = rlwe_coeff_moduli(cc);
    auto rlweMask         = sample_additive_mask(rlweModuli, masking);
    auto coeffPi          = sample_permutation(CKKS_N, masking);
    auto coeffInv         = invert_permutation(coeffPi);

    add_mask_mod(tmp_rlwe_coeff, rlweMask, rlweModuli);
    permute_rlwe_prefix_coefficients(cc, tmp_rlwe_coeff, coeffPi);

    tmp_dec.assign(CKKS_N, 0.0);
    tmp_lwe_coeffs.assign((size_t)CKKS_N * SEV_LWE_CT * PER_SLOT_BIT, 0);
    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = sev_remote_reenc_coeff_dec_lwe_ct(sev_sock, tmp_rlwe_coeff.data(), coeffCount, tmp_dec.data(),
                                                (size_t)CKKS_N, tmp_lwe_coeffs.data(), tmp_lwe_coeffs.size());
    auto t1 = std::chrono::high_resolution_clock::now();
    g_sev_remote_time_sec +=
        std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    if (!ok) {
        throw std::runtime_error("sev_remote_reenc_coeff_dec_lwe_ct failed");
    }
    permute_lwe_slot_blocks(tmp_lwe_coeffs, tmp_dec, CKKS_N, SEV_LWE_CT * PER_SLOT_BIT, coeffInv);

    // 4) build LWE ciphertexts
    ct_lwe.resize((size_t)CKKS_N * PER_SLOT_BIT);
#pragma omp parallel for
    for (long unsigned int i = 0; i < CKKS_N * PER_SLOT_BIT; i++) {
        const uint64_t* ptr = tmp_lwe_coeffs.data() + (size_t)i * SEV_LWE_CT;
        std::vector<uint64_t> coeffs(ptr, ptr + SEV_LWE_CT);
        ct_lwe[i] = makeLWECiphertextFromCoeffs(ccLWE, coeffs);
    }

// 5) ReLU mask: if MSB==1 => zero lower bits (you can also zero MSB if you want strict ReLU)
#pragma omp parallel for
    for (long unsigned int k = 0; k < CKKS_N; k++) {
        int base     = k * PER_SLOT_BIT;
        int msb      = base + PER_SLOT_BIT - 1;
        auto not_msb = ccLWE->EvalNOT(ct_lwe[msb]);
        for (int b = 0; b < PER_SLOT_BIT - 1; b++) {
            ct_lwe[base + b] = EvalBinGateSEV(ccLWE, AND, ct_lwe[base + b], not_msb);
        }
        // Optional strict ReLU:
        // ct_lwe[msb] = EvalBinGateSEV(ccLWE, AND, ct_lwe[msb], ccLWE->EvalConstant(false));
    }

    // 6) serialize LWE coeffs back for SEV dec
#pragma omp parallel for
    for (long unsigned int i = 0; i < CKKS_N * PER_SLOT_BIT; i++) {
        auto c = extractLWECiphertextCoeffs(ct_lwe[i]);
        for (long unsigned int j = 0; j < SEV_LWE_CT; j++) {
            tmp_lwe_coeffs[(size_t)i * SEV_LWE_CT + j] = c[j];
        }
    }

    // 7) LWE -> coeff enc (SEV, one shot)
    std::vector<uint64_t> out_coeff(coeffCount, 0);
    auto slotPi  = sample_permutation(CKKS_N, masking);
    auto slotInv = invert_permutation(slotPi);
    permute_lwe_slot_blocks(tmp_lwe_coeffs, tmp_dec, CKKS_N, SEV_LWE_CT * PER_SLOT_BIT, slotPi);

    t0 = std::chrono::high_resolution_clock::now();
    ok = sev_remote_lwe_dec_coeff_enc(sev_sock, tmp_dec.data(), (size_t)CKKS_N, tmp_lwe_coeffs.data(),
                                      tmp_lwe_coeffs.size(), out_coeff.data());
    t1 = std::chrono::high_resolution_clock::now();
    g_sev_remote_time_sec +=
        std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    if (!ok) {
        throw std::runtime_error("sev_remote_lwe_dec_coeff_enc failed");
    }
    permute_rlwe_prefix_coefficients(cc, out_coeff, slotInv);
    sub_mask_mod(out_coeff, rlweMask, rlweModuli);
    return makeCiphertextFromCoeffs(cc, out_coeff);
}

static FeatureMap relu_featuremap(int sev_sock, CryptoContext<DCRTPoly> cc,
                                  std::shared_ptr<lbcrypto::BinFHEContext> ccLWE, const FeatureMap& x) {
    FeatureMap y = x;

    std::vector<uint64_t> tmp_rlwe_coeff(coeffCount);
    std::vector<double> tmp_dec(CKKS_N);
    std::vector<uint64_t> tmp_lwe_coeffs;
    std::vector<LWECiphertext> ct_lwe;

    for (auto& ct : y.ct) {
        ct = relu_sev_lwe_one_ct(sev_sock, cc, ccLWE, ct, tmp_rlwe_coeff, tmp_dec, tmp_lwe_coeffs, ct_lwe);
    }
    return y;
}

// =========================
// Conv over FeatureMap using CHEETAH encode/repack/extract
// - We chunk output channels into Mchunk groups, each group becomes one ciphertext.
// - We chunk input channels according to x.chunkC groups.
// =========================
/*
static FeatureMap conv_featuremap_cheetah(
    CryptoContext<DCRTPoly> cc,
    const FeatureMap& x,
    const Kernel4D& Wfull,     // [Cout][Cin][K][K]
    int Cout,
    int K,
    int stride
){
    // input is stored as groups of chunkC channels, each ct holds chunkC*H*W coeffs.
    int H = x.H, W = x.W, Cin = x.C;
    int CinChunk = x.chunkC;
    int inGroups = ceil_div(Cin, CinChunk);

    ConvParam cpBase;
    cpBase.H = H;
    cpBase.W = W;
    cpBase.kernelSize = K;
    cpBase.stride = stride;

    // output spatial
    int Hout, Wout;
    ConvParam cpTmp = cpBase;
    cpTmp.inputChannel = 1;
    cpTmp.outputChannel = 1;
    calculate_output_dimensions(cpTmp, Hout, Wout);

    // Choose Mchunk safely for the worst-case CinChunk used in this conv
    // We'll cap to 8 for convenience; you can tune this.
    //int Mchunk = choose_mchunk(H, W, CinChunk, K, CKKS_N, maxWant=8);

    FeatureMap y;
    y.H = Hout;
    y.W = Wout;
    y.C = Cout;
    y.chunkC = Mchunk;
    int outGroups = ceil_div(Cout, Mchunk);
    y.ct.resize(outGroups);

    std::cout << "  conv: H="<<H<<" W="<<W
          << " Cin="<<Cin<<" CinChunk="<<CinChunk
          << " => inGroups="<<inGroups
          << " Cout="<<Cout<<" Mchunk="<<Mchunk
          << " => outGroups="<<outGroups
          << " EvalMult~="<<(long long)inGroups*outGroups
          << std::endl;

    // Pre-encode plaintext kernels per (outGroup, inGroup) to avoid recompute
    // You can cache more aggressively if you want.
    #pragma omp parallel for
    for (int og = 0; og < outGroups; ++og) {
        int m0 = og * Mchunk;
        int thisM = std::min(Mchunk, Cout - m0);

        Ciphertext<DCRTPoly> acc;
        bool accInit = false;

        for (int ig = 0; ig < inGroups; ++ig) {
            int c0 = ig * CinChunk;
            int thisC = std::min(CinChunk, Cin - c0);

            // Build chunked kernel [thisM][thisC][K][K]
            auto kchunk = slice_kernel(Wfull, m0, thisM, c0, thisC, K);

            // Encode kernel for this chunk
            ConvParam cp = cpBase;
            cp.inputChannel = thisC;
            cp.outputChannel = thisM;

            std::vector<double> encK;
            cheetah_encode_kernel(cp, CKKS_N, kchunk, encK);
            Plaintext ptxtK = cc->MakeCKKSPackedPlaintext(encK, 1, 0, nullptr);

            // Run cheetah conv chunk
            auto xin = x.ct[ig];
            auto xr  = cheetah_repack_for_conv(cc, cp, CKKS_N, xin);
            auto prod = cc->EvalMult(xr, ptxtK);

            // IMPORTANT:
            // If your pipeline requires additional shift/add accumulation (like you had in LeNet),
            // put the generalized rule here, otherwise leave as-is.

            auto outChunk = cheetah_extract_conv(cc, cp, CKKS_N, prod);

            if (!accInit) { acc = outChunk; accInit = true; }
            else          { acc = cc->EvalAdd(acc, outChunk); }
        }

        y.ct[og] = acc;
    }

    return y;
}
*/

static FeatureMap conv_featuremap_cheetah(CryptoContext<DCRTPoly> cc, const FeatureMap& x_in,
                                          const Kernel4D& Wfull,  // [Cout][Cin][K][K]
                                          int Cout, int K, int stride) {
    constexpr int CKKS_N = 32768;

    if (x_in.H <= 0 || x_in.W <= 0) {
        std::cerr << "Invalid input dims: H=" << x_in.H << " W=" << x_in.W << "\n";
        std::abort();
    }
    if (K <= 0 || stride <= 0) {
        std::cerr << "Invalid conv params: K=" << K << " stride=" << stride << "\n";
        std::abort();
    }
    if ((int)Wfull.size() != Cout) {
        std::cerr << "Wfull.size() != Cout\n";
        std::abort();
    }
    if (Cout == 0) {
        std::cerr << "Cout == 0\n";
        std::abort();
    }

    // Cin은 weight에서 유도 (Wfull[m].size())
    const int Cin = (int)Wfull[0].size();
    if (Cin <= 0) {
        std::cerr << "Cin <= 0\n";
        std::abort();
    }

    // ResNet same padding: 3x3 -> P=1, 1x1 -> P=0 (일반 규칙)
    const int P = (K == 3 ? 1 : 0);

    // conv 파라미터 구성
    ConvParam cp;
    cp.H             = x_in.H;
    cp.W             = x_in.W;
    cp.inputChannel  = Cin;
    cp.outputChannel = Cout;
    cp.kernelSize    = K;
    cp.stride        = stride;
    cp.padding       = P;

    // SAME-padding을 “ciphertext coefficient rearrangement”로 먼저 적용
    FeatureMap x = x_in;
    //if (P > 0) {
    //    x = pad_featuremap(cc, x_in, P); // x.H/W = (Hin+2P)/(Win+2P)
    //}

    // 이제 CHEETAH는 valid conv처럼 돌리기 위해 padding=0인 cp_local 사용
    ConvParam cp_local = cp;
    cp_local.H         = x.H;
    cp_local.W         = x.W;
    cp_local.padding   = 0;

    // 논리적 output dims (padding 포함)
    int H_out, W_out;
    calculate_output_dimensions_pad(cp, H_out, W_out);
    if (H_out <= 0 || W_out <= 0) {
        std::cerr << "Invalid output dims: H_out=" << H_out << " W_out=" << W_out << " (Hin=" << cp.H << " Win=" << cp.W
                  << " K=" << K << " S=" << stride << " P=" << P << ")\n";
        std::abort();
    }

    // ---- kernel cache (precomputed at startup if desired) ----
    const KernelCache& cache = get_or_build_kernel_cache(cc, Wfull, Cout, K, stride, x.H, x.W, x.chunkC);

    FeatureMap y;
    y.H      = cache.H_out;
    y.W      = cache.W_out;
    y.C      = Cout;
    y.chunkC = cache.Mchunk;
    y.ct.resize(cache.outGroups);

    // 디버그 로그(원하면 유지)
    std::cout << "  conv: H=" << cp.H << " W=" << cp.W << " Cin=" << Cin << " CinChunk=" << cache.CinChunk
              << " => inGroups=" << cache.inGroups << " Cout=" << Cout << " Mchunk=" << cache.Mchunk
              << " => outGroups=" << cache.outGroups << " EvalMult~=" << (long long)cache.inGroups * cache.outGroups
              << " (pad=" << P << ", paddedHW=" << cp_local.H << "x" << cp_local.W << ")"
              << "\n";

// ---- CHEETAH conv ----
#pragma omp parallel for
    for (int og = 0; og < cache.outGroups; ++og) {
        Ciphertext<DCRTPoly> acc = nullptr;

        for (int ig = 0; ig < cache.inGroups; ++ig) {
            const KernelPack& kp = cache.kernel_packs[(size_t)og * cache.inGroups + ig];

            // kernel is already handled; skip extra repacking here
            auto cr = cc->EvalMult(x.ct[ig], kp.ptxt_kernel);

            // shift-add (너가 쓰던 패턴 그대로)
            auto cr_shift1 = cc->GetScheme()->MultByMonomial(cr, 1);
            cr             = cc->EvalAdd(cr, cr_shift1);

            auto cr_shift_W = cc->GetScheme()->MultByMonomial(cr, cache.W_out);
            cr              = cc->EvalAdd(cr, cr_shift_W);

            // extract
            auto part = cheetah_extract_conv(cc, kp.cp_enc, CKKS_N, cr);

            // accumulate across input groups
            acc = acc ? cc->EvalAdd(acc, part) : part;
        }

        if (!acc) {
            std::cerr << "acc is null at outGroup " << og << "\n";
            std::abort();
        }
        y.ct[og] = acc;
    }

    return y;
}

static FeatureMap add_featuremap(CryptoContext<DCRTPoly> cc, const FeatureMap& a, const FeatureMap& b) {
    // assume same shape/chunking
    FeatureMap y = a;
#pragma omp parallel for
    for (size_t i = 0; i < y.ct.size(); ++i) {
        y.ct[i] = cc->EvalAdd(a.ct[i], b.ct[i]);
    }
    return y;
}

// Downsample skip if needed: 1x1 conv with stride=2, or just channel-match
static FeatureMap downsample_skip(CryptoContext<DCRTPoly> cc, const FeatureMap& x,
                                  const Kernel4D& Wdown,  // [Cout][Cin][1][1]
                                  int Cout, int stride) {
    return conv_featuremap_cheetah(cc, x, Wdown, Cout, /*K=*/1, stride);
}

// BasicBlock: 3x3 -> ReLU -> 3x3 -> Add(skip) -> ReLU
static FeatureMap basic_block(int sev_sock, CryptoContext<DCRTPoly> cc, std::shared_ptr<lbcrypto::BinFHEContext> ccLWE,
                              const FeatureMap& x,
                              const Kernel4D& W1,  // [Cout][Cin][3][3]
                              const Kernel4D& W2,  // [Cout][Cout][3][3]
                              bool useDownsample,
                              const Kernel4D& Wdown,  // [Cout][Cin][1][1]
                              int Cout, int strideFirst) {
    double wall_membership_start = omp_get_wtime();
    auto y                       = conv_featuremap_cheetah(cc, x, W1, Cout, /*K=*/3, strideFirst);
    double wall_membership_end   = omp_get_wtime();
    std::cout << "Conv 1 : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;

    wall_membership_start = omp_get_wtime();
    y                     = relu_featuremap(sev_sock, cc, ccLWE, y);
    wall_membership_end   = omp_get_wtime();
    std::cout << "ReLU 1 : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;

    wall_membership_start = omp_get_wtime();
    y                     = conv_featuremap_cheetah(cc, y, W2, Cout, /*K=*/3, /*stride=*/1);
    wall_membership_end   = omp_get_wtime();
    std::cout << "Conv 2 : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;

    FeatureMap skip = x;
    if (useDownsample) {
        skip = downsample_skip(cc, x, Wdown, Cout, /*stride=*/strideFirst);
    }
    wall_membership_start = omp_get_wtime();
    y                     = add_featuremap(cc, y, skip);
    wall_membership_end   = omp_get_wtime();
    std::cout << "Add feature map : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;

    wall_membership_start = omp_get_wtime();
    y                     = relu_featuremap(sev_sock, cc, ccLWE, y);
    wall_membership_end   = omp_get_wtime();
    std::cout << "ReLU 2 : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;
    return y;
}

// ======================================================
// Build input FeatureMap from plaintext image (64x64x3)
// - We store channels in chunks so that chunkC*H*W <= CKKS_N.
// - For 64x64, H*W=4096, so chunkC up to 8 is fine.
// ======================================================
static FeatureMap build_input_featuremap_from_plain(int sev_sock, CryptoContext<DCRTPoly> cc,
                                                    const std::vector<double>& image_chw,  // size C*H*W, C major
                                                    int H, int W, int C, int chunkC) {
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

        // pack thisC channels into coeffs: ch*(H*W)+h*W+w
        std::vector<double> plain;
        plain.assign((size_t)thisC * H * W, 0.0);

        for (int ch = 0; ch < thisC; ++ch) {
            for (int i = 0; i < H * W; ++i) {
                plain[(size_t)ch * H * W + i] = image_chw[(size_t)(c0 + ch) * H * W + i];
            }
        }

        x.ct[g] = sev_encrypt_feature_chunk(sev_sock, cc, plain, tmp_coeff);
    }

    return x;
}

// ======================================================
// MAIN: ResNet-20 (CIFAR-style 32x32 demo)
// Stages: [3,3,3], channels: 16,32,64
// This code uses "valid conv" because your cheetah_extract_conv uses that.
// For true ResNet padding=same, you’ll want to add padding handling later.
// ======================================================
int main() {
    // ---- connect to SEV + load keys
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
        return 1;
    }
    std::cout << "SEV VM connected\n";

    CryptoContext<DCRTPoly> cc;
    std::shared_ptr<lbcrypto::BinFHEContext> ccLWE1;
    KeyPair<DCRTPoly> keys;
    LWEPrivateKey privateKeyFHEW;

    parameterSetupAndKeyLoadOrGen(cc, ccLWE1, keys, privateKeyFHEW, sevSecretCoeffs);

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
        return 1;
    }
    ccLWE->BTKeyGen(privateKeyFHEW);

    // ---- create random input image 32x32x3 (CHW)
    const int H0 = 32, W0 = 32, C0 = 3;
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(-2, 2);

    std::vector<double> image_chw((size_t)C0 * H0 * W0, 0.0);
    for (size_t i = 0; i < image_chw.size(); ++i)
        image_chw[i] = (double)dist(rng);

    // ---- build encrypted input feature map (channel chunking only)
    // For 32x32, chunkC=3 is simplest (one ct holds all channels).
    // You can also set chunkC=4 or 8 if you want consistent chunking.
    int inChunkC = 3;
    FeatureMap x = build_input_featuremap_from_plain(sev_sock, cc, image_chw, H0, W0, C0, inChunkC);

    // ---- build random ResNet-20 weights (for demo)
    // NOTE: real ResNet uses padding=1 for 3x3 conv; your current cheetah conv is "valid".
    // This demo is for wiring correctness + pipeline integration.
    auto W_stem = rand_kernel(/*M=*/16, /*C=*/3, /*K=*/3, rng);  // CIFAR-style stem 3x3 s1

    // stage1: 16 (3 blocks)
    auto W1_0a = rand_kernel(16, 16, 3, rng);
    auto W1_0b = rand_kernel(16, 16, 3, rng);
    auto W1_1a = rand_kernel(16, 16, 3, rng);
    auto W1_1b = rand_kernel(16, 16, 3, rng);
    auto W1_2a = rand_kernel(16, 16, 3, rng);
    auto W1_2b = rand_kernel(16, 16, 3, rng);

    // stage2: 32 (first block stride2 + downsample, then 2 blocks)
    auto W2_0a = rand_kernel(32, 16, 3, rng);
    auto W2_0b = rand_kernel(32, 32, 3, rng);
    auto W2_0d = rand_kernel(32, 16, 1, rng);  // downsample 1x1
    auto W2_1a = rand_kernel(32, 32, 3, rng);
    auto W2_1b = rand_kernel(32, 32, 3, rng);
    auto W2_2a = rand_kernel(32, 32, 3, rng);
    auto W2_2b = rand_kernel(32, 32, 3, rng);

    // stage3: 64 (first block stride2 + downsample, then 2 blocks)
    auto W3_0a = rand_kernel(64, 32, 3, rng);
    auto W3_0b = rand_kernel(64, 64, 3, rng);
    auto W3_0d = rand_kernel(64, 32, 1, rng);
    auto W3_1a = rand_kernel(64, 64, 3, rng);
    auto W3_1b = rand_kernel(64, 64, 3, rng);
    auto W3_2a = rand_kernel(64, 64, 3, rng);
    auto W3_2b = rand_kernel(64, 64, 3, rng);

    // ---- Precompute kernels + packed plaintexts before inference
    g_randomize_kernel_cache = true;
    std::cout << "Precompute kernels\n";
    FeatureMapMeta meta;
    meta.H      = H0;
    meta.W      = W0;
    meta.C      = C0;
    meta.chunkC = inChunkC;

    meta = precompute_conv_cache(cc, W_stem, 16, /*K=*/3, /*stride=*/1, meta);
    meta = precompute_basic_block_cache(cc, meta, W1_0a, W1_0b, /*down=*/false, Kernel4D{}, 16, 1);
    meta = precompute_basic_block_cache(cc, meta, W1_1a, W1_1b, /*down=*/false, Kernel4D{}, 16, 1);
    meta = precompute_basic_block_cache(cc, meta, W1_2a, W1_2b, /*down=*/false, Kernel4D{}, 16, 1);

    meta = precompute_basic_block_cache(cc, meta, W2_0a, W2_0b, /*down=*/true, W2_0d, 32, 2);
    meta = precompute_basic_block_cache(cc, meta, W2_1a, W2_1b, /*down=*/false, Kernel4D{}, 32, 1);
    meta = precompute_basic_block_cache(cc, meta, W2_2a, W2_2b, /*down=*/false, Kernel4D{}, 32, 1);

    meta = precompute_basic_block_cache(cc, meta, W3_0a, W3_0b, /*down=*/true, W3_0d, 64, 2);
    meta = precompute_basic_block_cache(cc, meta, W3_1a, W3_1b, /*down=*/false, Kernel4D{}, 64, 1);
    meta = precompute_basic_block_cache(cc, meta, W3_2a, W3_2b, /*down=*/false, Kernel4D{}, 64, 1);

    // ---- Forward (ResNet-20, CIFAR-style stem)
    std::cout << "Start Resnet Eval\n";
    auto t0 = std::chrono::high_resolution_clock::now();

    // stem: 3x3 s1 -> ReLU
    double wall_membership_start = omp_get_wtime();
    x                            = conv_featuremap_cheetah(cc, x, W_stem, 16, 3, 1);
    double wall_membership_end   = omp_get_wtime();
    std::cout << "Conv 0.1 : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;

    wall_membership_start = omp_get_wtime();
    x                     = relu_featuremap(sev_sock, cc, ccLWE, x);
    wall_membership_end   = omp_get_wtime();
    std::cout << "ReLU 0.1 : " << (wall_membership_end - wall_membership_start) << " s" << std::endl;

    // stage1 (3 blocks, 16)
    std::cout << "Stage 1 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W1_0a, W1_0b, /*down=*/false, Kernel4D{}, 16, 1);
    std::cout << "Stage 1 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W1_1a, W1_1b, /*down=*/false, Kernel4D{}, 16, 1);
    std::cout << "Stage 1 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W1_2a, W1_2b, /*down=*/false, Kernel4D{}, 16, 1);

    // stage2 (3 blocks, 32)
    std::cout << "Stage 2 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W2_0a, W2_0b, /*down=*/true, W2_0d, 32, 2);
    std::cout << "Stage 2 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W2_1a, W2_1b, /*down=*/false, Kernel4D{}, 32, 1);
    std::cout << "Stage 2 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W2_2a, W2_2b, /*down=*/false, Kernel4D{}, 32, 1);

    // stage3 (3 blocks, 64)
    std::cout << "Stage 3 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W3_0a, W3_0b, /*down=*/true, W3_0d, 64, 2);
    std::cout << "Stage 3 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W3_1a, W3_1b, /*down=*/false, Kernel4D{}, 64, 1);
    std::cout << "Stage 3 Eval\n";
    x = basic_block(sev_sock, cc, ccLWE, x, W3_2a, W3_2b, /*down=*/false, Kernel4D{}, 64, 1);

    auto t1 = std::chrono::high_resolution_clock::now();
    std::cout << "ResNet-20 forward (wired) elapsed: "
              << std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count() << " s\n";
    {
        auto flags = std::cout.flags();
        auto prec  = std::cout.precision();
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "SEV remote total time (excluding connect): " << g_sev_remote_time_sec << " s\n";
        std::cout.flags(flags);
        std::cout.precision(prec);
    }

    // ---- TODO: GlobalAvgPool + FC
    // With your current toolchain, the simplest is:
    // 1) SEV decrypt x.ct[*] -> plaintext vector
    // 2) do pooling + FC in SEV (or host for testing)
    // 3) re-encrypt if needed
    //
    // If you want FC in CKKS, you’ll need a plaintext-packed FC weight encoding
    // compatible with your coeff layout (like you did for LeNet fc).

    return 0;
}
