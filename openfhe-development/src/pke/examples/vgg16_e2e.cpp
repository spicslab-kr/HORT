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
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
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

static const size_t CKKS_N = 32768;

static double g_sev_remote_time_sec = 0.0;
static double g_ckks_bootstrap_time_sec = 0.0;
static double g_last_ckks_bootstrap_time_sec = 0.0;
static uint64_t g_ckks_bootstrap_calls = 0;
static const uint32_t CKKS_BOOTSTRAP_MULT_DEPTH = 18;
static const uint32_t CKKS_BOOTSTRAP_CORRECTION_FACTOR = 20;

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

Ciphertext<DCRTPoly> makeCiphertextFromCoeffs(CryptoContext<DCRTPoly> cc,
                                              const std::vector<uint64_t>& buffer) {
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers = towerParams.size();
    size_t ringDim   = elemParams->GetRingDimension();

    // for (const auto& p : elemParams->GetParams())
    // std::cout << p->GetModulus() << std::endl;


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

static PrivateKey<DCRTPoly> makeSecretKeyFromCoeffs(CryptoContext<DCRTPoly> cc,
                                                    const std::vector<uint64_t>& coeffs,
                                                    const PublicKey<DCRTPoly>& pk) {
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers = towerParams.size();
    size_t ringDim   = elemParams->GetRingDimension();

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

void parameterSetupAndKeyLoadOrGen(CryptoContext<DCRTPoly>& cc,
                                   std::shared_ptr<lbcrypto::BinFHEContext>& ccLWE,
                                   KeyPair<DCRTPoly>& keys,
                                   LWEPrivateKey& privateKeyFHEW,
                                   const std::vector<uint64_t>& sevSecretCoeffs ) {
    // Specify main parameters

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    

    // uint32_t levelsAvailableAfterBootstrap = 14;
    std::vector<uint32_t> levelBudget = {2, 2};
    //usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    // uint32_t depth = 2;

    uint32_t multDepth    = CKKS_BOOTSTRAP_MULT_DEPTH;
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 40;
    uint32_t ringDim      = 65536;
    SecurityLevel sl      = HEStd_NotSet ;
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
    auto elemParams   = cc->GetCryptoParameters()->GetElementParams();
    const auto& towers = elemParams->GetParams();
    for (size_t t = 0; t < towers.size(); ++t) {
    auto mod  = towers[t]->GetModulus();
    auto psi  = towers[t]->GetRootOfUnity();
    auto w    = psi.ModMul(psi, mod);  // w = psi^2 mod q
    std::cout << "[OpenFHE] tower " << t << " modulus " << mod.ToString()
              << " psi " << psi.ToString()
              << " w "   << w.ToString() << std::endl;
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

    PublicKey<DCRTPoly>     pk;

    bool ccNotLoaded = true;
    std::cout << "Using freshly generated cc with CKKS bootstrap parameters" << std::endl;

    


    //Load or generate keys ...
    if(file_exists(pkFile) && file_exists(mkFile) && file_exists(rkFile)) {
        std::cout << "Public/evaluation keys found, loading from disk" << std::endl;
        try
        {
            std::ifstream pkif(pkFile, std::ios::binary);
            std::ifstream multKeyIStream(mkFile, std::ios::in | std::ios::binary);
            std::ifstream rotKeyIStream(rkFile, std::ios::in | std::ios::binary);
            
            Serial::Deserialize( pk, pkif, SerType::BINARY);
            cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY);
            cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY);
            

            keys.publicKey = pk;
        }
        catch(const std::exception& e)
        {
            std::cout << "Failed to load key files" << std::endl;
            throw;
        }
    }        
    else {
        throw std::runtime_error("public.key/mult.key/rot.key not found. Provision keys exported from SEV VM.");
    }

    keys.secretKey = makeSecretKeyFromCoeffs(cc, sevSecretCoeffs, keys.publicKey);
    std::cout << "SEV secret key applied (" << sevSecretCoeffs.size() << " coefficients)" << std::endl;

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
    ccLWE  = (cc->GetBinCCForSchemeSwitch());
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    //bool haveSchemeSwitchData = false;


    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << "Ptxt Space :  " << ccLWE->GetMaxPlaintextSpace().ConvertToInt() << std::endl;


    // Compute the scaling factor to decrypt correctly in FHEW; under the hood, the LWE mod switch will performed on the ciphertext at the last level
    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
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
    try
    {
        

        if (Serial::DeserializeFromFile(refKeyFile, refreshKey, SerType::BINARY) == false) {
            throw std::invalid_argument( "refKeyFile Error" );
        }
        if (Serial::DeserializeFromFile(kswKeyFile, ksKey, SerType::BINARY) == false) {
            throw std::invalid_argument( "kswKeyFile Error" );
        }
        
        ccLWE->BTKeyLoad({refreshKey, ksKey});
        std::cout << "TFHE Evks Loaded " << kswKeyFile << std::endl;
    }
    catch(const std::exception& e)
    {
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
#include "sev_masking.h"



struct FeatureMap {
    int H = 0, W = 0;
    int C = 0;
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

static inline int ceil_div(int a, int b) { return (a + b - 1) / b; }

static inline int choose_chunk_by_hw(int H, int W) {
    int maxChunk = static_cast<int>(CKKS_N / std::max(1, H * W));
    maxChunk = std::max(1, maxChunk);
    return std::min(maxChunk, 32);
}

static inline int choose_mchunk(int H, int W, int CinChunk, int K, int N, int maxWant) {
    long long extra = 1LL * W * (K - 1) + (K - 1);
    for (int m = maxWant; m >= 1; --m) {
        long long need = 1LL * H * W * (1LL * m * CinChunk) + extra;
        if (need <= N) return m;
    }
    return 1;
}

using Kernel4D = std::vector<std::vector<std::vector<std::vector<int>>>>;

static std::vector<double> make_bn_scale(int C) {
    return std::vector<double>((size_t)C, 1.0);
}

static std::vector<double> make_bn_bias(int C) {
    return std::vector<double>((size_t)C, 0.0);
}

static size_t estimate_vgg_ct_plan(
    const std::vector<int>& stage_blocks,
    const std::vector<int>& stage_channels,
    int H0, int W0, int C0,
    int initChunkC,
    int fixConvCount,
    std::vector<std::string>* labels,
    std::vector<size_t>* ct_in,
    std::vector<size_t>* ct_out
) {
    int H = H0;
    int W = W0;
    int Cin = C0;
    int chunkC = initChunkC;
    size_t total = 0;
    size_t layer_idx = 0;

    if (labels) labels->clear();
    if (ct_in) ct_in->clear();
    if (ct_out) ct_out->clear();

    for (size_t s = 0; s < stage_blocks.size(); ++s) {
        for (int b = 0; b < stage_blocks[s]; ++b) {
            int Cout = stage_channels[s];
            int inGroups = ceil_div(Cin, chunkC);
            int maxWant = choose_chunk_by_hw(H, W);
            int feasible = choose_mchunk(H, W, chunkC, 3, CKKS_N, maxWant);
            feasible = std::max(1, std::min(feasible, Cout));
            int Mchunk = feasible;
            if (static_cast<int>(layer_idx) < fixConvCount) {
                Mchunk = std::min(initChunkC, feasible);
            }
            int outGroups = ceil_div(Cout, Mchunk);

            if (labels) labels->push_back("conv " + std::to_string(layer_idx));
            if (ct_in) ct_in->push_back(static_cast<size_t>(inGroups));
            if (ct_out) ct_out->push_back(static_cast<size_t>(outGroups));
            total += static_cast<size_t>(inGroups) + static_cast<size_t>(outGroups);

            ConvParam cp;
            cp.H = H;
            cp.W = W;
            cp.inputChannel = Cin;
            cp.outputChannel = Cout;
            cp.kernelSize = 3;
            cp.stride = 1;
            cp.padding = 1;
            calculate_output_dimensions_pad(cp, H, W);

            Cin = Cout;
            if (static_cast<int>(layer_idx) + 1 >= fixConvCount) {
                chunkC = Mchunk;
            }
            layer_idx++;
        }
        H = (H - 2) / 2 + 1;
        W = (W - 2) / 2 + 1;
        int ct = ceil_div(Cin, chunkC);
        if (labels) labels->push_back("pool " + std::to_string(s));
        if (ct_in) ct_in->push_back(static_cast<size_t>(ct));
        if (ct_out) ct_out->push_back(static_cast<size_t>(ct));
        total += static_cast<size_t>(ct) * 2;
    }
    return total;
}

static int choose_initial_chunk_min_ct(
    const std::vector<int>& stage_blocks,
    const std::vector<int>& stage_channels,
    int H0, int W0, int C0,
    int fixConvCount,
    std::vector<std::string>& labels,
    std::vector<size_t>& ct_in,
    std::vector<size_t>& ct_out,
    size_t& best_total
) {
    int maxChunk = std::min(choose_chunk_by_hw(H0, W0), C0);
    maxChunk = std::max(1, maxChunk);
    int bestChunk = 1;
    best_total = std::numeric_limits<size_t>::max();

    for (int c = 1; c <= maxChunk; ++c) {
        size_t total = estimate_vgg_ct_plan(
            stage_blocks, stage_channels, H0, W0, C0, c, fixConvCount,
            nullptr, nullptr, nullptr
        );
        if (total < best_total) {
            best_total = total;
            bestChunk = c;
        }
    }

    estimate_vgg_ct_plan(stage_blocks, stage_channels, H0, W0, C0, bestChunk,
                         fixConvCount,
                         &labels, &ct_in, &ct_out);
    return bestChunk;
}

static void log_fixed_chunk_plan(
    const std::vector<int>& stage_blocks,
    const std::vector<int>& stage_channels,
    int H0, int W0, int C0
) {
    int totalConv = 0;
    for (int b : stage_blocks) totalConv += b;

    std::cout << "[VGG16] fixed-chunkC plan sweep (fix first N convs)\n";
    for (int fixN = 0; fixN <= totalConv; ++fixN) {
        std::vector<std::string> labels;
        std::vector<size_t> ct_in;
        std::vector<size_t> ct_out;
        size_t ct_total = 0;
        int bestChunk = choose_initial_chunk_min_ct(
            stage_blocks, stage_channels, H0, W0, C0, fixN,
            labels, ct_in, ct_out, ct_total
        );
        std::cout << "[VGG16][fixN] N=" << fixN
                  << " best_chunkC=" << bestChunk
                  << " total_ct=" << ct_total << "\n";
    }
}

static Kernel4D rand_kernel(int M, int C, int K, std::mt19937& rng, int lo=-1, int hi=1) {
    std::uniform_int_distribution<int> dist(lo, hi);
    Kernel4D k(M,
        std::vector<std::vector<std::vector<int>>>(
            C, std::vector<std::vector<int>>(K, std::vector<int>(K, 0))
        )
    );
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
    std::vector<Plaintext> bias_plaintexts;
};

struct KernelCacheKey {
    const Kernel4D* wptr;
    int H_in;
    int W_in;
    int CinChunk;
    int Cout;
    int K;
    int stride;
    int forceMchunk;
    const std::vector<double>* bn_scale_ptr;
    const std::vector<double>* bn_bias_ptr;
    bool fuse_bn;

    bool operator==(const KernelCacheKey& other) const {
        return wptr == other.wptr &&
               H_in == other.H_in &&
               W_in == other.W_in &&
               CinChunk == other.CinChunk &&
               Cout == other.Cout &&
               K == other.K &&
               stride == other.stride &&
               forceMchunk == other.forceMchunk &&
               bn_scale_ptr == other.bn_scale_ptr &&
               bn_bias_ptr == other.bn_bias_ptr &&
               fuse_bn == other.fuse_bn;
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
        hash_combine(seed, std::hash<int>{}(k.forceMchunk));
        hash_combine(seed, std::hash<const std::vector<double>*>{}(k.bn_scale_ptr));
        hash_combine(seed, std::hash<const std::vector<double>*>{}(k.bn_bias_ptr));
        hash_combine(seed, std::hash<bool>{}(k.fuse_bn));
        return seed;
    }
};

static std::unordered_map<KernelCacheKey, KernelCache, KernelCacheKeyHash> g_kernel_cache;

static KernelCache build_kernel_cache(
    CryptoContext<DCRTPoly> cc,
    const Kernel4D& Wfull,
    int Cout,
    int K,
    int stride,
    int H_in,
    int W_in,
    int CinChunk,
    int forceMchunk,
    const std::vector<double>* bn_scale,
    const std::vector<double>* bn_bias,
    bool fuse_bn
) {
    KernelCache cache;
    cache.H_in = H_in;
    cache.W_in = W_in;
    cache.CinChunk = CinChunk;
    cache.Cout = Cout;
    cache.K = K;
    cache.stride = stride;

    const int Cin = static_cast<int>(Wfull[0].size());
    const int P = (K == 3 ? 1 : 0);

    ConvParam cp;
    cp.H = H_in;
    cp.W = W_in;
    cp.inputChannel = Cin;
    cp.outputChannel = Cout;
    cp.kernelSize = K;
    cp.stride = stride;
    cp.padding = P;

    calculate_output_dimensions_pad(cp, cache.H_out, cache.W_out);

    ConvParam cp_local = cp;
    cp_local.padding = 0;

    int maxWant = choose_chunk_by_hw(cp.H, cp.W);
    int feasible = choose_mchunk(cp.H, cp.W, CinChunk, K, CKKS_N, maxWant);
    feasible = std::max(1, std::min(feasible, Cout));
    if (forceMchunk > 0) {
        cache.Mchunk = std::min(forceMchunk, feasible);
        cache.Mchunk = std::max(1, std::min(cache.Mchunk, Cout));
    } else {
        cache.Mchunk = feasible;
    }
    cache.inGroups = ceil_div(Cin, CinChunk);
    cache.outGroups = ceil_div(Cout, cache.Mchunk);
    cache.kernel_packs.resize((size_t)cache.outGroups * cache.inGroups);
    cache.bias_plaintexts.resize((size_t)cache.outGroups);

    #pragma omp parallel for
    for (int og = 0; og < cache.outGroups; ++og) {
        const int m0 = og * cache.Mchunk;
        const int thisM = std::min(cache.Mchunk, Cout - m0);

        for (int ig = 0; ig < cache.inGroups; ++ig) {
            const int c0 = ig * CinChunk;
            const int thisC = std::min(CinChunk, Cin - c0);

            ConvParam cp_enc = cp_local;
            cp_enc.inputChannel = thisC;
            cp_enc.outputChannel = thisM;

            Kernel4D Wslice(
                thisM,
                std::vector<std::vector<std::vector<int>>>(
                    thisC,
                    std::vector<std::vector<int>>(K, std::vector<int>(K))
                )
            );
            for (int mm = 0; mm < thisM; ++mm)
                for (int cc_i = 0; cc_i < thisC; ++cc_i)
                    for (int kh = 0; kh < K; ++kh)
                        for (int kw = 0; kw < K; ++kw)
                            Wslice[mm][cc_i][kh][kw] = Wfull[m0 + mm][c0 + cc_i][kh][kw];

            std::vector<double> encoded_kernel;
            if (fuse_bn && bn_scale) {
                encoded_kernel.assign(CKKS_N, 0.0);
                int H = cp_enc.H;
                int W = cp_enc.W;
                int C = cp_enc.inputChannel;
                int M = cp_enc.outputChannel;
                int O = H * W * (M * C - 1) + W * (K - 1) + (K - 1);
                for (int m = 0; m < M; ++m) {
                    double s = (*bn_scale)[(size_t)m0 + m];
                    for (int c = 0; c < C; ++c) {
                        for (int kh = 0; kh < K; ++kh) {
                            for (int kw = 0; kw < K; ++kw) {
                                int poly_idx = O - m * C * H * W - c * H * W - kh * W - kw;
                                poly_idx = poly_idx % CKKS_N;
                                if (poly_idx < 0) poly_idx += CKKS_N;
                                encoded_kernel[poly_idx] = static_cast<double>(Wslice[m][c][kh][kw]) * s;
                            }
                        }
                    }
                }
            } else {
                cheetah_encode_kernel(cp_enc, CKKS_N, Wslice, encoded_kernel);
            }

            KernelPack kp;
            kp.cp_enc = cp_enc;
            kp.ptxt_kernel = cc->MakeCKKSPackedPlaintext(encoded_kernel, 1, 0, nullptr);
            cache.kernel_packs[(size_t)og * cache.inGroups + ig] = kp;
        }
        if (fuse_bn && bn_bias) {
            std::vector<double> bias_buf(coeffCount, 0.0);
            size_t hw = (size_t)cache.H_out * (size_t)cache.W_out;
            bool any_bias = false;
            for (int m = 0; m < thisM; ++m) {
                double b = (*bn_bias)[(size_t)m0 + m];
                if (b != 0.0) any_bias = true;
                size_t base = (size_t)m * hw;
                for (size_t idx = 0; idx < hw; ++idx) {
                    bias_buf[base + idx] = b;
                }
            }
            if (any_bias) {
                cache.bias_plaintexts[(size_t)og] = cc->MakeCKKSPackedPlaintext(bias_buf, 1, 0, nullptr);
            }
        }
    }

    return cache;
}

static const KernelCache& get_or_build_kernel_cache(
    CryptoContext<DCRTPoly> cc,
    const Kernel4D& Wfull,
    int Cout,
    int K,
    int stride,
    int H_in,
    int W_in,
    int CinChunk,
    int forceMchunk,
    const std::vector<double>* bn_scale,
    const std::vector<double>* bn_bias,
    bool fuse_bn
) {
    KernelCacheKey key{&Wfull, H_in, W_in, CinChunk, Cout, K, stride, forceMchunk,
                       bn_scale, bn_bias, fuse_bn};
    auto it = g_kernel_cache.find(key);
    if (it == g_kernel_cache.end()) {
        it = g_kernel_cache.emplace(
            key, build_kernel_cache(cc, Wfull, Cout, K, stride, H_in, W_in,
                                    CinChunk, forceMchunk, bn_scale, bn_bias, fuse_bn)
        ).first;
    }
    return it->second;
}

static FeatureMapMeta precompute_conv_cache(
    CryptoContext<DCRTPoly> cc,
    const Kernel4D& Wfull,
    int Cout,
    int K,
    int stride,
    const FeatureMapMeta& x,
    int forceMchunk,
    bool updateChunk,
    const std::vector<double>* bn_scale,
    const std::vector<double>* bn_bias,
    bool fuse_bn
) {
    const KernelCache& cache = get_or_build_kernel_cache(
        cc, Wfull, Cout, K, stride, x.H, x.W, x.chunkC, forceMchunk,
        bn_scale, bn_bias, fuse_bn
    );
    FeatureMapMeta y;
    y.H = cache.H_out;
    y.W = cache.W_out;
    y.C = Cout;
    y.chunkC = updateChunk ? cache.Mchunk : x.chunkC;
    const int P = (K == 3 ? 1 : 0);
    ConvParam cp;
    cp.H = x.H;
    cp.W = x.W;
    cp.inputChannel = x.C;
    cp.outputChannel = Cout;
    cp.kernelSize = K;
    cp.stride = stride;
    cp.padding = P;
    calculate_output_dimensions_pad(cp, y.H, y.W);
    return y;
}

static void log_chunking_conv(
    size_t layer_idx,
    const FeatureMap& x,
    const KernelCache& cache,
    int Cout
) {
    std::cout << "[VGG16] conv " << layer_idx
              << " in(HxW=" << x.H << "x" << x.W
              << ", C=" << x.C
              << ", chunkC=" << x.chunkC
              << ", ct=" << x.ct.size() << ")"
              << " -> out(HxW=" << cache.H_out << "x" << cache.W_out
              << ", C=" << Cout
              << ", chunkC=" << cache.Mchunk
              << ", ct=" << cache.outGroups << ")"
              << std::endl;
}

static void log_chunking_pool(size_t stage_idx, const FeatureMap& x) {
    std::cout << "[VGG16] pool " << stage_idx
              << " out(HxW=" << x.H << "x" << x.W
              << ", C=" << x.C
              << ", chunkC=" << x.chunkC
              << ", ct=" << x.ct.size() << ")"
              << std::endl;
}

static FeatureMap build_input_featuremap_from_plain(
    int sev_sock,
    CryptoContext<DCRTPoly> cc,
    const std::vector<double>& image_chw,
    int H, int W, int C,
    int chunkC
) {
    FeatureMap x;
    x.H = H; x.W = W; x.C = C; x.chunkC = chunkC;

    int groups = ceil_div(C, chunkC);
    x.ct.resize(groups);

    std::vector<uint64_t> tmp_coeff(coeffCount, 0);

    for (int g = 0; g < groups; ++g) {
        int c0 = g * chunkC;
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
        g_sev_remote_time_sec +=
            std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
        x.ct[g] = makeCiphertextFromCoeffs(cc, tmp_coeff);
    }

    return x;
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
    g_last_ckks_bootstrap_time_sec = 0.0;

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

static FeatureMap conv_featuremap_cheetah(
    CryptoContext<DCRTPoly> cc,
    const FeatureMap& x,
    const Kernel4D& Wfull,
    int Cout,
    int K,
    int stride,
    int forceMchunk,
    bool updateChunk,
    const std::vector<double>* bn_scale,
    const std::vector<double>* bn_bias,
    bool fuse_bn
) {
    const KernelCache& cache = get_or_build_kernel_cache(
        cc, Wfull, Cout, K, stride, x.H, x.W, x.chunkC, forceMchunk,
        bn_scale, bn_bias, fuse_bn
    );

    FeatureMap y;
    y.H = cache.H_out;
    y.W = cache.W_out;
    y.C = Cout;
    y.chunkC = updateChunk ? cache.Mchunk : x.chunkC;
    y.ct.resize(cache.outGroups);

    #pragma omp parallel for
    for (int og = 0; og < cache.outGroups; ++og) {
        Ciphertext<DCRTPoly> acc = nullptr;

        for (int ig = 0; ig < cache.inGroups; ++ig) {
            const KernelPack& kp = cache.kernel_packs[(size_t)og * cache.inGroups + ig];
            auto cr = cc->EvalMult(x.ct[ig], kp.ptxt_kernel);

            auto cr_shift1 = cc->GetScheme()->MultByMonomial(cr, 1);
            cr = cc->EvalAdd(cr, cr_shift1);
            auto cr_shift_W = cc->GetScheme()->MultByMonomial(cr, cache.W_out);
            cr = cc->EvalAdd(cr, cr_shift_W);

            auto part = cheetah_extract_conv(cc, kp.cp_enc, CKKS_N, cr);
            acc = acc ? cc->EvalAdd(acc, part) : part;
        }

        if (fuse_bn && cache.bias_plaintexts[og]) {
            auto bias = cache.bias_plaintexts[og];
            acc = cc->EvalAdd(acc, bias);
        }
        y.ct[og] = acc;
    }

    return y;
}

static FeatureMap avgpool_featuremap(
    CryptoContext<DCRTPoly> cc,
    const FeatureMap& x,
    int k,
    int stride
) {
    FeatureMap y = x;
    y.H = (x.H - k) / stride + 1;
    y.W = (x.W - k) / stride + 1;
    y.ct.resize(x.ct.size());

    ConvParam cp;
    cp.kernelSize = k;
    cp.stride = stride;
    cp.padding = 0;

    for (size_t i = 0; i < x.ct.size(); ++i) {
        int c0 = static_cast<int>(i) * x.chunkC;
        int thisC = std::min(x.chunkC, x.C - c0);
        cp.H = x.H;
        cp.W = x.W;
        cp.inputChannel = thisC;
        cp.outputChannel = thisC;
        y.ct[i] = cheetah_extract_avgpool(cc, cp, CKKS_N, x.ct[i], x.H, x.W, thisC, k, stride);
    }

    return y;
}

static FeatureMap batchnorm_featuremap(
    CryptoContext<DCRTPoly> cc,
    const FeatureMap& x,
    const std::vector<double>& scale,
    const std::vector<double>& bias
) {
    if ((int)scale.size() != x.C || (int)bias.size() != x.C) {
        throw std::runtime_error("BatchNorm params size mismatch with channel count");
    }

    FeatureMap y = x;
    const size_t hw = (size_t)x.H * (size_t)x.W;

    for (size_t i = 0; i < x.ct.size(); ++i) {
        int c0 = static_cast<int>(i) * x.chunkC;
        int thisC = std::min(x.chunkC, x.C - c0);

        std::vector<double> scale_buf(coeffCount, 0.0);
        std::vector<double> bias_buf(coeffCount, 0.0);

        for (int ch = 0; ch < thisC; ++ch) {
            double s = scale[(size_t)c0 + ch];
            double b = bias[(size_t)c0 + ch];
            size_t base = (size_t)ch * hw;
            for (size_t idx = 0; idx < hw; ++idx) {
                scale_buf[base + idx] = s;
                bias_buf[base + idx] = b;
            }
        }

        auto ptxt_scale = cc->MakeCKKSPackedPlaintext(scale_buf, 1, 0, nullptr);
        auto ptxt_bias  = cc->MakeCKKSPackedPlaintext(bias_buf, 1, 0, nullptr);
        auto scaled = cc->EvalMult(y.ct[i], ptxt_scale);
        y.ct[i] = cc->EvalAdd(scaled, ptxt_bias);
    }

    return y;
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
    } catch (const std::exception& e) {
        std::cerr << "Failed to receive SEV secret key: " << e.what() << "\n";
        ::close(sev_sock);
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

    const int H0 = 32, W0 = 32, C0 = 3;
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(-2, 2);

    std::vector<double> image_chw((size_t)C0 * H0 * W0, 0.0);
    for (size_t i = 0; i < image_chw.size(); ++i) image_chw[i] = (double)dist(rng);

    std::vector<int> stage_blocks = {2, 2, 3, 3, 3};
    std::vector<int> stage_channels = {64, 128, 256, 512, 512};

    struct VggLayer {
        Kernel4D W;
        int Cout;
        std::vector<double> bn_scale;
        std::vector<double> bn_bias;
    };
    std::vector<VggLayer> layers;
    layers.reserve(13);

    int Cin = C0;
    for (size_t s = 0; s < stage_blocks.size(); ++s) {
        for (int b = 0; b < stage_blocks[s]; ++b) {
            int Cout = stage_channels[s];
            layers.push_back({rand_kernel(Cout, Cin, 3, rng), Cout,
                              make_bn_scale(Cout), make_bn_bias(Cout)});
            Cin = Cout;
        }
    }

    const int fixConvCount = 0;
    const bool fuse_bn = true;
    std::vector<std::string> ct_labels;
    std::vector<size_t> ct_in;
    std::vector<size_t> ct_out;
    size_t ct_total = 0;
    log_fixed_chunk_plan(stage_blocks, stage_channels, H0, W0, C0);

    int inChunkC = choose_initial_chunk_min_ct(
        stage_blocks, stage_channels, H0, W0, C0, fixConvCount,
        ct_labels, ct_in, ct_out, ct_total
    );
    std::cout << "[VGG16] ct plan (min total=" << ct_total
              << ", input chunkC=" << inChunkC
              << ", fixConvCount=" << fixConvCount << ")\n";
    for (size_t i = 0; i < ct_labels.size(); ++i) {
        std::cout << "[VGG16][ct-plan] " << ct_labels[i]
                  << " in_ct=" << ct_in[i]
                  << " out_ct=" << ct_out[i] << "\n";
    }

    FeatureMap x = build_input_featuremap_from_plain(sev_sock, cc, image_chw, H0, W0, C0, inChunkC);

    std::cout << "Precompute VGG-16 kernels\n";
    FeatureMapMeta meta{H0, W0, C0, inChunkC};
    size_t layer_idx = 0;
    for (size_t s = 0; s < stage_blocks.size(); ++s) {
        for (int b = 0; b < stage_blocks[s]; ++b) {
            bool updateChunk = static_cast<int>(layer_idx) + 1 >= fixConvCount;
            int forceMchunk = static_cast<int>(layer_idx) < fixConvCount ? inChunkC : 0;
            meta = precompute_conv_cache(
                cc, layers[layer_idx].W, layers[layer_idx].Cout, 3, 1,
                meta, forceMchunk, updateChunk,
                &layers[layer_idx].bn_scale, &layers[layer_idx].bn_bias, fuse_bn
            );
            layer_idx++;
        }
        meta.H = (meta.H - 2) / 2 + 1;
        meta.W = (meta.W - 2) / 2 + 1;
    }

    std::cout << "Start VGG-16 Eval\n";
    auto t0 = std::chrono::high_resolution_clock::now();

    layer_idx = 0;
    for (size_t s = 0; s < stage_blocks.size(); ++s) {
        for (int b = 0; b < stage_blocks[s]; ++b) {
            const KernelCache& cache = get_or_build_kernel_cache(
                cc, layers[layer_idx].W, layers[layer_idx].Cout, 3, 1,
                x.H, x.W, x.chunkC,
                static_cast<int>(layer_idx) < fixConvCount ? inChunkC : 0,
                &layers[layer_idx].bn_scale, &layers[layer_idx].bn_bias, fuse_bn
            );
            log_chunking_conv(layer_idx, x, cache, layers[layer_idx].Cout);
            auto t_conv_start = std::chrono::high_resolution_clock::now();
            bool updateChunk = static_cast<int>(layer_idx) + 1 >= fixConvCount;
            int forceMchunk = static_cast<int>(layer_idx) < fixConvCount ? inChunkC : 0;
            x = conv_featuremap_cheetah(
                cc, x, layers[layer_idx].W, layers[layer_idx].Cout, 3, 1,
                forceMchunk, updateChunk,
                &layers[layer_idx].bn_scale, &layers[layer_idx].bn_bias, fuse_bn
            );
            auto t_conv_end = std::chrono::high_resolution_clock::now();
            std::cout << "Conv " << layer_idx << " : "
                      << std::chrono::duration_cast<std::chrono::duration<double>>(t_conv_end - t_conv_start).count()
                      << " s\n";

            if (!fuse_bn) {
                auto t_bn_start = std::chrono::high_resolution_clock::now();
                x = batchnorm_featuremap(cc, x, layers[layer_idx].bn_scale, layers[layer_idx].bn_bias);
                auto t_bn_end = std::chrono::high_resolution_clock::now();
                std::cout << "BN " << layer_idx << " : "
                          << std::chrono::duration_cast<std::chrono::duration<double>>(t_bn_end - t_bn_start).count()
                          << " s\n";
            }

            auto t_relu_start = std::chrono::high_resolution_clock::now();
            x = relu_featuremap(sev_sock, cc, ccLWE, x);
            auto t_relu_end = std::chrono::high_resolution_clock::now();
            std::cout << "ReLU " << layer_idx << " : "
                      << std::chrono::duration_cast<std::chrono::duration<double>>(t_relu_end - t_relu_start).count()
                      << " s\n";
            layer_idx++;
        }
        x = avgpool_featuremap(cc, x, 2, 2);
        log_chunking_pool(s, x);
    }

    x = avgpool_featuremap(cc, x, 1, 1);
    std::cout << "[VGG16] pool final out(HxW=" << x.H << "x" << x.W
              << ", C=" << x.C
              << ", chunkC=" << x.chunkC
              << ", ct=" << x.ct.size() << ")"
              << std::endl;

    auto t1 = std::chrono::high_resolution_clock::now();
    std::cout << "VGG-16 forward (wired) elapsed: "
              << std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count()
              << " s\n";
    {
      auto flags = std::cout.flags();
      auto prec  = std::cout.precision();
      std::cout << std::fixed << std::setprecision(6);
      std::cout << "SEV remote total time (excluding connect): " << g_sev_remote_time_sec << " s\n";
      std::cout << "CKKS bootstrap total time: " << g_ckks_bootstrap_time_sec
                << " s, calls=" << g_ckks_bootstrap_calls << "\n";
      std::cout.flags(flags);
      std::cout.precision(prec);
    }


    return 0;
}
