#include "openfhe.h"
#include "binfhecontext.h"
#include "math/chebyshev.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include <random>
#include <chrono>
#include <vector>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <type_traits>
#include <utility>
#include <cstdlib>
#include <omp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

using namespace lbcrypto;
using namespace std;

static constexpr int DATADIM = 16;

// sev_functions.h

#define TIC_FHE(t) t = omp_get_wtime();
#define TOC_FHE(t, acc) acc += (omp_get_wtime() - t);

static bool kmeans_verbose_enabled() {
    static const bool enabled = std::getenv("KMEANS_VERBOSE") != nullptr;
    return enabled;
}

#define LOG_STEP(msg) do { if (kmeans_verbose_enabled()) { std::cout << "[LOG] " << msg << '\n'; } } while (0)
#define LOG_VERBOSE(expr) do { if (kmeans_verbose_enabled()) { std::cout << expr << '\n'; } } while (0)

static constexpr double SEV_SCALE = static_cast<double>(uint64_t(1) << 40);

static double g_sev_remote_time_sec = 0.0;

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

static void add_profile_time(double& total_sec, uint64_t& calls, double delta_sec) {
#pragma omp critical(runtime_profile_accum)
    {
        total_sec += delta_sec;
        ++calls;
    }
}

struct ScopedProfileTimer {
    double& total_sec;
    uint64_t& calls;
    double start_sec;
    double child_sec = 0.0;
    ScopedProfileTimer* parent;
    static thread_local ScopedProfileTimer* current;

    ScopedProfileTimer(double& total, uint64_t& count)
        : total_sec(total), calls(count), start_sec(omp_get_wtime()), parent(current) {
        current = this;
    }

    ~ScopedProfileTimer() {
        double elapsed_sec = omp_get_wtime() - start_sec;
        current = parent;
        if (parent) {
            parent->child_sec += elapsed_sec;
        }
        double exclusive_sec = elapsed_sec - child_sec;
        if (exclusive_sec < 0.0) {
            exclusive_sec = 0.0;
        }
        add_profile_time(total_sec, calls, exclusive_sec);
    }
};

thread_local ScopedProfileTimer* ScopedProfileTimer::current = nullptr;

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
    std::cout << "  Other CKKS functions (exclusive, non-SEV): "
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

static bool sev_remote_reenc_rescale(int sockfd, const uint64_t* in_buf, size_t coeff_count,
                                     long double input_scale, long double output_scale, uint64_t* out_buf);

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
            // #pragma omp parallel for
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

// static void LogCtStats(const std::string& label, ConstCiphertext<DCRTPoly>& ct);

Ciphertext<DCRTPoly> makeCiphertextFromCoeffs(CryptoContext<DCRTPoly> cc,
                                              const std::vector<uint64_t>& buffer) {
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers = towerParams.size();
    size_t ringDim   = elemParams->GetRingDimension();

    // for (const auto& p : elemParams->GetParams())
    // std::cout << p->GetModulus() << std::endl;

    // std::cout << "[LOG] makeCiphertextFromCoeffs: numTowers=" << numTowers
    //           << " ringDim=" << ringDim
    //           << " targetLevel=0" << std::endl;

    size_t expectedSize = 2 * numTowers * ringDim;
    if (buffer.size() != expectedSize) {
        throw std::runtime_error("Coefficient buffer size does not match ciphertext dimensions, expected " + std::to_string(expectedSize) + ", got " + std::to_string(buffer.size()));
    }

    auto ciphertextImpl = std::make_shared<CiphertextImpl<DCRTPoly>>(cc);
    std::vector<DCRTPoly> elements;
    elements.reserve(2);
    // std::cout << "makecoeff1" << std::endl;
    size_t offset = 0;
    // #pragma omp parallel for
    for (size_t comp = 0; comp < 2; ++comp) {
        DCRTPoly poly(elemParams, Format::EVALUATION, true);
        // std::cout << "makecoeff2" << std::endl;
        for (size_t t = 0; t < numTowers; ++t) {
            NativePoly tower(towerParams[t], Format::EVALUATION, true);
            // #pragma omp parallel for
            for (size_t i = 0; i < ringDim; ++i) {
                tower[i] = NativeInteger(buffer[offset++]);
            }
            poly.SetElementAtIndex(t, std::move(tower));
        }
        //poly.SetFormat(Format::EVALUATION);
        elements.push_back(poly);
    }

    
    ciphertextImpl->SetElements(std::move(elements));
    ciphertextImpl->SetEncodingType(PlaintextEncodings::CKKS_PACKED_ENCODING);
    // std::cout << "[LOG] makeCiphertextFromCoeffs: before SetLevel, level="
    //           << ciphertextImpl->GetLevel() << std::endl;
    ciphertextImpl->SetLevel(0);
    ciphertextImpl->SetNoiseScaleDeg(1);

    static const double kSevScale = std::pow(2.0, 40);
    ciphertextImpl->SetScalingFactor(kSevScale);
    ciphertextImpl->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(kSevScale)));
    ciphertextImpl->SetSlots(ringDim / 2);

    // LogCtStats("makeCiphertextFromCoeffs output", ciphertextImpl);
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
    ct->SetptModulus(2);
    return ct;
}

LWECiphertext makeLWECiphertextFromCoeffs(const std::shared_ptr<BinFHEContext>& ccLWE,
                                          const uint64_t* buffer,
                                          size_t bufferSize) {
    auto lweParams = ccLWE->GetParams()->GetLWEParams();
    size_t n = lweParams->Getn();
    NativeInteger q = lweParams->Getq();
    size_t expectedSize = n + 1;

    if (bufferSize != expectedSize) {
        throw std::runtime_error("LWE coefficient buffer size mismatch, expected " +
                                 std::to_string(expectedSize) + ", got " + std::to_string(bufferSize));
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
    ct->SetptModulus(2);
    return ct;
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

static PrivateKey<DCRTPoly> makeSecretKeyFromCoeffs(CryptoContext<DCRTPoly> cc,
                                                    const std::vector<uint64_t>& coeffs,
                                                    const PublicKey<DCRTPoly>& pk) {
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    const auto& towerParams = elemParams->GetParams();
    size_t numTowers = towerParams.size();
    size_t ringDim   = elemParams->GetRingDimension();

    if (coeffs.size() != numTowers * ringDim) {
        throw std::runtime_error("SEV secret key size mismatch with current crypto parameters, expected " +
                                 std::to_string(numTowers * ringDim) + ", got " + std::to_string(coeffs.size()));
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
/*
    Goal: given a ciphertext ct, perform SEV remote re-encryption and rescaling,
          return the refreshed ciphertext
    Extracts the coefficients from ct, sends them to SEV VM for re-encryption and rescaling,
    receives the new coefficients, constructs a new ciphertext and returns it
    
*/
static Ciphertext<DCRTPoly> sev_refresh_ciphertext(Ciphertext<DCRTPoly> ct,
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
    refreshed->SetLevel(0);
    // Set noise scale degree to 0 since it's been refreshed
    // forecing level to 0 is not available in OpenFHE API
    refreshed->SetNoiseScaleDeg(0);
    refreshed->SetKeyTag(keyTag);
    return refreshed;
}

// static void LogCtStats(const std::string& label, ConstCiphertext<DCRTPoly>& ct) {
//     std::cout << "[LOG] " << label
//               << " level=" << ct->GetLevel()
//               << " scale=" << ct->GetScalingFactor() << std::endl;
// }

// static PrivateKey<DCRTPoly> makeSecretKeyFromCoeffs(CryptoContext<DCRTPoly> cc,
//                                                     const std::vector<uint64_t>& coeffs,
//                                                     const PublicKey<DCRTPoly>& pk) {
//     auto elemParams = cc->GetCryptoParameters()->GetElementParams();
//     const auto& towerParams = elemParams->GetParams();
//     size_t numTowers = towerParams.size();
//     size_t ringDim   = elemParams->GetRingDimension();

//     if (coeffs.size() != numTowers * ringDim) {
//         throw std::runtime_error("SEV secret key size mismatch with current crypto parameters, expected " + std::to_string(numTowers * ringDim) + ", got " + std::to_string(coeffs.size()));
//     }

//     DCRTPoly poly(elemParams, Format::COEFFICIENT, true);
//     size_t offset = 0;
//     for (size_t t = 0; t < numTowers; ++t) {
//         NativePoly tower(towerParams[t], Format::COEFFICIENT, true);
//         auto modulus = towerParams[t]->GetModulus();
//         for (size_t i = 0; i < ringDim; ++i) {
//             NativeInteger val(coeffs[offset++]);
//             if (val >= modulus)
//                 val.ModEq(modulus);
//             tower[i] = val;
//         }
//         poly.SetElementAtIndex(t, std::move(tower));
//     }
//     poly.SetFormat(Format::EVALUATION);

//     auto skImpl = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
//     skImpl->SetPrivateElement(poly);
//     if (pk)
//         skImpl->SetKeyTag(pk->GetKeyTag());
//     return skImpl;
// }



// === SEV VM connection settings ===
static const char* SEV_VM_IP   = "192.168.100.2"; // replace with the actual SEV VM IP
//static const char* SEV_VM_IP   = "127.0.0.1"; // replace with the actual SEV VM IP
static const int   SEV_VM_PORT = 8080;        // port where reenc_e2e is listening
// Must match the N and LEVEL used to build reenc_e2e
static const size_t SEV_LEVEL  = 2;
static const size_t SEV_N      = 65536;       // example: if reenc_e2e was built with N=16384
static const size_t SEV_LWE_N  = 630;
static const size_t SEV_LWE_BIT_WIDTH = 15;  // must match reenc_e2e_engine_lwe.c
static const int    SEV_SOCKET_TIMEOUT_SEC = 600;

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

// static void print_bits_u64(const char* label, uint64_t value) {
//     std::cout << label;
//     for (int i = 63; i >= 0; --i) {
//         std::cout << ((value >> i) & 1ULL);
//     }
//     std::cout << std::endl;
// }


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

    struct timeval timeout;
    timeout.tv_sec = SEV_SOCKET_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("setsockopt(SO_RCVTIMEO)");
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("setsockopt(SO_SNDTIMEO)");
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


// static bool sev_remote_reenc_slot_enc(int sockfd,
//                              const double* in_buf,
//                              size_t coeff_count,
//                              uint64_t* out_buf) {
//         size_t byte_count = coeff_count * sizeof(uint64_t);
//         size_t msg_count = SEV_N / 2 * sizeof(double);
    
//     if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_ENC, msg_count)) {
//         return false;
//     }
//     if (write_full(sockfd, in_buf, msg_count) != (ssize_t)msg_count) {
//         perror("write_full");
//         return false;
//     }
//     //std::cout << "write done in sev_remote_reenc_slot_enc" << std::endl;

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

static bool sev_remote_reenc_slot_dec(int sockfd,
                             const uint64_t* in_buf,
                             size_t coeff_count,
                             double* out_buf) {
    SevRemoteTimer timer;
        size_t byte_count = coeff_count * sizeof(uint64_t);
        size_t msg_count = SEV_N / 2 * sizeof(double);
    
        if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_DEC, byte_count)) {
                return false;
            }
            if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full");
        return false;
    }
    //std::cout << "write done in sev_remote_reenc_slot_dec" << std::endl;

    ssize_t r = read_full(sockfd, out_buf, msg_count);
    if (r != (ssize_t)msg_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    //std::cout << "read done in sev_remote_reenc_slot_dec" << std::endl;
    return true;
}

static bool sev_remote_reenc_slot_dec_lwe_ct(int sockfd,
                             const uint64_t* in_buf,
                             size_t coeff_count,
                             size_t slot_count,
                             long double input_scale,
                             uint64_t* out_buf) {
    ScopedProfileTimer profileTimer(g_runtime_profile.ckksToFhewSec,
                                    g_runtime_profile.ckksToFhewCalls);
    SevRemoteTimer timer;
    size_t byte_count = coeff_count * sizeof(uint64_t);
    size_t msg_count = slot_count * SEV_LWE_BIT_WIDTH * (SEV_LWE_N + 1) * sizeof(uint64_t);
    uint64_t slot_count_u64 = static_cast<uint64_t>(slot_count);
    const size_t payload_bytes = sizeof(input_scale) + sizeof(slot_count_u64) + byte_count;

    LOG_VERBOSE("[SEV] RLWE slot decode + bitwise LWE encrypt request: payload="
                << payload_bytes << " bytes, slots=" << slot_count
                << ", expect=" << msg_count << " bytes");
    if (!sev_send_header(sockfd, SEV_REQ_RLWE_SLOT_DEC_LWE_CT, payload_bytes)) {
        return false;
    }
    if (write_full(sockfd, &input_scale, sizeof(input_scale)) != (ssize_t)sizeof(input_scale)) {
        perror("write_full (scale)");
        return false;
    }
    if (write_full(sockfd, &slot_count_u64, sizeof(slot_count_u64)) != (ssize_t)sizeof(slot_count_u64)) {
        perror("write_full (slot_count)");
        return false;
    }
    if (write_full(sockfd, in_buf, byte_count) != (ssize_t)byte_count) {
        perror("write_full");
        return false;
    }

    LOG_STEP("Waiting for bitwise LWE ciphertexts");
    ssize_t r = read_full(sockfd, out_buf, msg_count);
    if (r != (ssize_t)msg_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    LOG_STEP("RLWE->LWE response received");
    return true;
}

static bool sev_remote_lwe_dec_slot_enc(int sockfd,
                             const uint64_t* in_buf,
                             size_t in_u64_count,
                             size_t slot_count,
                             uint64_t* out_buf,
                             size_t out_u64_count) {
    ScopedProfileTimer profileTimer(g_runtime_profile.fhewToCkksSec,
                                    g_runtime_profile.fhewToCkksCalls);
    SevRemoteTimer timer;
    size_t in_bytes = in_u64_count * sizeof(uint64_t);
    size_t out_bytes = out_u64_count * sizeof(uint64_t);
    uint64_t slot_count_u64 = static_cast<uint64_t>(slot_count);
    size_t payload_bytes = sizeof(slot_count_u64) + in_bytes;

    LOG_VERBOSE("[SEV] LWE decrypt + CKKS slot encrypt request: payload="
                << payload_bytes << " bytes, slots=" << slot_count
                << ", expect=" << out_bytes << " bytes");
    if (!sev_send_header(sockfd, SEV_REQ_LWE_DEC_SLOT_ENC, payload_bytes)) {
        return false;
    }
    if (write_full(sockfd, &slot_count_u64, sizeof(slot_count_u64)) != (ssize_t)sizeof(slot_count_u64)) {
        perror("write_full (slot_count)");
        return false;
    }
    if (write_full(sockfd, in_buf, in_bytes) != (ssize_t)in_bytes) {
        perror("write_full");
        return false;
    }
    LOG_STEP("Waiting for packed CKKS membership ciphertext");
    ssize_t r = read_full(sockfd, out_buf, out_bytes);
    if (r != (ssize_t)out_bytes) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    LOG_STEP("LWE->RLWE response received");
    return true;
}

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

static bool sev_remote_reenc_rescale(int sockfd,
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

    LOG_VERBOSE("[SEV] RLWE slot reenc/rescale request: payload="
                << payload_bytes << " bytes, expect=" << byte_count << " bytes");
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
    LOG_STEP("Waiting for RLWE slot reenc/rescale output");
    ssize_t r = read_full(sockfd, out_buf, byte_count);
    if (r != (ssize_t)byte_count) {
        if (r < 0)
            perror("read_full");
        else
            fprintf(stderr, "short read: %zd bytes\n", r);
        return false;
    }
    LOG_STEP("RLWE slot reenc/rescale response received");
    return true;
}


// uint32_t CheckInputFunctionLocal(const std::vector<NativeInteger>& lut, NativeInteger mod) {
//     size_t mid{lut.size() / 2};
//     if (lut[0] == (mod - lut[mid])) {
//         for (size_t i = 1; i < mid; ++i)
//             if (lut[i] != (mod - lut[mid + i]))
//                 return 2;
//         return 0;
//     }
//     if (lut[0] == lut[mid]) {
//         for (size_t i = 1; i < mid; ++i)
//             if (lut[i] != lut[mid + i])
//                 return 2;
//         return 1;
//     }
//     return 2;
// }

// Accelerated summation using a tree structure and parallel processing
Ciphertext<DCRTPoly> EvalSumTree(
    std::vector<Ciphertext<DCRTPoly>> cipherList,
    CryptoContext<DCRTPoly> cc) {
    if (cipherList.empty()) return nullptr;
    while (cipherList.size() > 1) {
        size_t currentSize = cipherList.size();
        size_t nextSize = (currentSize + 1) / 2;
        std::vector<Ciphertext<DCRTPoly>> nextList(nextSize);

        #pragma omp parallel for
        for (size_t i = 0; i < currentSize; i += 2) {
            if (i + 1 < currentSize) {
                nextList[i / 2] = timed_call(g_runtime_profile.otherCkksSec,
                                             g_runtime_profile.otherCkksCalls,
                                             [&] { return cc->EvalAdd(cipherList[i], cipherList[i + 1]); });
            } else {
                nextList[i / 2] = cipherList[i];
            }
        }
        cipherList = std::move(nextList);
    }
    return cipherList[0];
}

static Ciphertext<DCRTPoly> EvalNewtonInverse256Local(ConstCiphertext<DCRTPoly>& x,
                                                      int iterations,
                                                      int dataNum,
                                                      int sev_sock, size_t coeffCount,
                                                      const std::string& keyTag) {
    auto cc = x->GetCryptoContext();
    auto y  = timed_call(g_runtime_profile.otherCkksSec,
                         g_runtime_profile.otherCkksCalls,
                         [&] { return cc->EvalSub(x, x); });
    timed_call(g_runtime_profile.otherCkksSec, g_runtime_profile.otherCkksCalls,
               [&] { cc->EvalAddInPlace(y, 1.0); });

    for (int i = 0; i < iterations; ++i) {
        auto xy = timed_call(g_runtime_profile.otherCkksSec,
                             g_runtime_profile.otherCkksCalls,
                             [&] { return cc->EvalMult(x, y); });
        xy = sev_refresh_ciphertext(xy, sev_sock, coeffCount, keyTag, SEV_SCALE, "Newton x*y");
        auto t = timed_call(g_runtime_profile.otherCkksSec,
                            g_runtime_profile.otherCkksCalls,
                            [&] { return cc->EvalSub(2.0, xy); });
        y = timed_call(g_runtime_profile.otherCkksSec,
                       g_runtime_profile.otherCkksCalls,
                       [&] { return cc->EvalMult(y, t); });
        y = sev_refresh_ciphertext(y, sev_sock, coeffCount, keyTag, SEV_SCALE, "Newton y*(2-xy)");
    }

    auto inv = timed_call(g_runtime_profile.otherCkksSec,
                          g_runtime_profile.otherCkksCalls,
                          [&] { return cc->EvalMult(y, 1.0 / static_cast<double>(dataNum)); });
    inv = sev_refresh_ciphertext(inv, sev_sock, coeffCount, keyTag, SEV_SCALE, "Newton inv/256");
    return inv;
}

/*
    Inverse function evaluation using SEV remote re-encryption service.
    We are using Newton-Raphson method to compute the inverse of a ciphertext
    encrypted value. The input ciphertext is first rescaled using SEV remote
    service, then we perform several iterations of Newton's method locally,
    with re-encryption after each multiplication to manage noise growth.
*/

Ciphertext<DCRTPoly> lut_inverse_fhe(
    Ciphertext<DCRTPoly> cCount,
    CryptoContext<DCRTPoly> cc,
    int sev_sock,
    size_t coeffCount,
    const std::string& keyTag,
    int dataNum) {
    std::vector<uint64_t> in_coeff(coeffCount, 0);
    std::vector<uint64_t> out_coeff(coeffCount, 0);
    in_coeff = extractCiphertextCoeffs(cCount);
    double scale = cCount->GetScalingFactor();
    double targetScale = SEV_SCALE;
    if (!sev_remote_reenc_rescale(sev_sock, in_coeff.data(), coeffCount,
                                  static_cast<long double>(scale),
                                  static_cast<long double>(targetScale),
                                  out_coeff.data())) {
        throw std::runtime_error("SEV reenc (inverse) failed");
    }
    cCount = makeCiphertextFromCoeffs(cc, out_coeff);
    cCount->SetScalingFactor(targetScale);
    cCount->SetScalingFactorInt(NativeInteger(static_cast<uint64_t>(targetScale)));
    cCount->SetKeyTag(keyTag);

    cCount = timed_call(g_runtime_profile.otherCkksSec,
                        g_runtime_profile.otherCkksCalls,
                        [&] { return cc->EvalMult(cCount, 1.0 / static_cast<double>(dataNum)); });
    cCount = sev_refresh_ciphertext(cCount, sev_sock, coeffCount, keyTag, SEV_SCALE, "inverse pre-newton");
    cCount->SetKeyTag(keyTag);
    ConstCiphertext<DCRTPoly> cCountConst = cCount;
    return EvalNewtonInverse256Local(cCountConst, 3, dataNum, sev_sock, coeffCount, keyTag);
}

int main() {

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

    const std::vector<int> dataNumCases = {256, 1024,4096};
    const std::vector<int> centNumCases = { 4, 8};

    for (int dataNum : dataNumCases) {
        for (int centNum : centNumCases) {
            if (dataNum > static_cast<int>(SEV_N / 2)) {
                std::cerr << "DATANUM exceeds available CKKS slots: " << dataNum << std::endl;
                return 1;
            }
            g_runtime_profile = RuntimeProfile{};
            g_sev_remote_time_sec = 0.0;
            std::cout << "\n[CASE] DATANUM=" << dataNum
                      << " CENTNUM=" << centNum << std::endl;

    double wall_start = omp_get_wtime();
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

    CryptoContext<DCRTPoly> cc =  GenCryptoContext(parameters);
    {
        auto elemParams = cc->GetCryptoParameters()->GetElementParams();
        size_t numTowers = elemParams->GetParams().size();
        if (numTowers != SEV_LEVEL) {
            throw std::runtime_error("CKKS tower count mismatch: numTowers=" + std::to_string(numTowers) +
                                     " (expected " + std::to_string(SEV_LEVEL) + ")");
        }
        if (kmeans_verbose_enabled()) {
            std::cout << "[LOG] CKKS params (N=" << ringDim << "):\n";
            for (size_t i = 0; i < numTowers; ++i) {
                const auto& p = elemParams->GetParams()[i];
                std::cout << "  q[" << i << "]=" << p->GetModulus()
                          << " root=" << p->GetRootOfUnity() << '\n';
            }
        }
    }
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    try {
        keys.secretKey = makeSecretKeyFromCoeffs(cc, sevSecretCoeffs, keys.publicKey);
    } catch (const std::exception& e) {
        std::cerr << "SEV secret key load failed: " << e.what() << std::endl;
        return 1;
    }
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 4, 8, 16, 32, 64, 128, -1, -2, -4, -8, -16, -32, -64, -128});

    LOG_VERBOSE("[LWE] SEV n=" << SEV_LWE_N
                << " bit_width=" << SEV_LWE_BIT_WIDTH);
    LOG_STEP("Skipping OpenFHE BTKeyGen; kmeans uses SEV RLWE->LWE and LWE->RLWE.");

    // transpose-style data: one ciphertext per dimension holding all points
    LOG_STEP("Preparing K-means plaintext data");
    std::vector<std::vector<double>> dataValues(DATADIM, std::vector<double>(batchSize, 0.0));
    for (int i = 0; i < dataNum; i++) {
        double baseVal = (i < dataNum / 3) ? 0.1 : 0.9;
        for (int d = 0; d < DATADIM; d++) {
            dataValues[d][i] = baseVal;
        }
    }

    std::vector<std::vector<double>> centValues(centNum, std::vector<double>(DATADIM));
    for (int k = 0; k < centNum; k++) {
        const double centValue = (centNum <= 1) ? 0.0 : static_cast<double>(k) / static_cast<double>(centNum - 1);
        for (int d = 0; d < DATADIM; d++) {
            centValues[k][d] = centValue;
        }
    }

    LOG_STEP("Encrypting data vectors");
    std::vector<Ciphertext<DCRTPoly>> dataDims(DATADIM);
    #pragma omp parallel for
    for (int d = 0; d < DATADIM; d++) {
        dataDims[d] = cc->Encrypt(keys.secretKey, cc->MakeCKKSPackedPlaintext(dataValues[d]));
    }

    LOG_STEP("Encrypting centroid vectors");
    std::vector<std::vector<Ciphertext<DCRTPoly>>> centDims(centNum, std::vector<Ciphertext<DCRTPoly>>(DATADIM));
    #pragma omp parallel for collapse(2)
    for (int k = 0; k < centNum; k++) {
        for (int d = 0; d < DATADIM; d++) {
            std::vector<double> repeated(batchSize, centValues[k][d]);
            centDims[k][d] = cc->Encrypt(keys.secretKey, cc->MakeCKKSPackedPlaintext(repeated));
        }
    }

    double wall_distance_start = omp_get_wtime();
    // distance per centroid over all points (packed)
    // std::vector<Ciphertext<DCRTPoly>> dist(centNum);
    // #pragma omp parallel for
    // for (int k = 0; k < centNum; k++) {
    //     std::vector<Ciphertext<DCRTPoly>> sq_diffs(DATADIM);
    //     // Ciphertext<DCRTPoly> accum = nullptr;
    //     for (int d = 0; d < DATADIM; d++) {
    //         auto diff = cc->EvalSub(dataDims[d], centDims[k][d]);
    //         auto sq = cc->EvalMult(diff, diff);
    //         // sq = sev_refresh_ciphertext(sq, sev_sock, coeffCount, keys.publicKey->GetKeyTag());
    //         // accum = (accum == nullptr) ? sq : cc->EvalAdd(accum, sq);
    //     }
    //     dist[k] = EvalSumTree(sq_diffs, cc);
    //     // dist[k] = accum;
    // }

    std::vector<std::vector<Ciphertext<DCRTPoly>>> sq_matrix(centNum, std::vector<Ciphertext<DCRTPoly>>(DATADIM));

    LOG_STEP("Computing squared distances");
    #pragma omp parallel for collapse(2)
    for (int k = 0; k < centNum; k++) {
        for (int d = 0; d < DATADIM; d++) {
            auto diff = timed_call(g_runtime_profile.otherCkksSec,
                                   g_runtime_profile.otherCkksCalls,
                                   [&] { return cc->EvalSub(dataDims[d], centDims[k][d]); });
            sq_matrix[k][d] = timed_call(g_runtime_profile.otherCkksSec,
                                         g_runtime_profile.otherCkksCalls,
                                         [&] { return cc->EvalMult(diff, diff); });
        }
    }

    // 그 다음 순차적으로 합산
    LOG_STEP("Reducing distances");
    std::vector<Ciphertext<DCRTPoly>> dist(centNum);
    for (int k = 0; k < centNum; k++) {
        dist[k] = EvalSumTree(sq_matrix[k], cc);
    }

    // diff vector (d0 - d1) packed over points
    auto cDiffVec = timed_call(g_runtime_profile.otherCkksSec,
                               g_runtime_profile.otherCkksCalls,
                               [&] { return cc->EvalSub(dist[0], dist[1]); });
    double wall_distance_end = omp_get_wtime();

    std::vector<uint64_t> in_coeff_dec(coeffCount, 0);
    size_t lwe_ct_u64 = SEV_LWE_N + 1;
    const size_t active_slots = dataNum;
    std::vector<uint64_t> diffLweCoeff(active_slots * SEV_LWE_BIT_WIDTH * lwe_ct_u64, 0);

    // Decrypt distance differences via SEV VM and emit bitwise LWE ciphertexts.

    // Encrypt DiffVec into LWE ciphertexts and evaluate sign function
    // p_out for LWE is 2 which means LWE data is binary
    // Therefore, # of LWE ct is same with data type size (e.g., 8 for uint8_t)
    // After LWE ct returned, comparing MSB with 1 to get sign to make masking vector for membership

    /*
    # of LWE = bits of data type * number of data points
    e.g., uint8_t and 1024 data points => 8 * 1024 LWE cts
    Comparison is only needed for # of data points, but LWE encryption is done for all 8*1024 cts
    */

    /*
    SEV must decompose DiffVec into uint8_t values and encrypt each value into LWE ciphertexts
    1. Scale DiffVec into [-128, 127] range
    2. Convert each value into uint8_t representation
    3. Send all uint8_t values to SEV VM for LWE encryption
    4. SEV VM returns all LWE ciphertexts as coefficients
    5. Reconstruct LWE ciphertexts from coefficients
    6. Evaluate sign function on each LWE ciphertexts at MSB
    7. Decrypt sign LWE ciphertexts to get membership values
    8. Pack membership values into CKKS ciphertext
    9. Continue K-means steps as usual
    */
    double wall_membership_start = omp_get_wtime();

    std::vector<uint64_t> diff_rescaled_coeffs(coeffCount, 0);
    auto diff_coeffs = extractCiphertextCoeffs(cDiffVec);
    LOG_STEP("Refreshing distance-diff ciphertext via SEV");
    if (!sev_remote_reenc_rescale(sev_sock, diff_coeffs.data(), coeffCount,
                                  static_cast<long double>(cDiffVec->GetScalingFactor()),
                                  static_cast<long double>(SEV_SCALE),
                                  diff_rescaled_coeffs.data())) {
        std::cerr << "[ERR] SEV distance-diff refresh failed" << std::endl;
        return 1;
    }
    auto cDiffVecRescaled = makeCiphertextFromCoeffs(cc, diff_rescaled_coeffs);
    cDiffVecRescaled->SetKeyTag(keys.publicKey->GetKeyTag());


    in_coeff_dec = extractCiphertextCoeffs(cDiffVecRescaled);
    LOG_STEP("Converting distance-diff slots to bitwise LWE via SEV");
    if (!sev_remote_reenc_slot_dec_lwe_ct(sev_sock, in_coeff_dec.data(), coeffCount,
                                          active_slots,
                                          static_cast<long double>(SEV_SCALE),
                                          diffLweCoeff.data())) {
        std::cerr << "[ERR] SEV RLWE->LWE conversion failed" << std::endl;
        return 1;
    }
    
    std::vector<uint64_t> lwe_batch(active_slots * lwe_ct_u64, 0);

    LOG_STEP("Preparing LWE ciphertexts for membership decryption");
    
    // Using different slot, prepare LWE ciphertexts for LWE decryption + slot encryption
    // Re-arranging LWE ciphertexts from diffLweCoeff to lwe_batch
    #pragma omp parallel for
    for (size_t sev_slot = 0; sev_slot < active_slots; ++sev_slot) {
        size_t bit_offset = (sev_slot * SEV_LWE_BIT_WIDTH) * lwe_ct_u64;
        std::copy(diffLweCoeff.begin() + bit_offset,
                  diffLweCoeff.begin() + bit_offset + lwe_ct_u64,
                  lwe_batch.begin() + (sev_slot * lwe_ct_u64));
    }

    LOG_STEP("Decrypting membership LWE ciphertexts via SEV");

    std::vector<uint64_t> out_coeff(coeffCount, 0);
    if (!sev_remote_lwe_dec_slot_enc(sev_sock, lwe_batch.data(), lwe_batch.size(),
                                     active_slots,
                                     out_coeff.data(), out_coeff.size())) {
        std::cerr << "[ERR] SEV LWE->RLWE conversion failed" << std::endl;
        return 1;
    }
    auto cMembership1 = makeCiphertextFromCoeffs(cc, out_coeff);
    cMembership1->SetKeyTag(keys.publicKey->GetKeyTag());

    LOG_STEP("Packing membership values into CKKS ciphertext");

    auto ptxtOnes = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, 1.0));
    
    auto cMembership0 = cc->EvalSub(ptxtOnes, cMembership1);

    auto ctCount1 = cc->EvalSum(cMembership1, dataNum);
    auto ctCount0 = cc->EvalSum(cMembership0, dataNum); 
    double wall_membership_end = omp_get_wtime();

    LOG_STEP("Encrypted counts obtained");

    double wall_inverse_start = omp_get_wtime();
    auto inv1 = lut_inverse_fhe(ctCount1, cc, sev_sock, coeffCount, keys.publicKey->GetKeyTag(), dataNum);
    auto inv0 = lut_inverse_fhe(ctCount0, cc, sev_sock, coeffCount, keys.publicKey->GetKeyTag(), dataNum);
    double wall_inverse_end = omp_get_wtime();

    LOG_STEP("Inverse ciphertexts computed");
    // {
    //     Plaintext ptInv1;
    //     Plaintext ptInv0;
    //     auto log_ct = [](const char* label, const Ciphertext<DCRTPoly>& ct) {
    //         std::cout << "[LOG] " << label
    //                   << " level=" << ct->GetLevel()
    //                   << " scale=" << ct->GetScalingFactor()
    //                   << " noise_deg=" << ct->GetNoiseScaleDeg()
    //                   << std::endl;
    //     };
    //     log_ct("inv1 pre-decrypt", inv1);
    //     log_ct("inv0 pre-decrypt", inv0);
    //     std::cout << "[LOG] Decrypt inv start" << std::endl;
    //     try {
    //         cc->Decrypt(keys.secretKey, inv1, &ptInv1);
    //         cc->Decrypt(keys.secretKey, inv0, &ptInv0);
    //     }
    //     catch (const OpenFHEException& e) {
    //         std::cerr << "[ERR] Decrypt inv failed: " << e.what() << std::endl;
    //         throw;
    //     }
    //     ptInv1->SetLength(1);
    //     ptInv0->SetLength(1);
    //     auto v1 = ptInv1->GetRealPackedValue();
    //     auto v0 = ptInv0->GetRealPackedValue();
    //     std::cout << "[LOG] inv1=" << (v1.empty() ? 0.0 : v1[0])
    //               << " inv0=" << (v0.empty() ? 0.0 : v0[0]) << std::endl;
    // }

    std::vector<std::vector<Ciphertext<DCRTPoly>>> new_centroids(centNum, std::vector<Ciphertext<DCRTPoly>>(DATADIM));

    double wall_update_start = omp_get_wtime();
    #pragma omp parallel for collapse(2)
    for (int k = 0; k < centNum; k++) {
        for (int d = 0; d < DATADIM; d++) {
            auto masked = timed_call(g_runtime_profile.otherCkksSec,
                                     g_runtime_profile.otherCkksCalls,
                                     [&] { return cc->EvalMult(dataDims[d], (k == 0 ? cMembership0 : cMembership1)); });
            #pragma omp critical(sev_sock)
            {
                masked = sev_refresh_ciphertext(masked, sev_sock, coeffCount, keys.publicKey->GetKeyTag());
            }
            auto sumDim = timed_call(g_runtime_profile.otherCkksSec,
                                     g_runtime_profile.otherCkksCalls,
                                     [&] { return cc->EvalSum(masked, dataNum); });
            new_centroids[k][d] = timed_call(g_runtime_profile.otherCkksSec,
                                             g_runtime_profile.otherCkksCalls,
                                             [&] { return cc->EvalMult(sumDim, (k == 0 ? inv0 : inv1)); });
            #pragma omp critical(sev_sock)
            {
                new_centroids[k][d] = sev_refresh_ciphertext(new_centroids[k][d], sev_sock, coeffCount,
                                                            keys.publicKey->GetKeyTag());
            }

        }
    }
    double wall_update_end = omp_get_wtime();

    if (kmeans_verbose_enabled()) {
        std::cout << "[LOG] SEV slot-dec centroids (first dim, first 5 slots)\n";
        size_t slots = SEV_N / 2;
        std::vector<double> slot_values(slots, 0.0);
        for (int k = 0; k < centNum; ++k) {
            auto coeffs = extractCiphertextCoeffs(new_centroids[k][0]);
            if (coeffs.size() != coeffCount) {
                std::cerr << "[ERR] centroid coeff size mismatch: expected " << coeffCount
                          << ", got " << coeffs.size() << std::endl;
                continue;
            }
            if (!sev_remote_reenc_slot_dec(sev_sock, coeffs.data(), coeffCount, slot_values.data())) {
                std::cerr << "[ERR] sev_remote_reenc_slot_dec failed for centroid " << k << std::endl;
                continue;
            }
            std::cout << "Centroid " << k << " first dim slots:";
            for (size_t i = 0; i < 5 && i < slot_values.size(); ++i) {
                std::cout << " " << slot_values[i];
            }
            std::cout << '\n';
        }
    }

    double wall_end = omp_get_wtime();
    std::cout << "Distance phase wall: " << (wall_distance_end - wall_distance_start) << " s" << std::endl;
    std::cout << "Membership phase wall: " << (wall_membership_end - wall_membership_start) << " s" << std::endl;
    std::cout << "Inverse phase wall: " << (wall_inverse_end - wall_inverse_start) << " s" << std::endl;
    std::cout << "Update phase wall: " << (wall_update_end - wall_update_start) << " s" << std::endl;
    std::cout << "Total wall clock (end-to-end): " << (wall_end - wall_start) << " s" << std::endl;
    std::cout << "SEV time (s): " << g_sev_remote_time_sec << std::endl;
    print_runtime_profile();
        }
    }

    return 0;
}
