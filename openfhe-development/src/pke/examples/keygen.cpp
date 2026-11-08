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
#include "cryptocontext.h"
#include <fstream>

#include <chrono>

#include "key/keypair.h"
#include "key/privatekey.h"
#include "key/publickey.h"

#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"
#include "binfhecontext-ser.h"

#include "resnet.h"
#include "dataset.h"
#include "packed_conv.h"

using namespace lbcrypto;

static const uint32_t CKKS_BOOTSTRAP_MULT_DEPTH = 18;
static const uint32_t CKKS_BOOTSTRAP_CORRECTION_FACTOR = 20;




void parameterSetupAndKeyLoadOrGen(CryptoContext<DCRTPoly>& cc, std::shared_ptr<lbcrypto::BinFHEContext>& ccLWE, KeyPair<DCRTPoly>& keys, LWEPrivateKey& privateKeyFHEW);
std::vector<CIFARImage> loadCIFAR10Binary(const std::string& filename, int numImages = 10000);
std::vector<MNISTImage> loadMNISTImages(const std::string& filename, int numImages = -1);
int reverseInt (int i);

int main() {
    //Init
    CryptoContext<DCRTPoly> cc;
    std::shared_ptr<lbcrypto::BinFHEContext> ccLWE;
    KeyPair<DCRTPoly> keys;
    LWEPrivateKey privateKeyFHEW;
    parameterSetupAndKeyLoadOrGen(cc, ccLWE, keys, privateKeyFHEW);
    // auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision - change later

    /*
    // Inputs
    std::vector<double> x1  = {1,2,4,8,16,32,64,128,256};
    uint32_t encodedLength1 = x1.size();

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext plaintextDec;

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    cc->Decrypt(keys.secretKey, c1, &plaintextDec);
    plaintextDec->SetLength(ptxt1->GetLength());

    std::cout << "Original plaintext: "  << ptxt1 << std::endl;
    std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    */

    return 0;
}

// bool file_exists(const std::string &filename) {
//     std::ifstream file(filename);
//     return file.good();
// }

void parameterSetupAndKeyLoadOrGen(CryptoContext<DCRTPoly>& cc,
                                   std::shared_ptr<lbcrypto::BinFHEContext>& ccLWE,
                                   KeyPair<DCRTPoly>& keys,
                                   LWEPrivateKey& privateKeyFHEW ) {
    // Specify main parameters

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    

    // uint32_t levelsAvailableAfterBootstrap = 14;
    std::vector<uint32_t> levelBudget = {2, 2};
    //usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    uint32_t depth = CKKS_BOOTSTRAP_MULT_DEPTH;

    uint32_t multDepth    = depth;
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

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys
    std::string pkFile = "public.key";
    std::string skFile = "secret.key";
    std::string mkFile = "mult.key";
    std::string rkFile = "rot.key";

    std::string lweSkFile = "lwesk.key";

    //TFHE Evks
    std::string refKeyFile = "ref.key";
    std::string kswKeyFile = "ksw.key";

    //CryptoContext
    std::string ccFile = "cc.key";

    PublicKey<DCRTPoly>     pk;
    PrivateKey<DCRTPoly>    sk;


    //Load or generate keys ...
    if(file_exists(pkFile) && file_exists(skFile) && file_exists(mkFile) && file_exists(rkFile)) {
        std::cout << "Test keys found, loading from " << skFile << std::endl;
        try
        {
            std::ifstream pkif(pkFile, std::ios::binary);
            std::ifstream skif(skFile, std::ios::binary);
            std::ifstream multKeyIStream(mkFile, std::ios::in | std::ios::binary);
            std::ifstream rotKeyIStream(rkFile, std::ios::in | std::ios::binary);
            
            Serial::Deserialize( pk, pkif, SerType::BINARY);
            Serial::Deserialize( sk, skif, SerType::BINARY);
            cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY);
            cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY);
            

            keys.publicKey = pk;
            keys.secretKey = sk;
        }
        catch(const std::exception& e)
        {
            std::cout << "Failed to load Keys" << skFile << std::endl;
            
            std::cout << "Test keys not found, Generating ..." << std::endl;
            keys = cc->KeyGen();

            cc->EvalMultKeyGen(keys.secretKey);
            cc->EvalRotateKeyGen(keys.secretKey, {1});

            //cc->EvalRotateKeyGen(keys.secretKey, {1, -2});


            std::cout << "Saving test keys to " << skFile << std::endl;
            pk = keys.publicKey;
            sk = keys.secretKey;

            std::ofstream pkof(pkFile, std::ios::binary);
            std::ofstream skof(skFile, std::ios::binary);
            std::ofstream multKeyFile(mkFile, std::ios::out | std::ios::binary);
            std::ofstream rotationKeyFile(rkFile, std::ios::out | std::ios::binary);

            Serial::Serialize(pk, pkof, SerType::BINARY);
            Serial::Serialize(sk, skof, SerType::BINARY);
            cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY);
            cc->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY);

        }
    }        
    else {
        std::cout << "Test keys not found, Generating ..." << std::endl;
        keys = cc->KeyGen();

        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalRotateKeyGen(keys.secretKey, {1});



        std::cout << "Saving test keys to " << skFile << std::endl;
        pk = keys.publicKey;
        sk = keys.secretKey;

        std::ofstream pkof(pkFile, std::ios::binary);
        std::ofstream skof(skFile, std::ios::binary);
        std::ofstream multKeyFile(mkFile, std::ios::out | std::ios::binary);
        std::ofstream rotationKeyFile(rkFile, std::ios::out | std::ios::binary);

        Serial::Serialize(pk, pkof, SerType::BINARY);
        Serial::Serialize(sk, skof, SerType::BINARY);
        cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY);
        cc->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY);
    }

    std::cout << "Regenerating CKKS keys for bootstrap depth " << CKKS_BOOTSTRAP_MULT_DEPTH << std::endl;
    keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1});
    {
        std::vector<uint32_t> bootstrapLevelBudget = {2, 2};
        std::vector<uint32_t> bootstrapBsgsDim     = {0, 0};
        cc->EvalBootstrapSetup(bootstrapLevelBudget, bootstrapBsgsDim, slots, CKKS_BOOTSTRAP_CORRECTION_FACTOR);
        cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    }
    pk = keys.publicKey;
    sk = keys.secretKey;
    {
        std::ofstream pkof(pkFile, std::ios::binary);
        std::ofstream skof(skFile, std::ios::binary);
        std::ofstream multKeyFile(mkFile, std::ios::out | std::ios::binary);
        std::ofstream rotationKeyFile(rkFile, std::ios::out | std::ios::binary);

        Serial::Serialize(pk, pkof, SerType::BINARY);
        Serial::Serialize(sk, skof, SerType::BINARY);
        cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY);
        cc->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY);
    }

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

    // Perform the precomputation for switching and persist the bootstrap-capable context.
    cc->EvalCKKStoFHEWPrecompute(scale1);
    Serial::SerializeToFile(ccFile, cc, SerType::BINARY);

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

    //TODO : Save & Load these
    //cc->EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE);
    //cc->EvalFHEWtoCKKSKeyGen(keys, privateKeyFHEW);

    //std::vector<uint32_t> levelBudget = {2, 2};

    //cc->EvalBootstrapSetup(levelBudget);
    //cc->EvalBootstrapKeyGen(keys.secretKey, slots);
    

}




std::vector<CIFARImage> loadCIFAR10Binary(const std::string& filename, int numImages) {
    const int imageSize = 3072;   // 3 * 32 * 32
    // const int recordSize = 1 + imageSize;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open CIFAR-10 file: " + filename);
    }

    std::vector<CIFARImage> dataset;
    dataset.reserve(numImages);

    for (int i = 0; i < numImages; i++) {
        CIFARImage img;
        char label;
        file.read(&label, 1);
        img.label = static_cast<uint8_t>(label);

        img.pixels.resize(imageSize);
        file.read(reinterpret_cast<char*>(img.pixels.data()), imageSize);
        
        if (!file) {
            throw std::runtime_error("Error reading image " + std::to_string(i) + " from " + filename);
        }

        for (int c = 0; c < 3; c++) {
            for (int y = 0; y < 32; y++)
            {
                for (int x = 0; x < 32; x++)
                {
                    img.img[c][y][x] = img.pixels[(c*1024 + y*32 + x)];

                }
            }
        }
        

        dataset.push_back(std::move(img));
    }

    return dataset;
}


int reverseInt (int i) 
{
    unsigned char c1, c2, c3, c4;

    c1 = i & 255;
    c2 = (i >> 8) & 255;
    c3 = (i >> 16) & 255;
    c4 = (i >> 24) & 255;

    return ((int)c1 << 24) + ((int)c2 << 16) + ((int)c3 << 8) + c4;
}

std::vector<MNISTImage> loadMNISTImages(const std::string& filename, int numImages) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open MNIST image file: " + filename);
    }

    int magic_number = 0, number_of_images = 0, n_rows = 0, n_cols = 0;
    file.read(reinterpret_cast<char*>(&magic_number), sizeof(magic_number));
    magic_number = reverseInt(magic_number);
    file.read(reinterpret_cast<char*>(&number_of_images), sizeof(number_of_images));
    number_of_images = reverseInt(number_of_images);
    file.read(reinterpret_cast<char*>(&n_rows), sizeof(n_rows));
    n_rows = reverseInt(n_rows);
    file.read(reinterpret_cast<char*>(&n_cols), sizeof(n_cols));
    n_cols = reverseInt(n_cols);

    if (numImages < 0 || numImages > number_of_images) {
        numImages = number_of_images;
    }

    std::vector<MNISTImage> dataset;
    dataset.reserve(numImages);

    for (int i = 0; i < numImages; ++i) {
        MNISTImage img(n_rows, n_cols);
        file.read(reinterpret_cast<char*>(img.pixels.data()), n_rows * n_cols);

        for (int y = 0; y < n_rows; ++y) {
            for (int x = 0; x < n_cols; ++x) {
                uint8_t pixel = img.pixels[y * n_cols + x];
                img.img[0][y][x] = pixel;  
                img.img[1][y][x] = 0; 
                img.img[2][y][x] = 0;
            }
        }
        dataset.push_back(std::move(img));
    }

    return dataset;
}
