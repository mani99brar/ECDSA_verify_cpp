#include <iostream>
#include "CkCrypt2.h"
#include "CkPrivateKey.h"
#include "CkPrng.h"
#include "CkEcc.h"
#include "CkPublicKey.h"

bool verifyMetamaskSignature(const std::string& message, const std::string& signature) {
    // Use Chilkat Crypt2 to generate a hash for the message.
    CkCrypt2 crypt;
    crypt.put_HashAlgorithm("SHA256");
    crypt.put_Charset("utf-8");
    crypt.put_EncodingMode("base64");

    const char *hash = crypt.hashStringENC(message.c_str());

    // Load the ECC public key used by Metamask for verification.
    CkPublicKey pubKey;
    bool success = pubKey.LoadFromFile("path_to_metamask_public_key.pem");
    if (success != true) {
        std::cout << pubKey.lastErrorText() << "\r\n";
        return false;
    }

    // Verify the Metamask signature.
    CkEcc ecdsa;
    int result = ecdsa.VerifyHashENC(hash, signature.c_str(), "base64", pubKey);
    if (result == 1) {
        std::cout << "Signature is valid." << "\r\n";
        return true;
    } else if (result == 0) {
        std::cout << "Signature is invalid." << "\r\n";
        return false;
    } else {
        std::cout << ecdsa.lastErrorText() << "\r\n";
        std::cout << "The VerifyHashENC method call failed." << "\r\n";
        return false;
    }
}

int main() {
     std::string message = "personal_sign"; // Replace with your message.
    std::string signature = "0x32c98ebdd64b16f75c85bc044e1de118188b34c5b91443b2a2a1109c61551d42295d10291f30e331fb886cb685515a978f0c2fbfd545bf6476077cdabba8cdd71b"; // Replace with your Metamask signature.

    bool isSignatureValid = verifyMetamaskSignature(message, signature);

    if (isSignatureValid) {
        std::cout << "Metamask signature is valid." << "\r\n";
    } else {
        std::cout << "Metamask signature is invalid." << "\r\n";
    }

    return 0;
}
