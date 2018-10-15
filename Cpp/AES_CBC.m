#include "AES_CBC.h"
#include <iostream>
using std::cout;
using std::endl;

#include <fstream>
#include <streambuf>
#include <sstream>
using std::ifstream;
using std::ofstream;
using std::exception;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;

using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::byte;


// byte[]定义可能会导致\0结尾,导致15位. 直接生成Block这种方法不会.但是给的key_o_iv大于16只取16;
void AES_CBC_Cryption::generateBlock(const string& key_o_iv, SecByteBlock& block)
{
    if (key_o_iv.size() < AES::DEFAULT_KEYLENGTH) {
        throw Exception(Exception::INVALID_ARGUMENT, "Generate to block string, size can't less than 16.");
    }
    block.Assign(reinterpret_cast<const byte*>(&key_o_iv[0]), AES::DEFAULT_KEYLENGTH);
    
    // the block has encoding problem, cout-func unable print. convert to hex-16:
    string encoded;
    StringSource(block, AES::DEFAULT_KEYLENGTH,
                 true,new HexEncoder(new StringSink(encoded))); // StringSource
}

bool AES_CBC_Cryption::handleDecryptionWithFile(const string& cipherFilePath,
                                                const string& resultFilePath)
{
    string readFileContent, result;
    if (!readFile(cipherFilePath, readFileContent)) {
//        cout << "Read file error!" << endl;
        return false;
    }
    if (!handleDecryption(readFileContent, result)) return false;
    if (!writeFile(resultFilePath, result)) return false;
    return true;
}

bool AES_CBC_Cryption::handleEncryptionWithFile(const string& normalFilePath,
                                                const string& resultFilePath)
{
    string readContent, cipher;
    if (!readFile(normalFilePath, readContent)) {
//        cout << "Read file error!" << endl;
        return false;
    }
    if (!handleEncryption(readContent, cipher)) return false;
    if (!writeFile(resultFilePath, cipher)) return false;
    return true;
}


bool AES_CBC_Cryption::handleDecryption(const string& cipherContent, string& resultContent)
{
    try {
        resultContent.clear();
        m_decryptionStart(decodeB64(cipherContent),
                          resultContent);
    }catch (const exception &ex) {
        cout << "Decryption faild: " << ex.what() << endl;
        return false;
    }
    return true;
}

bool AES_CBC_Cryption::handleEncryption(const string& normalContent, string& resultContent)
{
    try {
        string cryptResult;
        m_encryptionStart(normalContent,
                          cryptResult);
        resultContent.clear();
        resultContent = encodeB64(cryptResult);
    }catch (...) {
        return false;
    }
    return true;
}

string AES_CBC_Cryption::decodeB64(const string& decodeText)
{
    string decoded;
    Base64Decoder decoder;
    decoder.Put(reinterpret_cast<const byte*>(decodeText.data()), decodeText.size());
    decoder.MessageEnd();
    
    auto size = decoder.MaxRetrievable();
    if(size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }
    return decoded;
}

string AES_CBC_Cryption::encodeB64(const string& encodeText)
{
    string encoded;
    Base64Encoder encoder;
    // string 强转byte来进行才可以进行扰乱
    encoder.Put(reinterpret_cast<const byte*>(encodeText.data()), encodeText.size());
    encoder.MessageEnd();
    
    auto size = encoder.MaxRetrievable();
    if(size)
    {
        encoded.resize(size);
        encoder.Get((byte*)&encoded[0], encoded.size());
    }
    return encoded;
}

bool AES_CBC_Cryption::readFile(const string& readFilePath, string& readFileContent)
{
    bool isSuc = true;
    try {
        ifstream in(readFilePath);
        std::stringstream buffer;
        buffer << in.rdbuf();
        string content(buffer.str());
        readFileContent = content; // 拷贝赋值
    }catch(const Exception& readEx) {
        cout << readEx.what() << endl;
        isSuc = false;
    }
    return isSuc;
}

bool AES_CBC_Cryption::writeFile(const string& writeFilePath, const string& writeToFileContent)
{
    bool isSuc = true;
    try {
        ofstream osWrite(writeFilePath);
        osWrite << writeToFileContent << endl;
    }catch(const exception& writeEx) {
        isSuc = false;
        cout << "write to File Error: " << writeEx.what() << endl;
    }
    return isSuc;
}

void AES_CBC_Cryption::m_decryptionStart(const string& cipher, string& retContent)
{
    CBC_Mode< AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(crypt_key, AES::DEFAULT_KEYLENGTH, crypt_iv);
    StringSource s(cipher, true,
                   new StreamTransformationFilter(decryptor,
                                                  new StringSink(retContent),
                                                  StreamTransformationFilter::PKCS_PADDING
                                                  ) // StreamTransformationFilter
                   ); // StringSource
}

void AES_CBC_Cryption::m_encryptionStart(const string& beCipher, string& retContent)
{
    CBC_Mode< AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(crypt_key, AES::DEFAULT_KEYLENGTH, crypt_iv);
    StringSource s(beCipher, true,
                   new StreamTransformationFilter(encryptor,
                                                  new StringSink(retContent),
                                                  StreamTransformationFilter::PKCS_PADDING
                                                  ) // StreamTransformationFilter
                   ); // StringSource
}
