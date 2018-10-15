//
//  CryptHandle.m
//  CryptoPP_OC
//
//  Created by Dobby on 2018/10/11.
//  Copyright © 2018 dobby. All rights reserved.
//

#import "CryptHandle.h"

#include <string>
using std::string;

#include "filters.h"
using CryptoPP::SecByteBlock;

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


#pragma mark - AES_CBC_Cryption~interface
class AES_CBC_Cryption
{
public:
    explicit AES_CBC_Cryption(const string& key, const string& iv) {
        initialKeyWithIv(key, iv);
    };
    
    /*
     * :cipherContent 待解密文本
     * :resultFilePath 解密完文本
     * ret:bool 过程是否成功.
     */
    bool handleDecryption(const string& cipherContent, string& resultContent);
    
    /*
     * :normalContent 待加密文本
     * :resultFilePath 加密完文本
     * ret:bool 过程是否成功.
     */
    bool handleEncryption(const string& normalContent, string& resultContent);
    
    /* [ 读取文件->b64Decode(option)->解密->写入到文件 ]
     * :cipherFilePath 待解密文件的路径
     * :resultFilePath 解密完写入的路径
     * ret:bool 过程是否成功.
     */
    bool handleDecryptionWithFile(const string& cipherFilePath, const string& resultFilePath);
    
    /* [ 读取文件->加密->b64Encode(option)->写入到文件 ]
     * :normalFilePath 待加密文件的路径
     * :resultFilePath 加密完写入的路径
     * ret:bool 过程是否成功.
     */
    bool handleEncryptionWithFile(const string& normalFilePath, const string& resultFilePath);
    
    
private:
    SecByteBlock crypt_key;
    SecByteBlock crypt_iv;
    
    inline void initialKeyWithIv(const string& key, const string& iv) {
        generateBlock(key, crypt_key);
        generateBlock(iv, crypt_iv);
    }; // 设置key-iv
    
    // 生成key-iv:
    void generateBlock(const string& key_o_iv, SecByteBlock& block);
    
    //  base64
    string decodeB64(const string& decodeText);
    string encodeB64(const string& encodeText);
    
    // 读写文本
    bool readFile(const string& readFilePath, string& readFileContent);
    bool writeFile(const string& writeFilePath, const string& writeToFileContent);
    
    // CBC_AES:
    void m_decryptionStart(const string& cipher, string& retContent);
    
    void m_encryptionStart(const string& beCipher, string& retContent);
};

#pragma mark - AES_CBC_Cryption~implement
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


#pragma mark - CryptHandle~implement

@implementation CryptHandle
+ (std::string)convertToStdstr:(NSString *)normalStr
{
    return std::string([normalStr UTF8String]);
}

+ (NSString *)convertToNsstr:(std::string)text
{
    return [NSString stringWithUTF8String:text.c_str()];
}

+ (AES_CBC_Cryption)initialAesObject:(NSString *)key iv:(NSString *)iv
{
    return AES_CBC_Cryption([self convertToStdstr:key],
                            [self convertToStdstr:iv]);
}

+ (NSString *)encryption:(NSString *)text
                 withKey:(NSString *)key Iv:(NSString *)iv
{
    std::string result;
    bool isSuc = [self initialAesObject:key iv:iv].handleEncryption([self convertToStdstr:text], result);
    if (isSuc) {
        return [self convertToNsstr:result];
    }
    return nil;
}

+ (NSString *)decryption:(NSString *)text
                 withKey:(NSString *)key Iv:(NSString *)iv
{
    std::string result;
    bool isSuc = [self initialAesObject:key iv:iv].handleDecryption([self convertToStdstr:text], result);
    if (isSuc) {
        return [self convertToNsstr:result];
    }
    return nil;
}

+ (bool)encryptionFromFilePath:(NSString *)readPath
                    toFilePath:(NSString *)resultSavePath withKey:(NSString *)key Iv:(NSString *)iv
{
    return [self initialAesObject:key iv:iv].handleEncryptionWithFile([self convertToStdstr:readPath],
                                                                      [self convertToStdstr:resultSavePath]);
}

+ (bool)decryptionFromFilePath:(NSString *)readPath
                    toFilePath:(NSString *)resultSavePath withKey:(NSString *)key Iv:(NSString *)iv
{
    
    return [self initialAesObject:key iv:iv].handleDecryptionWithFile([self convertToStdstr:readPath],
                                                                      [self convertToStdstr:resultSavePath]);
}

@end
