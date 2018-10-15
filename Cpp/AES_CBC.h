#include <string>
using std::string;

#include "filters.h"
using CryptoPP::SecByteBlock;


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