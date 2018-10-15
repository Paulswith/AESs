# -*- coding:utf-8 -*-
# __author:dobby
# desc:

from Crypto.Cipher import AES   # install follow : pip install pycryptodome
import base64, io, os


CBC_LENS = 16

class CipherMode:
    ''' enum: 加解密模式 '''
    TypeEncrypt = 0xfe,
    TypeDecrypt = 0xff


class PaddingMode:
    ''' enum: padding模式 '''
    TypePadding = 0xfc,
    TypeUnpadding = 0xfd


class AESCipher(object):
    def __init__( self, key, iv):
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')

    def encrypt(self, raw):
        """
          加密,先AES再base64
        """
        p_raw = self._padding(
            raw,
            handle_mode=PaddingMode.TypePadding
        )
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self._base64_handle(
            cipher.encrypt(p_raw),
            handle_mode=CipherMode.TypeEncrypt
        )

    def decrypt(self, enc):
        """
         解密,先base64再AES
        """
        d64_enc = self._base64_handle(enc, handle_mode=CipherMode.TypeDecrypt)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self._padding(
            cipher.decrypt(d64_enc).decode('utf-8'),
            handle_mode=PaddingMode.TypeUnpadding
        )

    def _base64_handle(self, content, handle_mode=CipherMode.TypeDecrypt):
        '''
          base-64
        '''
        if not isinstance(content, bytes):  # 非byte需要转一下
            content = content.encode('utf-8')

        if handle_mode == CipherMode.TypeDecrypt:
            return base64.decodebytes(content)
        else:
            return base64.encodebytes(content)

    def _padding(self, padding_str, handle_mode=PaddingMode.TypePadding):
        '''
          padding
        '''
        if handle_mode == PaddingMode.TypePadding:
            return (padding_str + (CBC_LENS - len(padding_str) % CBC_LENS) *
                    chr(CBC_LENS - len(padding_str) % CBC_LENS)).encode('utf-8')
        else:
            return padding_str[0:-ord(padding_str[-1])]


class CryptTool:
    @classmethod
    def decryption_save(self, cipher_key_iv, file_path, save_path=None):
        '''
          解密存储
        :param cipher_key_iv:(key, iv)
        :param file_path:解密的文件路径
        :param save_path:解密后存储的路径, 不指定则覆盖原先的文件
        '''
        if not isinstance(cipher_key_iv, tuple) or len(cipher_key_iv) != 2:
            raise KeyError("Cipher must type tuple, values is (key, iv).")

        if (not os.path.exists(file_path)) or (not os.path.isfile(file_path)):
            raise FileNotFoundError("Can't found handle file.")

        aes_cbc = AESCipher(cipher_key_iv[0], cipher_key_iv[1])

        if not save_path:
            save_path = file_path
        with io.open(file_path, mode='r') as f:
            rs_de_content = aes_cbc.decrypt(f.read())
            with io.open(save_path, mode='w') as f:
                f.write(rs_de_content)

    @classmethod
    def encryption_save(self, cipher_key_iv, file_path, save_path=None):
        '''
          加密存储
        :param cipher_key_iv:(key, iv)
        :param file_path:待加密的文件路径
        :param save_path:加密后存储的路径, 不指定则覆盖原先的文件
        '''
        if not isinstance(cipher_key_iv, tuple) or len(cipher_key_iv) != 2:
            raise KeyError("Cipher must type tuple, values is (key, iv).")

        if (not os.path.exists(file_path)) or (not os.path.isfile(file_path)):
            raise FileNotFoundError("Can't found handle file.")

        aes_cbc = AESCipher(cipher_key_iv[0], cipher_key_iv[1])
        if not save_path:
            save_path = file_path
        with io.open(file_path, mode='r') as f:
            rs_content = aes_cbc.encrypt(f.read())
            with io.open(save_path, mode='wb') as f:  # 字节写入
                f.write(rs_content)

    @classmethod
    def decryption(cls, cipher_key_iv, content):
        '''
          解密
        :param cipher_key_iv:(key, iv)
        :param content:解密的文本str
        '''
        if not isinstance(cipher_key_iv, tuple) or len(cipher_key_iv) != 2:
            raise KeyError("Cipher must type tuple, values is (key, iv).")

        aes_cbc = AESCipher(cipher_key_iv[0], cipher_key_iv[1])
        return aes_cbc.decrypt(content)

    @classmethod
    def encryption(cls, cipher_key_iv, cipher):
        '''
          加密
        :param cipher_key_iv:(key, iv)
        :param cipher:待加密文本 str
        '''
        if not isinstance(cipher_key_iv, tuple) or len(cipher_key_iv) != 2:
            raise KeyError("Cipher must type tuple, values is (key, iv).")

        aes_cbc = AESCipher(cipher_key_iv[0], cipher_key_iv[1])
        return aes_cbc.encrypt(cipher).decode('utf-8')


if __name__== "__main__":
    CryptTool.decryption_save(('i5tah*gw37JOHT==', '1dd89`X3nVfmchm?'),
                        os.path.join(os.getcwd(), 'example_will_decrypt.xml'),
                        os.path.join(os.getcwd(), 'example_decrypt_result.xml'))

    CryptTool.encryption_save(('i5tah*gw37JOHT==', '1dd89`X3nVfmchm?'),
                         os.path.join(os.getcwd(), 'example_will_encrypt.xml'),
                         os.path.join(os.getcwd(), 'example_encrypt_result.xml'))

