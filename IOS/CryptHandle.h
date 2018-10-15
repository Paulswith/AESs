//
//  CryptHandle.h
//  CryptoPP_OC
//
//  Created by Dobby on 2018/10/11.
//  Copyright © 2018 dobby. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface CryptHandle : NSObject

/*
 加解密文本
 */
+ (NSString *)encryption:(NSString *)text
                 withKey:(NSString *)key Iv:(NSString *)iv;
+ (NSString *)decryption:(NSString *)text
                 withKey:(NSString *)key Iv:(NSString *)iv;

/*
 加解密文件
 */
+ (bool)encryptionFromFilePath:(NSString *)readPath
                    toFilePath:(NSString *)resultSavePath withKey:(NSString *)key Iv:(NSString *)iv;

+ (bool)decryptionFromFilePath:(NSString *)readPath
                    toFilePath:(NSString *)resultSavePath withKey:(NSString *)key Iv:(NSString *)iv;

@end

NS_ASSUME_NONNULL_END
