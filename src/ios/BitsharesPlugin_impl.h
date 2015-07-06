//
//  BitsharesPlugin.h
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

@interface BitsharesPlugin_impl:NSObject

+(NSMutableData*) BTCSHA512:(NSData*)data;
+(NSMutableData*) BTCSHA256:(NSData*) data;
+(NSData*) btsDecodePubkey:(NSString*)epub with_test:(BOOL)is_test;
+(NSString*) createMasterKey ;
+(NSDictionary *) extractDataFromKey:(NSString*)extendedKey withTest:(BOOL)is_test;
+(NSString *) derivePrivate:(NSString*)extendedKey withDeriv:(int)deriv withTest:(BOOL)is_test;
+(NSString*) extendedPublicFromPrivate:(NSString*)extendedKey;
+(NSString*) encryptString:(NSString*)plaintext withKey:(NSString*)key;
+(NSString*) decryptString:(NSString*)ciphertext withKey:(NSString*)key;
+(NSString*) btsPubToAddress:(NSString*)pubkey with_test:(BOOL)is_test;
+(BOOL) isValidKey:(NSString*)key ;
+(BOOL) isValidWif:(NSString*)wif;
+(NSString*) compactSignatureForHash:(NSString*)hash wif:(NSString*)wif;
+(NSString*) btsWifToAddress:(NSString*)wif with_test:(BOOL)is_test;
+(BOOL) btsIsValidAddress:(NSString*)addy with_test:(BOOL)is_test;
+(BOOL) btsIsValidPubkey:(NSString*)pubkey with_test:(BOOL)is_test;
+(NSString*) compactSignatureForMessage:(NSString*)msg wif:(NSString*)wif;

+(NSString*) btsEncodePubkey:(NSData*)pubkey with_test:(BOOL)is_test;
+(BOOL) btcIsValidAddress:(NSString*)addy with_test:(BOOL)is_test;

+(NSString*) requestSignature:(NSString*)key withNonce:(int)nonce withUrl:(NSString*)url withBody:(NSString*)body;

+(NSDictionary*) createMemo:(NSString*)fromPubkey withDestPubkey:(NSString*)destPubkey withMessage:(NSString*)message           withOneTimePriv:(NSString*)oneTimePriv with_test:(BOOL)is_test;

+(NSDictionary*) decryptMemo:(NSString*)oneTimeKey withEncryptedMemo:(NSString*)encryptedMemo withPrivkey:(NSString*)privKey           with_test:(BOOL)is_test;

+(NSString*) createMnemonic:(int)entropy;

+(NSString*) mnemonicToMasterKey:(NSString*)words;

+(NSString *) sha256:(NSString *) data;

+(u_int32_t)randomInteger;

+(NSString*)randomData:(int)length;

+(uint32_t)skip32:(uint32_t)value withSkip32Key:(NSString*) skip32Key withEncrypt:(BOOL)encrypt;

+(NSString*)pbkdf2:(NSString*) password withSalt:(NSString*) salt withC:(int)c withDKeyLen:(int)dkLen;
@end
