#import <Foundation/Foundation.h>

@interface NSData (NSData_Conversion)

#pragma mark - String Conversion
- (NSString *)hexadecimalString;
@end

@implementation NSData (NSData_Conversion)
#pragma mark - String Conversion
- (NSString *)hexadecimalString {
    /* Returns hexadecimal string of NSData. Empty string if data is empty.   */
    
    const unsigned char *dataBuffer = (const unsigned char *)[self bytes];
    
    if (!dataBuffer)
        return [NSString string];
    
    NSUInteger          dataLength  = [self length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    
    return [NSString stringWithString:hexString];
}
@end


#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <CoreBitcoin/CoreBitcoin.h>
#import "RNOpenSSLEncryptor.h"
#import "RNOpenSSLDecryptor.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

#if BTCDataRequiresOpenSSL
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#endif

void skip32 (unsigned char *key, unsigned char* buf, int encrypt);

#import "BitsharesPlugin_impl.h"
@implementation BitsharesPlugin_impl



NSString * const PROD_PREFIX = @"BTS";
NSString * const TEST_PREFIX = @"DVS";

// Utils
+(NSMutableData*) BTCSHA512:(NSData*)data
{
  if (!data) return nil;
  unsigned char digest[CC_SHA512_DIGEST_LENGTH];
  CC_SHA512([data bytes], (CC_LONG)[data length], digest);
  
  NSMutableData* result = [NSMutableData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
  BTCSecureMemset(digest, 0, CC_SHA512_DIGEST_LENGTH);
  return result;
}

+(NSMutableData*) BTCSHA256:(NSData*) data
{
  if (!data) return nil;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256([data bytes], (CC_LONG)[data length], digest);
  
  NSMutableData* result = [NSMutableData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
  BTCSecureMemset(digest, 0, CC_SHA256_DIGEST_LENGTH);
  return result;
}

+(NSData*) btsDecodePubkey:(NSString*)epub with_test:(BOOL)is_test{
    
  if (![epub hasPrefix:(is_test?TEST_PREFIX:PROD_PREFIX)]) {
    return nil;
  }
  
  NSMutableData *data = BTCDataFromBase58([epub substringFromIndex:3]);
  if (data.length != 37) {
    return nil;
  }
  
  NSData *c1 = [data subdataWithRange:NSMakeRange(33, 4)];
  if(!c1) return nil;
  NSData *pubkey_data = [data subdataWithRange:NSMakeRange(0, 33)];
  if(!pubkey_data) return nil;
  
  NSData *c2 = BTCRIPEMD160(pubkey_data);
  if(!c2) return nil;

  const unsigned char *p1 = [c1 bytes];
  const unsigned char *p2 = [c2 bytes];
  
  if(!((p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3])))
    return nil;
  
  return pubkey_data;
}


//Impl
+(NSString*) createMasterKey {

  NSLog(@"#--createMasterKey:: about to create seed");
  NSMutableData* seed = BTCRandomDataWithLength(32);
  
  NSLog(@"createMasterKey:: about to create key");
  BTCKeychain* masterChain = [[BTCKeychain alloc] initWithSeed:seed];

  return masterChain.extendedPrivateKey;
}

+(NSDictionary *) extractDataFromKey:(NSString*)extendedKey withTest:(BOOL)is_test {
  BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];
  NSData* pubKey    = eKey.publicKeychain.key.publicKey;

  BTCKey *theKey = [[BTCKeychain alloc] initWithExtendedKey:eKey.extendedPrivateKey].key;
  NSString *strPubKey  = [BitsharesPlugin_impl btsEncodePubkey:pubKey with_test:is_test];
  NSString *addy       = [BitsharesPlugin_impl btsPubToAddress:strPubKey with_test:is_test];
  NSString *strPrivKey = theKey.WIF;
  NSString *hexPrivKey = [theKey.privateKey hexadecimalString];
    
  return @{@"addy":addy, @"pubkey":strPubKey, @"privkey":strPrivKey, @"privkey_hex":hexPrivKey};
}

+(NSString *) derivePrivate:(NSString*)extendedKey withDeriv:(int)deriv withTest:(BOOL)is_test {

  BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];
  BTCKeychain* dKey = [eKey derivedKeychainAtIndex:deriv hardened:TRUE];

  return dKey.extendedPrivateKey;
}

+(NSString*) extendedPublicFromPrivate:(NSString*)extendedKey {
    BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];
    return eKey.extendedPublicKey;
}

+(NSString*) encryptString:(NSString*)plaintext withKey:(NSString*)key {

  NSData *data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
  NSError *error;
  NSData *encryptedData = [RNOpenSSLEncryptor encryptData  : data
                                              withSettings : kRNCryptorAES256Settings
                                              password     : key
                                              error        : &error];
  
  if ([encryptedData respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
    return [encryptedData base64EncodedStringWithOptions:kNilOptions];  // iOS 7+
  }
  return [encryptedData base64Encoding];                              // pre iOS7
}

+(NSString*) decryptString:(NSString*)ciphertext withKey:(NSString*)key {
    
  NSData *data;
  if ([NSData instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)]) {
      data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:0]; // iOS 7+
  } else {
      data = [[NSData alloc] initWithBase64Encoding:ciphertext];                // pre iOS7
  }
  
  NSError *error;
  NSData *decryptedData = [RNOpenSSLDecryptor decryptData  : data
                                              withSettings : kRNCryptorAES256Settings
                                              password     : key
                                              error        : &error];
  return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

+(BOOL) isValidKey:(NSString*)key {
  BTCKey* btc_key = [[BTCKey alloc] initWithPrivateKey:[key dataUsingEncoding:NSUTF8StringEncoding]];
  return [btc_key.privateKeyAddress isKindOfClass:[BTCPrivateKeyAddress class]];
}

+(BOOL) isValidWif:(NSString*)wif {

  // Es asi, ver BTCKey
  @try {
    BTCPrivateKeyAddress* addr = [BTCPrivateKeyAddress addressWithBase58String:wif];
    NSLog(@"#-- Wif IS VALID!!");
  }
  @catch (NSException *exception) {
    NSLog(@"#-- %@", exception.reason);
    return FALSE;
  }

  return TRUE;
}

+(NSString*) compactSignatureForHash:(NSString*)hash wif:(NSString*)wif{
  BTCKey *key = [[BTCKey alloc] initWithWIF:wif];
  return BTCHexStringFromData( [key compactSignatureForHash:BTCDataWithHexString(hash)] );
}

+(NSString*) btsWifToAddress:(NSString*)wif with_test:(BOOL)is_test{
  NSString *pubkey = [BitsharesPlugin_impl btsEncodePubkey:[[BTCKey alloc] initWithWIF:wif].compressedPublicKey with_test:is_test];
  return [BitsharesPlugin_impl btsPubToAddress:pubkey  with_test:is_test];
}


+(NSString*) btsPubToAddress:(NSString*)pubkey with_test:(BOOL)is_test{

  NSData* pubkey_data = [BitsharesPlugin_impl btsDecodePubkey:pubkey with_test:is_test];

  //NSData *data = [pubkey_data dataUsingEncoding:NSUTF8StringEncoding];

  NSMutableData *r = BTCRIPEMD160( [self BTCSHA512:pubkey_data] );
  NSData *c = BTCRIPEMD160(r);

  [r appendBytes:c.bytes length:4];
  
  NSString * addy = [[NSString alloc] initWithFormat:@"%@%@",  (is_test?TEST_PREFIX:PROD_PREFIX), BTCBase58StringWithData(r)];
  
  return addy;
}

+(BOOL) btsIsValidAddress:(NSString*)addy with_test:(BOOL)is_test{
    
  if (![addy hasPrefix:(is_test?TEST_PREFIX:PROD_PREFIX)]) {
    return FALSE;
  }
  
  NSLog(@" #-- substring [%@] -> [%@]", addy, [addy substringFromIndex:3]);
  NSMutableData *data = BTCDataFromBase58([addy substringFromIndex:3]);
  if (data.length != 24) {
    return FALSE;
  }
  
  NSData *c1 = [data subdataWithRange:NSMakeRange(20, 4)];
  NSData *ripData = BTCRIPEMD160([data subdataWithRange:NSMakeRange(0, 20)]);
  NSData *c2 = [ripData subdataWithRange:NSMakeRange(0, 4)];
  
  NSLog(@" #-- is_valid_bts_address_impl comparing [%@] [%@]", [c1 hexadecimalString], [c2 hexadecimalString]);

  const unsigned char *p1 = [c1 bytes];
  const unsigned char *p2 = [c2 bytes];
  
  if(!(p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3]))
    return FALSE;
  
  return TRUE;
}

+(BOOL) btsIsValidPubkey:(NSString*)pubkey with_test:(BOOL)is_test{
    
  if (![pubkey hasPrefix:(is_test?TEST_PREFIX:PROD_PREFIX)]) {
      return FALSE;
  }
  
  NSMutableData *data = BTCDataFromBase58([pubkey substringFromIndex:3]);
  if (data.length != 37) {
      return FALSE;
  }
  
  NSData *c1 = [data subdataWithRange:NSMakeRange(33, 4)];
  NSData *ripData = BTCRIPEMD160([data subdataWithRange:NSMakeRange(0, 33)]);
  NSData *c2 = [ripData subdataWithRange:NSMakeRange(0, 4)];
  
  const unsigned char *p1 = [c1 bytes];
  const unsigned char *p2 = [c2 bytes];
  
  if(!((p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3])))
      return FALSE;
  
  return TRUE;
}

+(NSString*) compactSignatureForMessage:(NSString*)msg wif:(NSString*)wif{

  NSData   *msg_data = [msg dataUsingEncoding:NSUTF8StringEncoding];
  NSString *hash     = BTCHexStringFromData([self BTCSHA256:msg_data]);

  return [BitsharesPlugin_impl compactSignatureForHash:hash wif:wif];
}


+(NSString*) btsEncodePubkey:(NSData*)pubkey with_test:(BOOL)is_test{
    
  NSMutableData *tmp = [[NSMutableData alloc] initWithBytes:pubkey.bytes length:pubkey.length];
  NSMutableData *r = BTCRIPEMD160(pubkey);
  
  [tmp appendBytes:r.bytes length:4];
  NSString * epub = [[NSString alloc] initWithFormat:@"%@%@",  (is_test?TEST_PREFIX:PROD_PREFIX), BTCBase58StringWithData(tmp)];
  return epub;
}

// #define BTCPublicKeyAddressLength 20
+(BOOL) btcIsValidAddress:(NSString*)addy with_test:(BOOL)is_test{
    
  if(is_test){
    const char* cstring =[addy cStringUsingEncoding:NSASCIIStringEncoding];
    NSMutableData* composedData = BTCDataFromBase58CheckCString(cstring);
    if (!composedData) return FALSE;
    if (composedData.length < 2) return FALSE;
    
    int version = ((unsigned char*)composedData.bytes)[0];
    
    if (version != 27 || composedData.length != (1 + 20))
    {
        NSLog(@"is_valid_btc_address_impl:  %d bytes (need 20+1 bytes); version: %d", (int)composedData.length, version);
        return FALSE;
    }
    return TRUE;
  }
  
  BTCPublicKeyAddress* addr = [BTCPublicKeyAddress addressWithBase58String:addy];
  if (addr==nil || ![addr isKindOfClass:[BTCPublicKeyAddress class]])
      return FALSE;
  return TRUE;
}

+(NSString*) requestSignature:(NSString*)key withNonce:(int)nonce withUrl:(NSString*)url withBody:(NSString*)body {
    
    NSString *tmp = [[[NSString alloc] init] stringByAppendingFormat:@"%d%@%@", nonce, url, body];
    
    NSData   *tmp_req = [tmp dataUsingEncoding:NSUTF8StringEncoding];
    NSData   *tmp_key = [key dataUsingEncoding:NSUTF8StringEncoding];

    NSData   *res = BTCHMACSHA256(tmp_key, tmp_req);

    return [res hexadecimalString];
}

+(NSData*) getSharedSecret:(BTCKey *)Qp withDd:(BTCKey*)dd {
    BTCKey *dh = [Qp diffieHellmanWithPrivateKey:dd];
    return BTCSHA512([dh.compressedPublicKey subdataWithRange:NSMakeRange(1, 32)]);
}

+(NSDictionary*) createMemo:(NSString*)fromPubkey withDestPubkey:(NSString*)destPubkey withMessage:(NSString*)message           withOneTimePriv:(NSString*)oneTimePriv with_test:(BOOL)is_test {

    NSLog(@"#--createMemo");

    //dest = (dd, Qd)
    //tmp  = (dp, Qp)
    //(xk, yk) = dp * Qd
    //ss = sha512(xk)
    //ss[:32] => key
    //ss[32:48] => iv
    
    BTCKey *dp        = [[BTCKey alloc] initWithWIF:oneTimePriv];

    BTCKey *Qd = [[BTCKey alloc] initWithPublicKey:[BitsharesPlugin_impl btsDecodePubkey:destPubkey with_test:is_test]];
    
    NSData *ss = [BitsharesPlugin_impl getSharedSecret:Qd withDd:dp];
    
    //NSLog(@"SHARED => %@", [ss hexadecimalString]);
    //NSLog(@"IVO => %@",     [[ss subdataWithRange:NSMakeRange(32, 16)] hexadecimalString]);

    
    //build memo data

    NSData *fromPubkey_b = [BitsharesPlugin_impl btsDecodePubkey:fromPubkey with_test:is_test];
    NSData *message_b    = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *memo_content = [[NSMutableData alloc] initWithLength:message_b.length > 19 ? 33+8+19+1+32 : 33+8+19+1];
    
    //BTS_BLOCKCHAIN_MAX_MEMO_SIZE      = 19	
    //BTS_BLOCKCHAIN_EXTENDED_MEMO_SIZE = 32
    //total=51
    
    NSData *ocho = [[NSMutableData alloc] initWithLength:8];

    //NSLog(@"==>%lu Inicializado largo", memo_content.length);
    
    
    unsigned long i = MIN(message_b.length,19);
    
    [memo_content replaceBytesInRange:NSMakeRange(0 , 33) withBytes:fromPubkey_b.bytes length:33];
    [memo_content replaceBytesInRange:NSMakeRange(33+0,  8) withBytes:ocho.bytes length:8];
    [memo_content replaceBytesInRange:NSMakeRange(33+8,  i) withBytes:message_b.bytes length:i];

    unsigned long j = MIN(message_b.length-19,32);
    if( message_b.length > 19 )
      [memo_content replaceBytesInRange:NSMakeRange(33+8+1+i, j) withBytes:message_b.bytes+19 length:j];
    
    NSError *error;
    NSData *encrypted_memo_data = [RNEncryptor encryptData   : memo_content
                                         withSettings  : kRNCryptorAES256Settings
                                         encryptionKey : [ss subdataWithRange:NSMakeRange(0,  32)]
                                         HMACKey       : nil
                                         IV            : [ss subdataWithRange:NSMakeRange(32, 16)]
                                         error         : &error];


    //NSLog(@"==>Largo encriptado => %lu", encrypted_memo_data.length);
    
    NSData *cypher = [encrypted_memo_data subdataWithRange:NSMakeRange(18, encrypted_memo_data.length-18)];
    
    return @{
             @"one_time_key"        : [BitsharesPlugin_impl btsEncodePubkey:dp.compressedPublicKey with_test:is_test],
             @"encrypted_memo_data" : [cypher hexadecimalString],
             @"full"                : [encrypted_memo_data hexadecimalString],
    };
    
}

+(NSDictionary*) decryptMemo:(NSString*)oneTimeKey withEncryptedMemo:(NSString*)encryptedMemo withPrivkey:(NSString*)privKey           with_test:(BOOL)is_test {
    
    BTCKey *dd = [[BTCKey alloc] initWithWIF:privKey];

    BTCKey *Qp = [[BTCKey alloc] initWithPublicKey:[BitsharesPlugin_impl btsDecodePubkey:oneTimeKey with_test:is_test]];
    NSData *ss = [BitsharesPlugin_impl getSharedSecret:Qp withDd:dd];
    

    
    NSMutableData *full = [[NSMutableData alloc] init];
    [full appendData:BTCDataFromHex(@"0300")];
    [full appendData:[ss subdataWithRange:NSMakeRange(32, 16)]];
    [full appendData:BTCDataFromHex(encryptedMemo)];

    //NSLog(@"===> FULLU %@",encryptedMemo);

    NSError *error = nil;
    NSData *decrypted_data = [RNDecryptor decryptData   : full
                                          withSettings  : kRNCryptorAES256Settings
                                          encryptionKey : [ss subdataWithRange:NSMakeRange(0,  32)]
                                          HMACKey       : nil
                                          error         : &error];

    if(error != nil) {
        return  @{
          @"from"     : @"",
          @"from_sig" : @"",
          @"type"     : @"",
          @"message"  : @"",
          @"error"    : @"1"
        };
    }

    
    NSString *_from = [BitsharesPlugin_impl btsEncodePubkey:[decrypted_data subdataWithRange:NSMakeRange(0, 33)]  with_test:is_test];

    NSString *_from_sig = [[decrypted_data subdataWithRange:NSMakeRange(33,   8)] hexadecimalString];
    
    NSMutableData *msg_data = [[NSMutableData alloc] initWithData: [decrypted_data subdataWithRange:NSMakeRange(33+8, 19)]];
    
    NSString *_type     = [[decrypted_data subdataWithRange:NSMakeRange(33+8+19, 1)] hexadecimalString];

    if(decrypted_data.length > 33+8+19+1) {
        [msg_data appendData:[decrypted_data subdataWithRange:NSMakeRange(33+8+19+1, 32)]];
    }
    
    NSString *_message = [[NSString alloc] initWithBytes:msg_data.bytes length:msg_data.length encoding:NSUTF8StringEncoding];

    return @{
     @"from"     : _from,
     @"from_sig" : _from_sig,
     @"type"     : _type,
     @"message"  : _message,
     @"error"    : @"0"
    };
}

+(NSString*) createMnemonic:(int)entropy {

    
    BTCMnemonic* mnemonic = [[BTCMnemonic alloc] initWithEntropy:BTCRandomDataWithLength(entropy/8)  password:nil wordListType:BTCMnemonicWordListTypeEnglish];

    return [mnemonic.words componentsJoinedByString:@" "];
}

+(NSString*) mnemonicToMasterKey:(NSString*)words {
    
   NSArray *words_array = [words componentsSeparatedByString:@" "];
    
   BTCMnemonic* mnemonic = [[BTCMnemonic alloc] initWithWords:words_array password:nil wordListType:BTCMnemonicWordListTypeEnglish];
    
   return [mnemonic keychain].extendedPrivateKey;
}

+(NSString *) sha256:(NSString *) text{
   NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
//    return [[NSString alloc] initWithData:[self BTCSHA256:data] encoding:NSUTF8StringEncoding];
    return [[self BTCSHA256:data]hexadecimalString];
}

+(u_int32_t)randomInteger {
    NSData *random = BTCRandomDataWithLength(4);
    return *(uint32_t*)random.bytes;
}

+(NSString*)randomData:(int)length{
  return  [BTCRandomDataWithLength(length) hexadecimalString];
}


+(uint32_t)skip32:(uint32_t)value withSkip32Key:(NSString*) skip32Key withEncrypt:(BOOL)encrypt {

 uint32_t res = value;
 NSData *key = BTCDataFromHex(skip32Key);
 skip32((unsigned char*)key.bytes, (unsigned char*)&res, encrypt ? 1 : 0);
 return res;
}

+(NSString*)pbkdf2:(NSString*) password withSalt:(NSString*) salt withC:(int)c withDKeyLen:(int)dkLen{
    
    RNCryptorKeyDerivationSettings myRNCryptorKeyDerivationSettings;
    myRNCryptorKeyDerivationSettings.keySize        = dkLen;
    myRNCryptorKeyDerivationSettings.rounds         = c;
    myRNCryptorKeyDerivationSettings.saltSize       = salt.length/2;
    myRNCryptorKeyDerivationSettings.PRF            = kCCPRFHmacAlgSHA512;
    myRNCryptorKeyDerivationSettings.PBKDFAlgorithm = kCCPBKDF2;
    myRNCryptorKeyDerivationSettings.hasV2Password  = FALSE;
    
    return [[RNCryptor keyForPassword:password salt:BTCDataFromHex(salt) settings:myRNCryptorKeyDerivationSettings] hexadecimalString];
}

//private JSONObject pbkdf2(String password, String salt, int c, int dkLen)  throws JSONException, IOException, Exception {
//    JSONObject result = new JSONObject();
//    byte[] key = PBKDF2SHA512.derive(password, salt, c, dkLen);
//    result.put("key", new String(Hex.encode(key), "UTF-8"));
//    result.put("key_hash", new String(Hex.encode(sha256(key)), "UTF-8"));
//    return result;
//}



@end

