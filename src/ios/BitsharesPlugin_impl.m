#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <CoreBitcoin/CoreBitcoin.h>
#import "RNOpenSSLEncryptor.h"
#import "RNOpenSSLDecryptor.h"
#import <CommonCrypto/CommonCrypto.h>

#if BTCDataRequiresOpenSSL
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#endif

#import "BitsharesPlugin_impl.h"
@implementation BitsharesPlugin_impl

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
    return nill;
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

  return @{addy, @"addy", strPubKey, @"pubkey", strPrivKey, @"privkey", @hexPrivKey, @"privkey_hex"};
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

  NSString* pubkey_data = [BitsharesPlugin_impl btsDecodePubkey:pubkey with_test:is_test];

  NSData *data = [pubkey_data dataUsingEncoding:NSUTF8StringEncoding];

  NSMutableData *r = BTCRIPEMD160( [self BTCSHA512:pubkey] );
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
-(BOOL) is_valid_btc_address_impl:(NSString*)addy with_test:(BOOL)is_test{
    
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


