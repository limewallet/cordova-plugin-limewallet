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

+(NSString *) createMasterKey
{
  NSLog(@"#--createMasterKey:: about to create seed");
  NSMutableData* seed = BTCRandomDataWithLength(32);
  
  NSLog(@"createMasterKey:: about to create key");
  BTCKeychain* mk = [[BTCKeychain alloc] initWithSeed:seed];
  return mk.extendedPrivateKey;
}
