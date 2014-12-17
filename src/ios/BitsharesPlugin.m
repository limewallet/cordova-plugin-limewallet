// Hack para AES dentro de NSData

#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (AES256)

- (NSData *)AES256EncryptWithKey:(NSString *)key {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

- (NSData *)AES256DecryptWithKey:(NSString *)key {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

@end


//
//  BitsharesPlugin.m
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

#import "BitsharesPlugin.h"

#import <CoreBitcoin/CoreBitcoin.h>

#import <CommonCrypto/CommonCrypto.h>
#if BTCDataRequiresOpenSSL
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#endif


@implementation BitsharesPlugin
@synthesize callbackID;

// Utils
-(NSMutableData*) BTCSHA512:(NSData*)data
{
    if (!data) return nil;
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512([data bytes], (CC_LONG)[data length], digest);
    
    NSMutableData* result = [NSMutableData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
    BTCSecureMemset(digest, 0, CC_SHA512_DIGEST_LENGTH);
    return result;
}

/*
 if(pub_key.indexOf('BTSX') != 0) return false;
 var data = bs58.decode(pub_key.substr(4))
 if(data.length != 37) return false;
 var c1 = data.slice(33);
 var c2 = ripemd160(data.slice(0,33)).slice(0,4);
 return (c1[0] == c2[0] && c1[1] == c2[1] && c1[2] == c2[2] && c1[3] == c2[3]); 
 */
-(BOOL) is_valid_bts_pubkey_impl:(NSString*)pubkey{
    
    if (![pubkey hasPrefix:@"BTS"]) {
        return FALSE;
    }
    
    NSMutableData *data = BTCDataFromBase58([pubkey substringFromIndex:3]);
    if (data.length != 37) {
        return FALSE;
    }
    
    NSData *c1 = [data subdataWithRange:NSMakeRange(0, 33)];
    NSData *ripData = BTCRIPEMD160(c1);
    NSData *c2 = [ripData subdataWithRange:NSMakeRange(0, 4)];
    
    const unsigned char *p1 = [c1 bytes];
    const unsigned char *p2 = [c2 bytes];
    
    if(!((p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3])))
        return FALSE;
    
    return TRUE;
}

/*
 function is_valid_address(addy) {
 try {
 if(addy.indexOf('BTSX') != 0) return false;
 var data = bs58.decode(addy.substr(4))
 if(data.length != 24) return false;
 var c1 = data.slice(20);
 var c2 = ripemd160(data.slice(0,20)).slice(0,4);
 return (c1[0] == c2[0] && c1[1] == c2[1] && c1[2] == c2[2] && c1[3] == c2[3]);
 } catch(err) {
 console.log(err);
 }
 return false;
 }
 */
-(BOOL) is_valid_bts_address_impl:(NSString*)addy{
    
    if (![addy hasPrefix:@"BTS"]) {
        return FALSE;
    }
    
    NSMutableData *data = BTCDataFromBase58([addy substringFromIndex:3]);
    if (data.length != 24) {
        return FALSE;
    }
    
    NSData *c1 = [data subdataWithRange:NSMakeRange(0, 20)];
    NSData *ripData = BTCRIPEMD160(c1);
    NSData *c2 = [ripData subdataWithRange:NSMakeRange(0, 4)];
    
    const unsigned char *p1 = [c1 bytes];
    const unsigned char *p2 = [c2 bytes];
    
    if(!((p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3])))
        return FALSE;
    
    return TRUE;
}

-(NSString*) bts_pub_to_address_impl:(NSData*)pubkey{

    NSMutableData *r = BTCRIPEMD160( [self BTCSHA512:pubkey] );
    NSData *c = BTCRIPEMD160(r);

    [r appendBytes:c.bytes length:4];
    
    NSString * addy = [[NSString alloc] initWithFormat:@"BTS%@",   BTCBase58StringWithData(r)];
    
    return addy;
    
}

-(NSString*) bts_encode_pub_key:(NSData*)pubkey{
    
    NSMutableData *tmp = [[NSMutableData alloc] initWithBytes:pubkey.bytes length:pubkey.length];
    NSMutableData *r = BTCRIPEMD160(pubkey);
    
    [tmp appendBytes:r.bytes length:4];
    NSString * epub = [[NSString alloc] initWithFormat:@"BTS%@",   BTCBase58StringWithData(tmp)];
    return epub;
}

-(NSData*) bts_decode_pub_key:(NSString*)epub{
    
    if (![epub hasPrefix:@"BTS"]) {
        return nil;
    }
    
    NSMutableData *data = BTCDataFromBase58([epub substringFromIndex:3]);
    if (data.length != 37) {
        return nil;
    }
    
    NSData *c1 = [data subdataWithRange:NSMakeRange(33, 4)];
    NSData *pubkey_data = [data subdataWithRange:NSMakeRange(0, 33)];
    
    NSData *c2 = BTCRIPEMD160(pubkey_data);

    const unsigned char *p1 = [c1 bytes];
    const unsigned char *p2 = [c2 bytes];
    
    if(!((p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3])))
        return nil;
    
    return pubkey_data;
}

-(NSString*) bts_wif_to_address_impl:(NSString*)wif{
    return [self bts_pub_to_address_impl: [[BTCKey alloc] initWithWIF:wif].publicKey];
}

-(NSString*) compactSignatureForHash_impl:(NSString*)hash wif:(NSString*)wif{

    BTCKey *key = [[BTCKey alloc] initWithWIF:wif];
    return BTCHexStringFromData( [key compactSignatureForHash:BTCDataWithHexString(hash)] );
}

-(NSData*) encryptString_impl:(NSString*)plaintext withKey:(NSString*)key {
    return [[plaintext dataUsingEncoding:NSUTF8StringEncoding] AES256EncryptWithKey:key];
}

-(NSString*) decryptData_impl:(NSData*)ciphertext withKey:(NSString*)key {
    return [[NSString alloc] initWithData:[ciphertext AES256DecryptWithKey:key]
                                  encoding:NSUTF8StringEncoding];
}

-(NSString*) extendedPublicFromPrivate_impl:(NSString*)key {
    BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:key];
    return eKey.extendedPublicKey;
}

/******************************************/
/* Public interface implementation ****** */

-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *pubkey = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        pubkey = [args valueForKey:@"addy"];
    }
    
    if (pubkey.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read pubkey" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BOOL is_valid = [self is_valid_bts_pubkey_impl:pubkey];
    
    if(!is_valid)
    {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Invalid pubkey" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"is_valid", @"true",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *addy = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        addy = [args valueForKey:@"addy"];
    }
    
    if (addy.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read address" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BOOL is_valid = [self is_valid_bts_address_impl:addy];
    
    if(!is_valid)
    {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Invalid address" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"is_valid", @"true",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *pubkey = @"";
        
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
        
    if (args) {
        pubkey = [args valueForKey:@"pubkey"];
    }
        
    if (pubkey.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read pubkey" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                    resultWithStatus:CDVCommandStatus_ERROR
                                    messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSData *data = [pubkey dataUsingEncoding:NSUTF8StringEncoding];
    NSString* addy = [self bts_pub_to_address_impl:data];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                                initWithObjectsAndKeys :
                                @"addy", addy,
                                nil
                                ];
        
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                        resultWithStatus    : CDVCommandStatus_OK
                                        messageAsDictionary : jsonObj
                                        ];
        
        
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}
    
-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *wif = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        wif = [args valueForKey:@"wif"];
    }
    
    if (wif.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    NSString* addy = [self bts_wif_to_address_impl:wif];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"addy", addy,
                             nil
                             ];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *wif = @"";
    NSString *hash = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        wif = [args valueForKey:@"wif"];
        hash = [args valueForKey:@"hash"];
    }
    
    if (wif.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    if (hash.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read hash to sign" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSString *res = [self compactSignatureForHash_impl:hash wif:wif ];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"compactSignatureForHash", res,
                             nil
                             ];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    
}

-(void) isValidKey:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *key = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        key = [args valueForKey:@"key"];
    }
    
    if (key.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BTCKey* btc_key = [[BTCKey alloc] initWithPrivateKey:[key dataUsingEncoding:NSUTF8StringEncoding]];
    if (![btc_key.privateKeyAddress isKindOfClass:[BTCPrivateKeyAddress class]])
    {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Key is not valid" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"is_valid", @"true",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) isValidWif:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *wif = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        wif = [args valueForKey:@"wif"];
    }
    
    if (wif.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    // Es asi, ver BTCKey
    BTCPrivateKeyAddress* addr = [BTCPrivateKeyAddress addressWithBase58String:wif];
    if (![addr isKindOfClass:[BTCPrivateKeyAddress class]])
    {
       NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Key is not valid" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"is_valid", @"true",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) encryptString:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *textToCypher = @"";
    NSString *password = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        textToCypher = [args valueForKey:@"data"];
        password = [args valueForKey:@"password"];
    }
    
    if (textToCypher.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read cypher text" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    //NSData *data = [textToCypher dataUsingEncoding:NSUTF8StringEncoding];
    NSData* encryptedData = [self encryptString_impl:textToCypher withKey:password];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"encryptedData", [[NSString alloc] initWithData:encryptedData encoding:NSUTF8StringEncoding],
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


//Params: cypher text, password
//Returns: decrypted text
-(void) decryptString:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *cypherText = @"";
    NSString *password = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        cypherText = [args valueForKey:@"data"];
        password = [args valueForKey:@"password"];
    }
    
    if (cypherText.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to read cypher text" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSData *data = [cypherText dataUsingEncoding:NSUTF8StringEncoding];
    NSString* decryptedData = [self decryptData_impl:data withKey:password];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"decryptedData", decryptedData,
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// Params: private key
// Returns: public key
- (void) extendedPublicFromPrivate:(CDVInvokedUrlCommand*)command {
    NSDictionary* args;
    NSString *extendedKey = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        extendedKey = [args valueForKey:@"key"];
    }
    
    if (extendedKey.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to parse key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSString* strPubKey = [self extendedPublicFromPrivate_impl:extendedKey];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"extendedPublicKey", strPubKey,
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


// Params: none
// Returns: random generated private key
-(void) createMasterKey:(CDVInvokedUrlCommand*)command{
    NSMutableData* seed = BTCRandomDataWithLength(32);
    BTCKeychain* masterChain = [[BTCKeychain alloc] initWithSeed:seed];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"masterPrivateKey", masterChain.extendedPrivateKey ,
                             nil
                             ];

    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// Params: Private Key
// Returns: address, public key and private key.
-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command{
    
    NSDictionary* args;
    NSString *extendedKey = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }

    if (args) {
        extendedKey = [args valueForKey:@"key"];
    }

    if (extendedKey.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to parse key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];
    
    
    NSData* pubKey  = eKey.publicKeychain.key.publicKey;

    NSString *addy       = [self bts_pub_to_address_impl:pubKey];
    NSString *strPubKey  = [self bts_encode_pub_key:pubKey];
    NSString *strPrivKey = [[BTCKeychain alloc] initWithExtendedKey:eKey.extendedPrivateKey].key.WIF;
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"address", addy,
                             @"pubkey", strPubKey,
                             @"privkey", strPrivKey ,
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    
}

// Params: Private Key and derivation index.
// Returns: private key.
-(void) derivePrivate:(CDVInvokedUrlCommand*)command{
    
    NSDictionary* args;
    NSString *extendedKey = @"";
    uint32_t deriv = 0;
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        extendedKey = [args valueForKey:@"key"];
        deriv       = [[args valueForKey:@"deriv"] uint32value];
    }
    
    if (extendedKey.length == 0) {
        NSMutableDictionary* dictionary = [NSMutableDictionary dictionaryWithCapacity:2];
        [dictionary setValue:@"Unable to parse key" forKey:@"message"];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:dictionary];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
        
    }
    
    BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];

    BTCKeychain* dKey = [eKey derivedKeychainAtIndex:deriv hardened:TRUE];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"extendedPrivateKey", dKey.extendedPrivateKey ,
                             nil
                             ];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end


