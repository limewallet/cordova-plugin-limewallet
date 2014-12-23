
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
@implementation NSString (CCCryptUtil)
-(NSString*) md5 {
    const char * cStrValue = [self UTF8String];
    unsigned char theResult[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStrValue, strlen(cStrValue), theResult);
    return [NSString stringWithFormat:@"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            theResult[0], theResult[1], theResult[2], theResult[3],
            theResult[4], theResult[5], theResult[6], theResult[7],
            theResult[8], theResult[9], theResult[10], theResult[11],
            theResult[12], theResult[13], theResult[14], theResult[15]];
}
@end

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
//
//  BitsharesPlugin.m
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

#import "BitsharesPlugin.h"

#import <CoreBitcoin/CoreBitcoin.h>
#import "RNOpenSSLEncryptor.h"
#import "RNOpenSSLDecryptor.h"
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

-(BOOL) is_valid_bts_address_impl:(NSString*)addy{
    
    if (![addy hasPrefix:@"BTS"]) {
        return FALSE;
    }
    
//    var data = bs58.decode(addy.substr(3))
//    if(data.length != 24) return false;
//    var c1 = data.slice(20);
//    var c2 = ripemd160(data.slice(0,20)).slice(0,4);
//    return (c1[0] == c2[0] && c1[1] == c2[1] && c1[	2] == c2[2] && c1[3] == c2[3]);
    
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

-(NSString*) encryptString_impl:(NSString*)plaintext withKey:(NSString*)key {
    NSData *data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *encryptedData = [RNOpenSSLEncryptor encryptData:data
                                                withSettings:kRNCryptorAES256Settings
                                                password:key
                                                error:&error];
    
    if ([encryptedData respondsToSelector:@selector(base64EncodedStringWithOptions:)]) {
        return [encryptedData base64EncodedStringWithOptions:kNilOptions];  // iOS 7+
    } else {
        return [encryptedData base64Encoding];                              // pre iOS7
    }
    //return [encryptedData base64EncodedStringWithOptions:0];
}

-(NSString*) decryptData_impl:(NSString*)ciphertext withKey:(NSString*)key {
    
    NSData *data;
    if ([NSData instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)]) {
        data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:0]; // iOS 7+
    } else {
        data = [[NSData alloc] initWithBase64Encoding:ciphertext];                // pre iOS7
    }
    
    
    NSError *error;
    NSData *decryptedData = [RNOpenSSLDecryptor decryptData:data
                                                withSettings:kRNCryptorAES256Settings
                                                password:key
                                                error:&error];
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

-(NSString*) extendedPublicFromPrivate_impl:(NSString*)key {
    BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:key];
    return eKey.extendedPublicKey;
}

/******************************************/
/* Public interface implementation ****** */

-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--btsIsValidPubkey");
    NSDictionary* args;
    NSString *pubkey = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        pubkey = [args valueForKey:@"addy"];
    }
    
    if (pubkey.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read pubkey", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BOOL is_valid = [self is_valid_bts_pubkey_impl:pubkey];
    
    if(!is_valid)
    {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Invalid pubkey", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"true", @"is_valid",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--btsIsValidAddress");
    NSDictionary* args;
    NSString *addy = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        addy = [args valueForKey:@"addy"];
    }
    
    if (addy.length == 0) {
        NSLog(@"#--btsIsValidAddress addy es una baba papa!!!!");
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read address", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;    }
    
    BOOL is_valid = [self is_valid_bts_address_impl:addy];
    
    NSLog(@"#--btsIsValidAddress is_valid?: [%hhd]",is_valid);
    
    if(!is_valid)
    {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Invalid address", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"true", @"is_valid",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--btsPubToAddress");
    NSDictionary* args;
    NSString *pubkey = @"";
        
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
        
    if (args) {
        pubkey = [args valueForKey:@"pubkey"];
    }
        
    if (pubkey.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read pubkey", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSData *data = [pubkey dataUsingEncoding:NSUTF8StringEncoding];
    NSString* addy = [self bts_pub_to_address_impl:data];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                                initWithObjectsAndKeys :
                                addy, @"addy",
                                nil
                                ];
        
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                        resultWithStatus    : CDVCommandStatus_OK
                                        messageAsDictionary : jsonObj
                                        ];
        
        
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}
    
-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--btsWifToAddress");
    NSDictionary* args;
    NSString *wif = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        wif = [args valueForKey:@"wif"];
    }
    
    if (wif.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    NSString* addy = [self bts_wif_to_address_impl:wif];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             addy, @"addy",
                             nil
                             ];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--compactSignatureForHash");
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
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
        return;
    }
    if (hash.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read ahsh to sign", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;    }
    
    NSString *res = [self compactSignatureForHash_impl:hash wif:wif ];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             res, @"compactSignatureForHash",
                             nil
                             ];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    
}

-(void) isValidKey:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--isValidKey");
    NSDictionary* args;
    NSString *key = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        key = [args valueForKey:@"key"];
    }
    
    if (key.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to red key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BTCKey* btc_key = [[BTCKey alloc] initWithPrivateKey:[key dataUsingEncoding:NSUTF8StringEncoding]];
    if (![btc_key.privateKeyAddress isKindOfClass:[BTCPrivateKeyAddress class]])
    {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Key is not valid", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"true", @"is_valid",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) isValidWif:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--isValidWif");
    NSDictionary* args;
    NSString *wif = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        wif = [args valueForKey:@"wif"];
    }
    
    if (wif.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;    }
    
    // Es asi, ver BTCKey
    BTCPrivateKeyAddress* addr = [BTCPrivateKeyAddress addressWithBase58String:wif];
    if (![addr isKindOfClass:[BTCPrivateKeyAddress class]])
    {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Key is not valid", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"true", @"is_valid",
                             nil
                             ];
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

-(void) encryptString:(CDVInvokedUrlCommand*)command {
    NSLog(@"#--encryptString");
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
    
    if (textToCypher.length == 0 || password.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read cypher text and/or password", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
        
    }
    NSLog(@"#-- about to encrypt [%@] with key:[%@]", textToCypher, password);
    NSString* encryptedData = [self encryptString_impl:textToCypher withKey:password];
    NSLog(@"#-- encrypted: [%@]", encryptedData);
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             encryptedData, @"encryptedData",
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
    NSLog(@"#--decryptString");
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
        
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to read cypher text", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
//    NSData *data = [cypherText dataUsingEncoding:NSUTF8StringEncoding];
    NSString* decryptedData = [self decryptData_impl:cypherText withKey:password];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             decryptedData, @"decryptedData",
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
    NSLog(@"#--extendedPublicFromPrivate");
    NSDictionary* args;
    NSString *extendedKey = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        extendedKey = [args valueForKey:@"key"];
    }
    
    if (extendedKey.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to parse key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    NSString* strPubKey = [self extendedPublicFromPrivate_impl:extendedKey];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             strPubKey, @"extendedPublicKey",
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
    
    NSLog(@"#--createMasterKey:: about to create seed");
    NSMutableData* seed = BTCRandomDataWithLength(32);
    
    NSLog(@"createMasterKey:: about to create key");
    BTCKeychain* masterChain = [[BTCKeychain alloc] initWithSeed:seed];
    
    NSLog(@"createMasterKey:: key created!!");
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             masterChain.extendedPrivateKey , @"masterPrivateKey",
                             nil
                             ];

    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    NSLog(@"createMasterKey:: about to send command result");
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    NSLog(@"createMasterKey:: command result sent!!");
}

// Params: Private Key
// Returns: address, public key and private key.
-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command{
    NSLog(@"#--extractDataFromKey");
    NSDictionary* args;
    NSString *extendedKey = @"";
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }

    if (args) {
        extendedKey = [args valueForKey:@"key"];
    }

    if (extendedKey.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to parse key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
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
                             addy, @"address",
                             strPubKey, @"pubkey",
                             strPrivKey, @"privkey",
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
    NSLog(@"#--derivePrivate");
    NSDictionary* args;
    NSString *extendedKey = @"";
    uint32_t deriv = 0;
    
    if ([command.arguments count] > 0) {
        args = [command.arguments objectAtIndex:0];
    }
    
    if (args) {
        extendedKey            = [args valueForKey:@"key"];
        NSString *_deriv       = [args valueForKey:@"deriv"];
        deriv = (unsigned int)[_deriv intValue];
    }
    
    if (extendedKey.length == 0) {
        NSDictionary *errDict = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"Unable to parse key", @"messageData",
                                 nil
                                 ];
        CDVPluginResult *result = [ CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_ERROR
                                   messageAsDictionary:errDict];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }
    
    BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];

    BTCKeychain* dKey = [eKey derivedKeychainAtIndex:deriv hardened:TRUE];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             dKey.extendedPrivateKey, @"extendedPrivateKey",
                             nil
                             ];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end


