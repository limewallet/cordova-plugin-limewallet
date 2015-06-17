//
//  BitsharesPlugin.m
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

#import "BitsharesPlugin.h"

@implementation BitsharesPlugin
@synthesize callbackID;

-(BOOL) is_valid_bts_pubkey_impl:(NSString*)pubkey with_test:(BOOL)is_test{
    
    if (![pubkey hasPrefix:(is_test?TEST_PREFIX:PROD_PREFIX)]) {
        return FALSE;
    }
    
    NSMutableData *data = BTCDataFromBase58([pubkey substringFromIndex:3]);
    if (data.length != 37) {
        return FALSE;
    }
    /*
     if(pub_key.indexOf('BTSX') != 0) return false;
     var data = bs58.decode(pub_key.substr(4))
     if(data.length != 37) return false;
     var c1 = data.slice(33);
     var c2 = ripemd160(data.slice(0,33)).slice(0,4);
     return (c1[0] == c2[0] && c1[1] == c2[1] && c1[2] == c2[2] && c1[3] == c2[3]); 
     */
    
    NSData *c1 = [data subdataWithRange:NSMakeRange(33, 4)];
    NSData *ripData = BTCRIPEMD160([data subdataWithRange:NSMakeRange(0, 33)]);
    NSData *c2 = [ripData subdataWithRange:NSMakeRange(0, 4)];
    
    const unsigned char *p1 = [c1 bytes];
    const unsigned char *p2 = [c2 bytes];
    
    if(!((p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] && p1[3] == p2[3])))
        return FALSE;
    
    return TRUE;
}

-(BOOL) is_valid_bts_address_impl:(NSString*)addy with_test:(BOOL)is_test{
    
    if (![addy hasPrefix:(is_test?TEST_PREFIX:PROD_PREFIX)]) {
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

-(NSString*) bts_pub_to_address_impl:(NSData*)pubkey with_test:(BOOL)is_test{

    NSMutableData *r = BTCRIPEMD160( [self BTCSHA512:pubkey] );
    NSData *c = BTCRIPEMD160(r);

    [r appendBytes:c.bytes length:4];
    
    NSString * addy = [[NSString alloc] initWithFormat:@"%@%@",  (is_test?TEST_PREFIX:PROD_PREFIX), BTCBase58StringWithData(r)];
    
    return addy;
    
}

-(NSString*) bts_encode_pub_key:(NSData*)pubkey with_test:(BOOL)is_test{
    
    NSMutableData *tmp = [[NSMutableData alloc] initWithBytes:pubkey.bytes length:pubkey.length];
    NSMutableData *r = BTCRIPEMD160(pubkey);
    
    [tmp appendBytes:r.bytes length:4];
    NSString * epub = [[NSString alloc] initWithFormat:@"%@%@",  (is_test?TEST_PREFIX:PROD_PREFIX), BTCBase58StringWithData(tmp)];
    return epub;
    
    
}

-(NSData*) bts_decode_pub_key:(NSString*)epub with_test:(BOOL)is_test{
    
    if (![epub hasPrefix:(is_test?TEST_PREFIX:PROD_PREFIX)]) {
        return FALSE;
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

-(NSString*) bts_wif_to_address_impl:(NSString*)wif with_test:(BOOL)is_test{
    
    //[[BTCKey alloc] initWithWIF:wif].compressedPublicKey
    return [self bts_pub_to_address_impl: [[BTCKey alloc] initWithWIF:wif].compressedPublicKey with_test:is_test];
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



-(void) return_result:CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals withStatus:(CDVCommandStatus)status {

  CDVPluginResult *result = [ 
    CDVPluginResult
    resultWithStatus:status
    messageAsDictionary:errDict
  ];

  [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

-(void) return_error:CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals {
  return [self returl_result:command withVals:vals withStatus:CDVCommandStatus_ERROR];
}

-(void) return_ok:(NSDictionary *)vals  {

}

-(NSDictionary *) getParameters:(NSArray *)params withCommand:(CDVInvokedUrlCommand *)command {

  NSDictionary *args = NULL;
    
  if([command.arguments count] && [[command.arguments objectAtIndex:0] isKindOfClass:[NSDictionary class]])
    args = [command.arguments objectAtIndex:0];

  if(args) {

    NSArray *keys = [args allKeys];

    for (id object in params) {
      if( ![keys contains:object] )
        return NULL;
    }
  }

  return args;
}
/******************************************/
/* Public interface implementation ****** */
-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidPubkey");

  NSDictionary* args = [self getParameters:@[@"pubkey", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }
    
  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = (BOOL)[args valueForKey:@"test"];

  BOOL is_valid = [self is_valid_bts_pubkey_impl:pubkey with_test:is_test];

  if(!is_valid) {
    return return_error(command, @{@"Invalid pubkey", @"messageData"});
  }

  return return_ok(command, @{@"true", @"is_valid"});
}


-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidAddress");
  
  NSDictionary* args = [self getParameters:@[@"addy", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *addy = [args valueForKey:@"addy"];
  BOOL is_test   = (BOOL)[args valueForKey:@"test"];

  BOOL is_valid = [self is_valid_bts_address_impl:addy with_test:is_test];
  if(!is_valid) {
    return return_error(command, @{@"Invalid address", @"messageData"});
  }

  return return_ok(command, @{@"true", @"is_valid"});
}

-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsPubToAddress");

  NSDictionary* args = [self getParameters:@[@"pubkey", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = (BOOL)[args valueForKey:@"test"];
  
  NSData *data = [pubkey dataUsingEncoding:NSUTF8StringEncoding];
  NSString* addy = [self bts_pub_to_address_impl:data with_test:is_test];

  return return_ok(command, @{addy, @"addy"});
}
    
-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsWifToAddress");

  NSDictionary* args = [self getParameters:@[@"wif", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *wif = [args valueForKey:@"wif"];
  BOOL is_test  = (BOOL)[args valueForKey:@"test"];

  NSString* addy = [self bts_wif_to_address_impl:wif with_test:is_test];
  return return_ok(command, @{addy, @"addy"});
}

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--compactSignatureForHash");

  NSDictionary* args = [self getParameters:@[@"wif", "hash"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *wif  = [args valueForKey:@"wif"];
  NSString *hash = [args valueForKey:@"hash"];

  NSString *signature = [self compactSignatureForHash_impl:hash wif:wif ];
  return return_ok(command, @{signature, @"compactSignatureForHash"});
}

-(void) isValidKey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidKey");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *key = [args valueForKey:@"key"];
  
  BTCKey* btc_key = [[BTCKey alloc] initWithPrivateKey:[key dataUsingEncoding:NSUTF8StringEncoding]];
  if (![btc_key.privateKeyAddress isKindOfClass:[BTCPrivateKeyAddress class]]) {
    return return_error(command, @{@"Key is not valid", @"messageData"});
  }

  return return_ok(command, @{@"true", @"is_valid"});
}

-(void) isValidWif:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidWif");

  NSDictionary* args = [self getParameters:@[@"wif"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *key = [args valueForKey:@"wif"];
  
  // Es asi, ver BTCKey
  @try {
    BTCPrivateKeyAddress* addr = [BTCPrivateKeyAddress addressWithBase58String:wif];
    NSLog(@"#-- Wif IS VALID!!");
  }
  @catch (NSException *exception) {
    NSLog(@"#-- %@", exception.reason);
    return return_error(command, @{@"Wif is not valid", @"messageData"});
  }

  return return_ok(command, @{@"true", @"is_valid"});
}

-(void) encryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--encryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *textToCypher = [args valueForKey:@"data"];
  NSString *password     = [args valueForKey:@"password"];
  
  NSLog(@"#-- about to encrypt [%@] with key:[%@]", textToCypher, password);
  NSString* encryptedData = [self encryptString_impl:textToCypher withKey:password];
  NSLog(@"#-- encrypted: [%@]", encryptedData);
  
  return return_ok(command, @{encryptedData, @"encryptedData"});
}

//Params: cypher text, password
//Returns: decrypted text
-(void) decryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--decryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *cypherText = [args valueForKey:@"data"];
  NSString *password   = [args valueForKey:@"password"];
  
  NSString* decryptedData = [self decryptData_impl:cypherText withKey:password];
  
  return return_ok(command, @{decryptedData, @"decryptedData"});
}

// Params: private key
// Returns: public key
- (void) extendedPublicFromPrivate:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--extendedPublicFromPrivate");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *extendedKey = extendedKey = [args valueForKey:@"key"];
  
  NSString* strPubKey = [self extendedPublicFromPrivate_impl:extendedKey];
  
  return return_ok(command, @{strPubKey, @"extendedPublicKey"});
}


// Params: none
// Returns: random generated private key
-(void) createMasterKey:(CDVInvokedUrlCommand*)command{
    
  NSLog(@"#--createMasterKey:: about to create seed");
  NSMutableData* seed = BTCRandomDataWithLength(32);
  
  NSLog(@"createMasterKey:: about to create key");
  BTCKeychain* masterChain = [[BTCKeychain alloc] initWithSeed:seed];
  
  return return_ok(command, @{masterChain.extendedPrivateKey , @"masterPrivateKey"});
}

// Params: Private Key
// Returns: address, public key and private key.

-(NSDictionary *) extractDataFromKey_impl:(NSString*)extendedKey withTest:(BOOL)is_test {

  BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];
  NSData* pubKey    = eKey.publicKeychain.key.publicKey;

  BTCKey *theKey = [[BTCKeychain alloc] initWithExtendedKey:eKey.extendedPrivateKey].key;

  NSString *addy       = [self bts_pub_to_address_impl:pubKey with_test:is_test];
  NSString *strPubKey  = [self bts_encode_pub_key:pubKey with_test:is_test];
  NSString *strPrivKey = theKey.WIF;
  NSString *hexPrivKey = [theKey.privateKey hexadecimalString];

  return @{addy, @"addy", strPubKey, @"pubkey", strPrivKey, @"privkey", @hexPrivKey, @"privkey_hex"};
}

-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--extractDataFromKey");

  NSDictionary* args = [self getParameters:@[@"key", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = (BOOL)[args valueForKey:@"test"];

  NSDictionary *result = [self extractDataFromKey_impl:extendedKey withTest:is_test];
  return return_ok(command, result);
}

// Params: Private Key and derivation index.
// Returns: private key.
-(void) derivePrivate:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--derivePrivate");

  NSDictionary* args = [self getParameters:@[@"key", "test", "deriv"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = (BOOL)[args valueForKey:@"test"];
  uint32_t deriv        = [[args valueForKey:@"deriv"] intValue];

  BTCKeychain* eKey = [[BTCKeychain alloc] initWithExtendedKey:extendedKey];
  BTCKeychain* dKey = [eKey derivedKeychainAtIndex:deriv hardened:TRUE];

  NSDictionary *result = [self extractDataFromKey_impl:dKey.extendedPrivateKey withTest:is_test]; 

  [result setObject: dKey.extendedPrivateKey fromKey:@"extendedPrivateKey"];

  return return_ok(command, result);
}

-(void) compactSignatureForMessage:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--compactSignatureForMessage");

  NSDictionary* args = [self getParameters:@[@"wif", "msg", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *wif    = [args valueForKey:@"wif"];
  NSString *msg    = [args valueForKey:@"msg"];
  BOOL     is_test = (BOOL)[args valueForKey:@"test"];
    
  NSData   *msg_data = [msg dataUsingEncoding:NSUTF8StringEncoding];
  NSString *signature = [self compactSignatureForHash_impl:BTCHexStringFromData([self BTCSHA256:msg_data]) wif:wif];

  return return_ok(command, @{signature, @"compactSignatureForHash"});
}

-(void) recoverPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--recoverPubkey");

  NSDictionary* args = [self getParameters:@[@"signature", "msg", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *signature = [args valueForKey:@"signature"];
  NSString *msg       = [args valueForKey:@"msg"];
  BOOL     is_test    = (BOOL)[args valueForKey:@"test"];

  NSData *msg_data = [msg dataUsingEncoding:NSUTF8StringEncoding];
  NSData *signature_data = BTCDataWithHexString(signature);
    
  BTCKey* key = [BTCKey verifyCompactSignature:signature_data forHash:[self BTCSHA256:msg_data]];
  if(!key) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *pubkey = [self bts_encode_pub_key:[key compressedPublicKey] with_test:is_test];
  return return_ok(command, @{pubkey, @"pubKey"});
}

-(void) btcIsValidAddress:(CDVInvokedUrlCommand*)command{

  NSLog(@"#--btcIsValidAddress");

  NSDictionary* args = [self getParameters:@[@"addy", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *addy      = [args valueForKey:@"addy"];
  BOOL     is_test    = (BOOL)[args valueForKey:@"test"];

  BOOL is_valid = [self is_valid_btc_address_impl:addy with_test:is_test];
    
  if(!is_valid) {
    return return_error(command, @{@"Invalid address", @"messageData"});
  }

  return return_error(command, @{@"true", @"is_valid"});
}
@end


