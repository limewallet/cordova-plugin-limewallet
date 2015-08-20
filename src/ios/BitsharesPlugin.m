//
//  BitsharesPlugin.m
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

#import "BitsharesPlugin.h"
#import "BitsharesPlugin_impl.h"
#import <CoreBitcoin/CoreBitcoin.h>

@implementation BitsharesPlugin
@synthesize callbackID;

-(NSDictionary *) getParameters:(NSArray *)params withCommand:(CDVInvokedUrlCommand *)command {

  NSDictionary *args = NULL;
    
  if([command.arguments count] && [[command.arguments objectAtIndex:0] isKindOfClass:[NSDictionary class]])
    args = [command.arguments objectAtIndex:0];

  if(args) {
    NSArray *keys = (NSArray *)[args allKeys];
    for (id object in params) {
      if( ![keys containsObject:object] )
        return NULL;
    }
  }

  return args;
}

-(void) return_result:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals withStatus:(CDVCommandStatus)status {

  CDVPluginResult *result = [ 
    CDVPluginResult
    resultWithStatus:status
    messageAsDictionary:vals
  ];

  [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

-(void) return_error:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals {
  [self return_result:command withVals:vals withStatus:CDVCommandStatus_ERROR];
}

-(void) return_ok:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals {
  [self return_result:command withVals:vals withStatus:CDVCommandStatus_OK];
}

/******************************************/
/* Public interface implementation ****** */
/******************************************/

-(void) createMasterKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--createMasterKey");
  NSString *masterPrivateKey = [BitsharesPlugin_impl createMasterKey];
  [self return_ok:command withVals:@{@"masterPrivateKey":masterPrivateKey}];
}

-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--extractDataFromKey");

  NSDictionary* args = [self getParameters:@[@"key", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = [[args valueForKey:@"test"] boolValue];

  NSDictionary *result = [BitsharesPlugin_impl extractDataFromKey:extendedKey withTest:is_test];
  [self return_ok:command withVals:result];
}

-(void) derivePrivate:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--derivePrivate");

  NSDictionary* args = [self getParameters:@[@"key", @"test", @"deriv"] withCommand:command];
  if(!args) {
      [self return_error:command  withVals: @{@"messageData": @"Missing parameters"}];
    return;
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = [[args valueForKey:@"test"] boolValue];
  uint32_t deriv        = [[args valueForKey:@"deriv"] intValue];

  NSString *extendedPrivateKey = [BitsharesPlugin_impl derivePrivate:extendedKey withDeriv:deriv withTest:is_test];

  NSDictionary *result = [BitsharesPlugin_impl extractDataFromKey:extendedPrivateKey withTest:is_test]; 
  NSMutableDictionary *md = [result mutableCopy];
  [md setValue:extendedPrivateKey forKey:@"extendedPrivateKey"];

  [self return_ok:command withVals:md];
}

- (void) extendedPublicFromPrivate:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--extendedPublicFromPrivate");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *extendedKey = extendedKey = [args valueForKey:@"key"];
  
  NSString* strPubKey = [BitsharesPlugin_impl extendedPublicFromPrivate:extendedKey];
  
    [self return_ok:command withVals:@{@"extendedPublicKey":strPubKey}];
}

-(void) encryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--encryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *plainText = [args valueForKey:@"data"];
  NSString *password  = [args valueForKey:@"password"];
  
  NSString* encryptedData = [BitsharesPlugin_impl encryptString:plainText withKey:password];
  
    [self return_ok:command withVals:@{@"encryptedData":encryptedData}];
}

//Params: cypher text, password
//Returns: decrypted text
-(void) decryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--decryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *cypherText = [args valueForKey:@"data"];
  NSString *password   = [args valueForKey:@"password"];
  
  NSString* decryptedData = [BitsharesPlugin_impl decryptString:cypherText withKey:password];
  
    [self return_ok:command withVals:@{@"decryptedData":decryptedData}];
}

-(void) isValidKey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidKey");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *key = [args valueForKey:@"key"];

  BOOL is_valid = [BitsharesPlugin_impl isValidKey:key];
  if(!is_valid) {
      [self return_error:command withVals:@{@"messageData":@"Key is not valid"}];
      return;
  }

    [self return_ok:command withVals: @{@"is_valid":@"true"}];
}

-(void) isValidWif:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidWif");

  NSDictionary* args = [self getParameters:@[@"wif"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *wif = [args valueForKey:@"wif"];

  BOOL is_valid = [BitsharesPlugin_impl isValidWif:wif];
  if(!is_valid) {
      [self return_error:command withVals:@{@"messageData":@"Wif is not valid"}];
    return;
  }
  
    [self return_ok:command withVals:@{@"is_valid":@"true"}];
}

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--compactSignatureForHash");

  NSDictionary* args = [self getParameters:@[@"wif", @"hash"] withCommand:command];
  if(!args) {
      [self return_error:command withVals: @{@"messageData": @"Missing parameters"}];
     return;
  }

  NSString *wif  = [args valueForKey:@"wif"];
  NSString *hash = [args valueForKey:@"hash"];

  NSString *signature = [BitsharesPlugin_impl compactSignatureForHash:hash wif:wif ];
    [self return_ok:command  withVals:@{@"compactSignatureForHash":signature}];
}

-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsWifToAddress");

  NSDictionary* args = [self getParameters:@[@"wif", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    return;
  }

  NSString *wif = [args valueForKey:@"wif"];
  BOOL is_test  = [[args valueForKey:@"test"] boolValue];

  NSString* addy = [BitsharesPlugin_impl btsWifToAddress:wif with_test:is_test];
  [self return_ok:command withVals:@{@"addy":addy}];
}

-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsPubToAddress");

  NSDictionary* args = [self getParameters:@[@"pubkey", @"test"] withCommand:command];
  if(!args) {
    [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    return;
  }

  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = [[args valueForKey:@"test"] boolValue];
  
  NSString* addy = [BitsharesPlugin_impl btsPubToAddress:pubkey with_test:is_test];

    [self return_ok:command withVals:@{@"addy":addy}];
}
 
-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidAddress");
  
  NSDictionary* args = [self getParameters:@[@"addy", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals: @{@"messageData": @"Missing parameters"}];
    return;
  }

  NSString *addy = [args valueForKey:@"addy"];
  BOOL is_test   = [[args valueForKey:@"test"] boolValue];

  BOOL is_valid = [BitsharesPlugin_impl btsIsValidAddress:addy with_test:is_test];
  if(!is_valid) {
      [self return_error:command withVals: @{@"messageData":@"Invalid address"}];
     return;
  }

    [self return_ok:command withVals:@{@"is_valid":@"true"}];
}

-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidPubkey");

  NSDictionary* args = [self getParameters:@[@"pubkey", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
     return;
  }
    
  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = [[args valueForKey:@"test"] boolValue];
  BOOL is_valid    = [BitsharesPlugin_impl btsIsValidPubkey:pubkey with_test:is_test];

  if(!is_valid) {
      [self return_error:command withVals:@{@"messageData":@"Invalid pubkey"}];
    return;
  }

    [self return_ok:command withVals: @{@"is_valid":@"true"}];
}
   
-(void) compactSignatureForMessage:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--compactSignatureForMessage");

  NSDictionary* args = [self getParameters:@[@"wif", @"msg"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    return;
  }

  NSString *wif    = [args valueForKey:@"wif"];
  NSString *msg    = [args valueForKey:@"msg"];
 
  NSString *signature = [BitsharesPlugin_impl compactSignatureForMessage:msg wif:wif];

  [self return_ok:command withVals:@{@"compactSignatureForHash":signature}];
}

-(void) recoverPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--recoverPubkey");

  NSDictionary* args = [self getParameters:@[@"signature", @"msg", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
      return;
  }

  NSString *signature = [args valueForKey:@"signature"];
  NSString *msg       = [args valueForKey:@"msg"];
  BOOL     is_test    = [[args valueForKey:@"test"] boolValue];

  NSData *msg_data = [msg dataUsingEncoding:NSUTF8StringEncoding];
  NSData *signature_data = BTCDataWithHexString(signature);
    
  BTCKey* key = [BTCKey verifyCompactSignature:signature_data forHash:[BitsharesPlugin_impl BTCSHA256:msg_data]];
  if(!key) {
      [self return_error:command withVals: @{@"messageData": @"Missing parameters"}];
     return;
  }
    
  NSString *pubkey = [BitsharesPlugin_impl btsEncodePubkey:[key compressedPublicKey] with_test:is_test];
  [self return_ok:command withVals:@{@"pubKey":pubkey}];
}

-(void) btcIsValidAddress:(CDVInvokedUrlCommand*)command{

  NSLog(@"#--btcIsValidAddress");

  NSDictionary* args = [self getParameters:@[@"addy", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
  }

  NSString *addy      = [args valueForKey:@"addy"];
  BOOL     is_test    = [[args valueForKey:@"test"] boolValue];

  BOOL is_valid = [BitsharesPlugin_impl btcIsValidAddress:addy with_test:is_test];
    
  if(!is_valid) {
    [self return_error:command withVals: @{@"messageData":@"Invalid address"}];
    return;
  }

    [self return_ok:command withVals: @{@"is_valid":@"true"}];
}

-(void) requestSignature:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--requestSignature");
    
    NSDictionary* args = [self getParameters:@[@"key", @"nonce", @"url", @"body"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    }

    NSString *key    = [args valueForKey:@"key"];
    int     nonce    = [[args valueForKey:@"nonce"] integerValue];
    NSString *url    = [args valueForKey:@"url"];
    NSString *body   = [args valueForKey:@"body"];
    
    NSString *signature = [BitsharesPlugin_impl requestSignature:key withNonce:nonce withUrl:url withBody:body];
    
    [self return_ok:command withVals: @{@"signature":signature}];

}

-(void) createMemo:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--createMemo");
    
    NSDictionary* args = [self getParameters:@[@"fromPubkey", @"destPubkey", @"message", @"oneTimePriv", @"test"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    }
    
    NSString *fromPubkey    = [args valueForKey:@"fromPubkey"];
    NSString *destPubkey    = [args valueForKey:@"destPubkey"];
    NSString *message       = [args valueForKey:@"message"];
    NSString *oneTimePriv   = [args valueForKey:@"oneTimePriv"];
    BOOL     is_test        = [[args valueForKey:@"test"] boolValue];
    
    NSDictionary *res = [BitsharesPlugin_impl createMemo:fromPubkey
                                            withDestPubkey:destPubkey
                                            withMessage:message
                                            withOneTimePriv:oneTimePriv
                                            with_test:is_test];
    
    [self return_ok:command withVals: res];
    
}


-(void) decryptMemo:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--decryptMemo");
    
    NSDictionary* args = [self getParameters:@[@"encryptedMemo", @"privKey", @"test", @"oneTimeKey"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    }
    
    NSString *oneTimeKey       = [args valueForKey:@"oneTimeKey"];
    NSString *encryptedMemo    = [args valueForKey:@"encryptedMemo"];
    NSString *privKey          = [args valueForKey:@"privKey"];
    BOOL     is_test           = [[args valueForKey:@"test"] boolValue];
    
    NSDictionary *res = [BitsharesPlugin_impl decryptMemo:oneTimeKey withEncryptedMemo:encryptedMemo withPrivkey:privKey with_test:is_test];
    
    [self return_ok:command withVals: res];
    
}

-(void)createMnemonic:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--createMnemonic");
    
    NSDictionary* args = [self getParameters:@[@"entropy"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
    }
    
    int     entropy    = [[args valueForKey:@"entropy"] integerValue];
    
    NSString *res = [BitsharesPlugin_impl createMnemonic:entropy];
    
    [self return_ok:command withVals:@{@"words":res}];
    
}

-(void)mnemonicToMasterKey:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--mnemonicToMasterKey");
    
    NSDictionary* args = [self getParameters:@[@"words"] withCommand:command];
    if(!args) {
        NSLog(@"#--mnemonicToMasterKey ERROR");
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
        return;
    }
    
    NSString *words = [args valueForKey:@"words"];
    
    NSString *res   = [BitsharesPlugin_impl mnemonicToMasterKey:words];
    //NSLog(@"#--mnemonicToMasterKey: %@ %@", words, res);
    
    if(res==nil) {
        NSLog(@"#--mnemonicToMasterKey ERROR");
        [self return_error:command withVals:@{@"messageData": @"Invalid Words"}];
        return;
    }

    [self return_ok:command withVals:@{@"masterPrivateKey":res}];
    NSLog(@"#--mnemonicToMasterKey retorno!");
}

-(void)sha256:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--sha256");
    
    NSDictionary* args = [self getParameters:@[@"data"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
        return;
    }
    
    NSString *data = [args valueForKey:@"data"];
    
    NSString *res   = [BitsharesPlugin_impl sha256:data];
    
    [self return_ok:command withVals:@{@"sha256":res}];
    
}

-(void)randomInteger:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--randomInteger");
    
    u_int32_t res   = [BitsharesPlugin_impl randomInteger];
    
    //[self return_ok:command withVals:@{@"int":res}];
    [self return_ok:command withVals:@{@"int":[NSString stringWithFormat:@"%lu", (unsigned long)res]}];
}

-(void)randomData:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--randomData");
    
    NSDictionary* args = [self getParameters:@[@"length"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
        return;
    }
    
    int length = [[args valueForKey:@"length"] integerValue];
    
    NSString *res   = [BitsharesPlugin_impl randomData:length];
    
    [self return_ok:command withVals:@{@"random":res}];
    
}

-(void)skip32:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--skip32");
    
    NSDictionary* args = [self getParameters:@[@"value", @"key", @"encrypt"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
        return;
    }
    
    uint32_t value = [[args valueForKey:@"value"] unsignedIntegerValue];
    NSString *key  = [args valueForKey:@"key"];
    BOOL  encrypt  = (BOOL)[args valueForKey:@"encrypt"];
    
    uint32_t res   = [BitsharesPlugin_impl skip32:value withSkip32Key:key withEncrypt:encrypt];
    
    //[self return_ok:command withVals:@{@"skip32":res}];
    [self return_ok:command withVals:@{@"skip32":[NSString stringWithFormat:@"%lu", (unsigned long)res]}];
    
}

-(void)pbkdf2:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--pbkdf2");
    
    NSDictionary* args = [self getParameters:@[@"password", @"salt", @"c", @"dkLen"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"messageData": @"Missing parameters"}];
        return;
    }
    
    NSString *password  = [args valueForKey:@"password"];
    NSString *salt      = [args valueForKey:@"salt"];
    int c               = [[args valueForKey:@"c"] integerValue];
    int dklen           = [[args valueForKey:@"dkLen"] integerValue];
    
    NSString *res       = [BitsharesPlugin_impl pbkdf2:password withSalt:salt withC:c withDKeyLen:dklen];
    
    [self return_ok:command withVals:@{@"key":res}];
    
}

@end


