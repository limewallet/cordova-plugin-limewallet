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
  return [self return_result:command withVals:vals withStatus:CDVCommandStatus_ERROR];
}

-(void) return_ok:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals {
  return [self return_result:command withVals:vals withStatus:CDVCommandStatus_OK];
}

/******************************************/
/* Public interface implementation ****** */
/******************************************/

-(void) createMasterKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--createMasterKey");
  NSString *masterPrivateKey = [BitsharesPlugin_impl createMasterKey];
    [self return_ok:command withVals:@{masterPrivateKey:@"masterPrivateKey"}];
}

-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--extractDataFromKey");

  NSDictionary* args = [self getParameters:@[@"key", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = (BOOL)[args valueForKey:@"test"];

  NSDictionary *result = [BitsharesPlugin_impl extractDataFromKey:extendedKey withTest:is_test];
  [self return_ok:command withVals:result];
}

-(void) derivePrivate:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--derivePrivate");

  NSDictionary* args = [self getParameters:@[@"key", @"test", @"deriv"] withCommand:command];
  if(!args) {
      [self return_error:command  withVals: @{@"Missing parameters": @"messageData"}];
    return;
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = (BOOL)[args valueForKey:@"test"];
  uint32_t deriv        = [[args valueForKey:@"deriv"] intValue];

  NSString *extendedPrivateKey = [BitsharesPlugin_impl derivePrivate:extendedKey withDeriv:deriv withTest:is_test];

  NSDictionary *result = [BitsharesPlugin_impl extractDataFromKey:extendedPrivateKey withTest:is_test]; 

  [result setValue:extendedPrivateKey forKey:@"extendedPrivateKey"];

    [self return_ok:command withVals:result];
}

- (void) extendedPublicFromPrivate:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--extendedPublicFromPrivate");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *extendedKey = extendedKey = [args valueForKey:@"key"];
  
  NSString* strPubKey = [BitsharesPlugin_impl extendedPublicFromPrivate:extendedKey];
  
    [self return_ok:command withVals:@{strPubKey: @"extendedPublicKey"}];
}

-(void) encryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--encryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *plainText = [args valueForKey:@"data"];
  NSString *password  = [args valueForKey:@"password"];
  
  NSString* encryptedData = [BitsharesPlugin_impl encryptString:plainText withKey:password];
  
    [self return_ok:command withVals:@{encryptedData: @"encryptedData"}];
}

//Params: cypher text, password
//Returns: decrypted text
-(void) decryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--decryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *cypherText = [args valueForKey:@"data"];
  NSString *password   = [args valueForKey:@"password"];
  
  NSString* decryptedData = [BitsharesPlugin_impl decryptString:cypherText withKey:password];
  
    [self return_ok:command withVals:@{decryptedData: @"decryptedData"}];
}

-(void) isValidKey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidKey");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *key = [args valueForKey:@"key"];

  BOOL is_valid = [BitsharesPlugin_impl isValidKey:key];
  if(!is_valid) {
      [self return_error:command withVals:@{@"Key is not valid": @"messageData"}];
      return;
  }

    [self return_ok:command withVals: @{@"true": @"is_valid"}];
}

-(void) isValidWif:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidWif");

  NSDictionary* args = [self getParameters:@[@"wif"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *wif = [args valueForKey:@"wif"];

  BOOL is_valid = [BitsharesPlugin_impl isValidWif:wif];
  if(!is_valid) {
      [self return_error:command withVals:@{@"Wif is not valid": @"messageData"}];
    return;
  }
  
    [self return_ok:command withVals:@{@"true": @"is_valid"}];
}

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--compactSignatureForHash");

  NSDictionary* args = [self getParameters:@[@"wif", @"hash"] withCommand:command];
  if(!args) {
      [self return_error:command withVals: @{@"Missing parameters": @"messageData"}];
     return;
  }

  NSString *wif  = [args valueForKey:@"wif"];
  NSString *hash = [args valueForKey:@"hash"];

  NSString *signature = [BitsharesPlugin_impl compactSignatureForHash:hash wif:wif ];
    [self return_ok:command  withVals:@{signature: @"compactSignatureForHash"}];
}

-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsWifToAddress");

  NSDictionary* args = [self getParameters:@[@"wif", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
    return;
  }

  NSString *wif = [args valueForKey:@"wif"];
  BOOL is_test  = (BOOL)[args valueForKey:@"test"];

  NSString* addy = [BitsharesPlugin_impl btsWifToAddress:wif with_test:is_test];
    [self return_ok:command withVals:@{addy: @"addy"}];
}

-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsPubToAddress");

  NSDictionary* args = [self getParameters:@[@"pubkey", @"test"] withCommand:command];
  if(!args) {
    [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
    return;
  }

  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = (BOOL)[args valueForKey:@"test"];
  
  NSString* addy = [BitsharesPlugin_impl btsPubToAddress:pubkey with_test:is_test];

    [self return_ok:command withVals:@{addy: @"addy"}];
}
 
-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidAddress");
  
  NSDictionary* args = [self getParameters:@[@"addy", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals: @{@"Missing parameters": @"messageData"}];
    return;
  }

  NSString *addy = [args valueForKey:@"addy"];
  BOOL is_test   = (BOOL)[args valueForKey:@"test"];

  BOOL is_valid = [BitsharesPlugin_impl btsIsValidAddress:addy with_test:is_test];
  if(!is_valid) {
      [self return_error:command withVals: @{@"Invalid address": @"messageData"}];
     return;
  }

    [self return_ok:command withVals:@{@"true": @"is_valid"}];
}

-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidPubkey");

  NSDictionary* args = [self getParameters:@[@"pubkey", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
     return;
  }
    
  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = (BOOL)[args valueForKey:@"test"];
  BOOL is_valid    = [BitsharesPlugin_impl btsIsValidPubkey:pubkey with_test:is_test];

  if(!is_valid) {
      [self return_error:command withVals:@{@"Invalid pubkey": @"messageData"}];
    return;
  }

    [self return_ok:command withVals: @{@"true": @"is_valid"}];
}
   
-(void) compactSignatureForMessage:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--compactSignatureForMessage");

  NSDictionary* args = [self getParameters:@[@"wif", @"msg", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
    return;
  }

  NSString *wif    = [args valueForKey:@"wif"];
  NSString *msg    = [args valueForKey:@"msg"];
  //BOOL     is_test = (BOOL)[args valueForKey:@"test"];
    
  NSString *signature = [BitsharesPlugin_impl compactSignatureForMessage:msg wif:wif];

    [self return_ok:command withVals:@{signature: @"compactSignatureForHash"}];
}

-(void) recoverPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--recoverPubkey");

  NSDictionary* args = [self getParameters:@[@"signature", @"msg", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
      return;
  }

  NSString *signature = [args valueForKey:@"signature"];
  NSString *msg       = [args valueForKey:@"msg"];
  BOOL     is_test    = (BOOL)[args valueForKey:@"test"];

  NSData *msg_data = [msg dataUsingEncoding:NSUTF8StringEncoding];
  NSData *signature_data = BTCDataWithHexString(signature);
    
  BTCKey* key = [BTCKey verifyCompactSignature:signature_data forHash:[BitsharesPlugin_impl BTCSHA256:msg_data]];
  if(!key) {
      [self return_error:command withVals: @{@"Missing parameters": @"messageData"}];
     return;
  }
    
  NSString *pubkey = [BitsharesPlugin_impl btsEncodePubkey:[key compressedPublicKey] with_test:is_test];
  [self return_ok:command withVals:@{pubkey:@"pubKey"}];
}

-(void) btcIsValidAddress:(CDVInvokedUrlCommand*)command{

  NSLog(@"#--btcIsValidAddress");

  NSDictionary* args = [self getParameters:@[@"addy", @"test"] withCommand:command];
  if(!args) {
      [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
  }

  NSString *addy      = [args valueForKey:@"addy"];
  BOOL     is_test    = (BOOL)[args valueForKey:@"test"];

  BOOL is_valid = [BitsharesPlugin_impl btcIsValidAddress:addy with_test:is_test];
    
  if(!is_valid) {
    [self return_error:command withVals: @{@"Invalid address": @"messageData"}];
    return;
  }

    [self return_ok:command withVals: @{@"true": @"is_valid"}];
}

-(void) requestSignature:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--requestSignature");
    
    NSDictionary* args = [self getParameters:@[@"key", @"nonce", @"url", @"body"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
    }

    NSString *key    = [args valueForKey:@"key"];
    int     nonce    = [[args valueForKey:@"nonce"] integerValue];
    NSString *url    = [args valueForKey:@"url"];
    NSString *body   = [args valueForKey:@"body"];
    
    NSString *signature = [BitsharesPlugin_impl requestSignature:key withNonce:nonce withUrl:url withBody:body];
    
    [self return_ok:command withVals: @{signature: @"signature"}];

}

-(void) createMemo:(CDVInvokedUrlCommand*)command {
    
    NSLog(@"#--createMemo");
    
    NSDictionary* args = [self getParameters:@[@"fromPubkey", @"destPubkey", @"message", @"oneTimePriv", @"test"] withCommand:command];
    if(!args) {
        [self return_error:command withVals:@{@"Missing parameters": @"messageData"}];
    }
    
    NSString *fromPubkey    = [args valueForKey:@"fromPubkey"];
    NSString *destPubkey    = [args valueForKey:@"destPubkey"];
    NSString *message       = [args valueForKey:@"message"];
    NSString *oneTimePriv   = [args valueForKey:@"oneTimePriv"];
    BOOL     is_test        = (BOOL)[args valueForKey:@"test"];
    
    NSDictionary *res = [BitsharesPlugin_impl createMemo:fromPubkey
                                            withDestPubkey:destPubkey
                                            withMessage:message
                                            withOneTimePriv:oneTimePriv
                                            with_test:is_test];
    
    [self return_ok:command withVals: res];
    
}
//createMemo = //fromPubkey, destPubkey, message, oneTimePriv) {
//= //key, nonce, url, body) {






@end


