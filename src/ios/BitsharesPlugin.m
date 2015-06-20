//
//  BitsharesPlugin.m
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

#import "BitsharesPlugin.h"
#import "BitsharesPlugin_impl.h"

@implementation BitsharesPlugin
@synthesize callbackID;

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

-(void) return_result:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals withStatus:(CDVCommandStatus)status {

  CDVPluginResult *result = [ 
    CDVPluginResult
    resultWithStatus:status
    messageAsDictionary:errDict
  ];

  [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

-(void) return_error:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals {
  return [self returl_result:command withVals:vals withStatus:CDVCommandStatus_ERROR];
}

-(void) return_ok:(CDVInvokedUrlCommand*)command withVals:(NSDictionary *)vals {
  return [self returl_result:command withVals:vals withStatus:CDVCommandStatus_OK];
}

/******************************************/
/* Public interface implementation ****** */
/******************************************/

-(void) createMasterKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--createMasterKey");
  NSString *masterPrivateKey = [BitsharesPlugin_impl createMasterKey];
  return return_ok(command, @{masterPrivateKey , @"masterPrivateKey"});
}

-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--extractDataFromKey");

  NSDictionary* args = [self getParameters:@[@"key", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = (BOOL)[args valueForKey:@"test"];

  NSDictionary *result = [BitsharesPlugin_impl extractDataFromKey:extendedKey withTest:is_test];
  return return_ok(command, result);
}

-(void) derivePrivate:(CDVInvokedUrlCommand*)command{
  NSLog(@"#--derivePrivate");

  NSDictionary* args = [self getParameters:@[@"key", "test", "deriv"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *extendedKey = [args valueForKey:@"key"];
  BOOL is_test          = (BOOL)[args valueForKey:@"test"];
  uint32_t deriv        = [[args valueForKey:@"deriv"] intValue];

  NSString *extendedPrivateKey = [BitsharesPlugin_impl derivePrivate:extendedKey withDeriv:deriv withTest:is_test];

  NSDictionary *result = [BitsharesPlugin_impl extractDataFromKey:extendedPrivateKey withTest:is_test]; 

  [result setObject: extendedPrivateKey fromKey:@"extendedPrivateKey"];

  return return_ok(command, result);
}

- (void) extendedPublicFromPrivate:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--extendedPublicFromPrivate");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *extendedKey = extendedKey = [args valueForKey:@"key"];
  
  NSString* strPubKey = [BitsharesPlugin_impl extendedPublicFromPrivate:extendedKey];
  
  return return_ok(command, @{strPubKey, @"extendedPublicKey"});
}

-(void) encryptString:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--encryptString");

  NSDictionary* args = [self getParameters:@[@"data", @"password"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *plainText = [args valueForKey:@"data"];
  NSString *password  = [args valueForKey:@"password"];
  
  NSString* encryptedData = [BitsharesPlugin_impl encryptString:plaintext withKey:password];
  
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
  
  NSString* decryptedData = [BitsharesPlugin_impl decryptString:cypherText withKey:password];
  
  return return_ok(command, @{decryptedData, @"decryptedData"});
}

-(void) isValidKey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--isValidKey");

  NSDictionary* args = [self getParameters:@[@"key"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *key = [args valueForKey:@"key"];

  BOOL is_valid = [BitsharesPlugin_impl isValidKey:key];
  if(!is_valid) {
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

  NSString *wif = [args valueForKey:@"wif"];

  BOOL is_valid = [BitsharesPlugin_impl isValidWif:wif];
  if(!is_valid) {
    return return_error(command, @{@"Wif is not valid", @"messageData"});
  } 
  
  return return_ok(command, @{@"true", @"is_valid"});
}

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--compactSignatureForHash");

  NSDictionary* args = [self getParameters:@[@"wif", "hash"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *wif  = [args valueForKey:@"wif"];
  NSString *hash = [args valueForKey:@"hash"];

  NSString *signature = [BitsharesPlugin_impl compactSignatureForHash:hash wif:wif ];
  return return_ok(command, @{signature, @"compactSignatureForHash"});
}

-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsWifToAddress");

  NSDictionary* args = [self getParameters:@[@"wif", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *wif = [args valueForKey:@"wif"];
  BOOL is_test  = (BOOL)[args valueForKey:@"test"];

  NSString* addy = [BitsharesPlugin_impl btsWifToAddress:wif with_test:is_test];
  return return_ok(command, @{addy, @"addy"});
}

-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsPubToAddress");

  NSDictionary* args = [self getParameters:@[@"pubkey", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = (BOOL)[args valueForKey:@"test"];
  
  NSString* addy = [BitsharesPlugin_impl btsPubToAddress:pubkey with_test:is_test];

  return return_ok(command, @{addy, @"addy"});
}
 
-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidAddress");
  
  NSDictionary* args = [self getParameters:@[@"addy", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }

  NSString *addy = [args valueForKey:@"addy"];
  BOOL is_test   = (BOOL)[args valueForKey:@"test"];

  BOOL is_valid = [BitsharesPlugin_impl btsIsValidAddress:addy with_test:is_test];
  if(!is_valid) {
    return return_error(command, @{@"Invalid address", @"messageData"});
  }

  return return_ok(command, @{@"true", @"is_valid"});
}

-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command {
  NSLog(@"#--btsIsValidPubkey");

  NSDictionary* args = [self getParameters:@[@"pubkey", "test"] withCommand:command];
  if(!args) {
    return return_error(command, @{@"Missing parameters", @"messageData"});
  }
    
  NSString *pubkey = [args valueForKey:@"pubkey"];
  BOOL is_test     = (BOOL)[args valueForKey:@"test"];
  BOOL is_valid    = [BitsharesPlugin_impl btsIsValidPubkey:pubkey with_test:is_test];

  if(!is_valid) {
    return return_error(command, @{@"Invalid pubkey", @"messageData"});
  }

  return return_ok(command, @{@"true", @"is_valid"});
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
    
  NSString *signature = [BitsharesPlugin_impl compactSignatureForMessage:msg wif:wif];

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


