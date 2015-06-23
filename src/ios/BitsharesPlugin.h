//
//  BitsharesPlugin.h
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

#import <Cordova/CDV.h>

@interface BitsharesPlugin : CDVPlugin{
    NSString* callbackID;
}

@property (nonatomic, copy) NSString* callbackID;

-(void) createMasterKey:(CDVInvokedUrlCommand*)command;
-(void) extractDataFromKey:(CDVInvokedUrlCommand*)command;
-(void) derivePrivate:(CDVInvokedUrlCommand*)command;
-(void) extendedPublicFromPrivate:(CDVInvokedUrlCommand*)command;

-(void) encryptString:(CDVInvokedUrlCommand*)command;
-(void) decryptString:(CDVInvokedUrlCommand*)command;

-(void) isValidKey:(CDVInvokedUrlCommand*)command;
-(void) isValidWif:(CDVInvokedUrlCommand*)command;

-(void) compactSignatureForHash:(CDVInvokedUrlCommand*)command;
-(void) btsWifToAddress:(CDVInvokedUrlCommand*)command;
-(void) btsPubToAddress:(CDVInvokedUrlCommand*)command;
-(void) btsIsValidAddress:(CDVInvokedUrlCommand*)command;
-(void) btsIsValidPubkey:(CDVInvokedUrlCommand*)command;

-(void) compactSignatureForMessage:(CDVInvokedUrlCommand*)command;
-(void) recoverPubkey:(CDVInvokedUrlCommand*)command;

-(void) btcIsValidAddress:(CDVInvokedUrlCommand*)command;

-(void) requestSignature:(CDVInvokedUrlCommand*)command;
-(void) createMemo:(CDVInvokedUrlCommand*)command;
-(void) decryptMemo:(CDVInvokedUrlCommand*)command;
-(void) createMnemonic:(CDVInvokedUrlCommand*)command;

//createMnemonic = //entropy) {
//mnemonicToMasterKey = //words) {
//sha256 = //data) {
//randomInteger =
//skip32 = //value, key, encrypt) {
//randomData = //length) {
//pbkdf2 = //password, salt, c, dkLen) {



@end
