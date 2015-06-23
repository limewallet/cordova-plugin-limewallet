#import <Foundation/Foundation.h>

#include "BitsharesPlugin_impl.h"  

int main (int argc, const char * argv[])
{

//	NSString *key = @"peperulo";
//  int nonce = 155555;
//	NSString *url = @"http://pepe.com";
//	NSString *body = @"elbody";
//
//  NSString *signature = [BitsharesPlugin_impl requestSignature:key withNonce:nonce withUrl:url withBody:body];
//
//  NSLog (@"==> %@",signature);

    
    
    /*
Key1:
    5K5vZac5P3Z4AEo87z8BgSznV1tf2rTQeFgh5FEqzp3jMvFq7ML
    DVS7zLoRqPA4gQYCwnsTK7fDtuac21f9wEGUHkvnXnr8P9bHhNmFC
Key2:
    5Jho5vraaSJmBKTKwifRhK2oVaX61AqcYiT4Qpm4Qc6jVpXLr2F
    DVS8BGvgRb7v7J4VxNMyTyaoRbWGjDKj91mWL6EPH5XkxUL2PVnBK
    */

//    NSString *fromPub = @"DVS7zLoRqPA4gQYCwnsTK7fDtuac21f9wEGUHkvnXnr8P9bHhNmFC";
//  NSString *destpub = @"DVS8BGvgRb7v7J4VxNMyTyaoRbWGjDKj91mWL6EPH5XkxUL2PVnBK";
//  NSString *message = @"chupito";
//  NSString *wif     = @"5K5vZac5P3Z4AEo87z8BgSznV1tf2rTQeFgh5FEqzp3jMvFq7ML";
//    
//
//  NSDictionary *mermo =  [BitsharesPlugin_impl createMemo:fromPub withDestPubkey:destpub withMessage:message withOneTimePriv:wif with_test:TRUE];
//    
//
//    NSLog(@"%@",mermo);
//    
//    NSString *em = [mermo objectForKey:@"encrypted_memo_data"];
//    NSString *otk = [mermo objectForKey:@"one_time_key"];
//    
//    NSLog(@"EM => %@",em);
//    NSLog(@"TK => %@",otk);
//    
//    NSDictionary *res = [BitsharesPlugin_impl decryptMemo:otk withEncryptedMemo:em withPrivkey:@"5Jho5vraaSJmBKTKwifRhK2oVaX61AqcYiT4Qpm4Qc6jVpXLr2F"
//                             with_test:TRUE];
//    
//    NSLog(@"%@",res);
    
    

//  NSString *www = [BitsharesPlugin_impl createMnemonic:128];
//  NSLog(@"WORDs => %@s", www);
//    
//  NSString *mpk =   [BitsharesPlugin_impl mnemonicToMasterKey:www];
//  NSLog(@"mpk => %@s", mpk);
  
//  NSString* data = @"a sha256rear";
//  NSString *sha256 =   [BitsharesPlugin_impl sha256:data];
//  NSLog(@"mpk => %@s", sha256);

    u_int32_t rnd =   [BitsharesPlugin_impl randomInteger];
    NSLog(@"INT => %u", rnd);
	
//    NSString* data = [BitsharesPlugin_impl randomData:32];
//    NSLog(@"rnd data => %@s", data);

        NSString* data = @"799874ba3751a506835d6902f7561f5bab59e3d65f571d6ab15a22578c43df95";
        NSLog(@"rnd data => %@", data);
    

//
//    NSString* xxxx = [BitsharesPlugin_impl pbkdf2:@"lapass" withSalt:data withC:1000 withDKeyLen:32];
//    NSLog(@"xxxx => %@s", xxxx);

    u_int32_t skip =   [BitsharesPlugin_impl skip32:rnd withSkip32Key:data withEncrypt:TRUE];
    NSLog(@"skip => %u", skip);

    skip =   [BitsharesPlugin_impl skip32:skip withSkip32Key:data withEncrypt:FALSE];
    NSLog(@"un skip => %u", skip);

    return 0;
}

