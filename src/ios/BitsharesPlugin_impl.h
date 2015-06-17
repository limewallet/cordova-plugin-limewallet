//
//  BitsharesPlugin.h
//  Bitwallet
//
//  Created by Pablo on 12/2/14.
//
//

@interface BitsharesPlugin_impl

+(NSMutableData*) BTCSHA512:(NSData*)data;
+(NSMutableData*) BTCSHA256:(NSData*)data;

+(NSString *) createMasterKey;

@end
