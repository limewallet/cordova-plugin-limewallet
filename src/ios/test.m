#import <Foundation/Foundation.h>

#include "BitsharesPlugin_impl.h"  

int main (int argc, const char * argv[])
{
  NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];

  NSString *mpk = [BitsharesPlugin_impl createMasterKey];



  NSLog (@"hello world");
  [pool drain];
  return 0;
}

