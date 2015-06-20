#import <Foundation/Foundation.h>

#include "BitsharesPlugin_impl.h"  

int main (int argc, const char * argv[])
{
  NSString *mpk = [BitsharesPlugin_impl createMasterKey];

  NSLog (@"hello world");

  return 0;
}

