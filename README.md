cordova-plugin-bitwallet
========================

Bitshares plugin for Apache Cordova [BitWallet App](https://github.com/latincoin-com/bitwallet).
This plugin is a utility to perform basic crypto operations.
- Create private keys (using bip32).
- Encode pubkeys/addresses (bitshares format)
- Sign transactions
- Encrypt data

### Supported Platforms
- iOS 
- Android

iOS version is based on [Oleganza CoreBitcoin Lib](https://github.com/oleganza/CoreBitcoin) ,Android version is based on [bitcoinj](https://bitcoinj.github.io)

## How to add plugin
`cordova plugin add https://github.com/latincoin-com/cordova-plugin-bitwallet.git`
  
## iOS : Requirements after installation 
After plugin installation, open XCode project.
Please add `"$(SRCROOT)/../../plugins/com.latincoin.BitsharesPlugin/src/ios/includes"` to `Build Settings` (Combined view mode) -> `Header Search Paths`

