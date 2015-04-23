
//cordova.define("com.latincoin.BitsharesPlugin.BitsharesPlugin", function(require, exports, module) {
  var cordova = require('cordova');
  var is_test = true;
  function BitsharesPlugin() {}
  
  BitsharesPlugin.prototype.setTest = function (isTest) {
   is_test = isTest;
  };
 
  BitsharesPlugin.prototype.createMasterKey = function (successCB, errorCB) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'createMasterKey', [{'test':is_test}]);
  };

  BitsharesPlugin.prototype.extractDataFromKey = function (successCB, errorCB, key) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'extractDataFromKey', [{'test':is_test, "key": key}]);
  };

  BitsharesPlugin.prototype.extendedPublicFromPrivate = function (successCB, errorCB, key) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'extendedPublicFromPrivate', [{'test':is_test, "key": key}]);
  };

  BitsharesPlugin.prototype.derivePrivate = function (successCB, errorCB, key, deriv) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'derivePrivate', [{'test':is_test, "key": key, "deriv": deriv}]);
  };

  BitsharesPlugin.prototype.encryptString = function (successCB, errorCB, data, password) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'encryptString', [{'test':is_test, "data": data, "password": password}]);
  };

  BitsharesPlugin.prototype.decryptString = function (successCB, errorCB, data, password) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'decryptString', [{'test':is_test, "data": data, "password": password}]);
  };

  BitsharesPlugin.prototype.isValidKey = function (successCB, errorCB, key) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'isValidKey', [{'test':is_test, "key": key}]);
  };

  BitsharesPlugin.prototype.isValidWif = function (successCB, errorCB, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'isValidWif', [{'test':is_test, "wif": wif}]);
  };

  BitsharesPlugin.prototype.compactSignatureForHash = function (successCB, errorCB, hash, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'compactSignatureForHash', [{'test':is_test, "hash": hash, "wif": wif}]);
  };

  BitsharesPlugin.prototype.compactSignatureForMessage = function (successCB, errorCB, msg, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'compactSignatureForMessage', [{'test':is_test, "msg": msg, "wif": wif}]);
  };

  BitsharesPlugin.prototype.recoverPubkey = function (successCB, errorCB, msg, signature) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'recoverPubkey', [{'test':is_test, "msg": msg, "signature": signature}]);
  };

  BitsharesPlugin.prototype.btsWifToAddress = function (successCB, errorCB, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsWifToAddress', [{'test':is_test, "wif": wif}]);
  };

  BitsharesPlugin.prototype.btsPubToAddress = function (successCB, errorCB, pubkey) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsPubToAddress', [{'test':is_test, "pubkey": pubkey}]);
  };

  BitsharesPlugin.prototype.btsIsValidAddress = function (successCB, errorCB, addy) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsIsValidAddress', [{'test':is_test, "addy": addy}]);
  };

  BitsharesPlugin.prototype.btsIsValidPubkey = function (successCB, errorCB, pubkey) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsIsValidPubkey', [{'test':is_test, "pubkey": pubkey}]);
  };

  BitsharesPlugin.prototype.btcIsValidAddress = function (successCB, errorCB, addy) {
    cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btcIsValidAddress', [{'test':is_test, "addy": addy}]);
  };

  BitsharesPlugin.prototype.requestSignature = function (successCB, errorCB, key, nonce, url, body) {
    cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'requestSignature', [{'key':key, "none": nonce, "url":url, "body":body}]);
  };
  
  BitsharesPlugin.install = function () {
    if (!window.plugins) {
      window.plugins = {};
    }
    window.plugins.BitsharesPlugin = new BitsharesPlugin();
    return window.plugins.BitsharesPlugin;
  };
   
  cordova.addConstructor(BitsharesPlugin.install);
//});

