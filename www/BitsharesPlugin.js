//cordova.define("com.latincoin.BitsharesPlugin.BitsharesPlugin", function(require, exports, module) {
  var cordova = require('cordova');
  function BitsharesPlugin() {}
  
 
  BitsharesPlugin.prototype.createMasterKey = function (successCB, errorCB) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'createMasterKey', []);
  };

  BitsharesPlugin.prototype.extractDataFromKey = function (successCB, errorCB, key) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'extractDataFromKey', [{"key": key}]);
  };

  BitsharesPlugin.prototype.extendedPublicFromPrivate = function (successCB, errorCB, key) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'extendedPublicFromPrivate', [{"key": key}]);
  };

  BitsharesPlugin.prototype.derivePrivate = function (successCB, errorCB, key, deriv) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'derivePrivate', [{"key": key, "deriv": deriv}]);
  };

  BitsharesPlugin.prototype.encryptString = function (successCB, errorCB, data, password) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'encryptString', [{"data": data, "password": password}]);
  };

  BitsharesPlugin.prototype.decryptString = function (successCB, errorCB, data, password) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'decryptString', [{"data": data, "password": password}]);
  };

  BitsharesPlugin.prototype.isValidKey = function (successCB, errorCB, key) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'isValidKey', [{"key": key}]);
  };

  BitsharesPlugin.prototype.isValidWif = function (successCB, errorCB, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'isValidWif', [{"wif": wif}]);
  };

  BitsharesPlugin.prototype.compactSignatureForHash = function (successCB, errorCB, hash, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'compactSignatureForHash', [{"hash": hash, "wif": wif}]);
  };

  BitsharesPlugin.prototype.btsWifToAddress = function (successCB, errorCB, wif) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsWifToAddress', [{"wif": wif}]);
  };

  BitsharesPlugin.prototype.btsPubToAddress = function (successCB, errorCB, pubkey) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsPubToAddress', [{"pubkey": pubkey}]);
  };

  BitsharesPlugin.prototype.btsIsValidAddress = function (successCB, errorCB, addy) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsIsValidAddress', [{"addy": addy}]);
  };

  BitsharesPlugin.prototype.btsIsValidPubkey = function (successCB, errorCB, pubkey) {
   cordova.exec(successCB, errorCB, 'BitsharesPlugin', 'btsIsValidPubkey', [{"pubkey": pubkey}]);
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
