package com.latincoin.bitwallet;

import com.subgraph.orchid.crypto.PRNGFixes;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class BitsharesPlugin extends CordovaPlugin {

  private BitsharesPlugin_impl impl = new BitsharesPlugin_impl();

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    PRNGFixes.apply();
    try {
      impl.BIP32EnglishFile = cordova.getActivity().getAssets().open("english.txt");
    } catch(Exception ex) {
      impl.BIP32EnglishFile = null;
    }
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

    JSONObject params = new JSONObject();
    if(args.length() > 0)
      params = args.getJSONObject(0);

    if (action.equals("createMasterKey")) {
      try {
        callbackContext.success( impl.createMasterKey(params.getBoolean("test")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else 
    if (action.equals("extractDataFromKey")) {
      try {
        callbackContext.success( impl.extractDataFromKey( params.getBoolean("test"), params.getString("grandParent"), params.getString("parent"), params.getString("key") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("derivePrivate")) {
      try {
        callbackContext.success( impl.derivePrivate( params.getBoolean("test"), params.getString("grandParent"), params.getString("parent"), params.getString("key"), params.getInt("deriv") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("compactSignatureForHash")) {
      try {
        callbackContext.success( impl.compactSignatureForHash( params.getBoolean("test"), params.getString("wif"), params.getString("hash") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("compactSignatureForMessage")) {
      try {
        callbackContext.success( impl.compactSignatureForMessage( params.getBoolean("test"), params.getString("wif"), params.getString("msg") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("recoverPubkey")) {
      try {
        callbackContext.success( impl.recoverPubkey( params.getBoolean("test"), params.getString("signature"), params.getString("msg") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("isValidKey")) {
      try {
        callbackContext.success( impl.isValidKey( params.getBoolean("test"), params.getString("grandParent"), params.getString("parent"), params.getString("key") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("isValidWif")) {
      try {
        callbackContext.success( impl.isValidWif( params.getBoolean("test"), params.getString("wif") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsWifToAddress")) {
      try {
        callbackContext.success( impl.btsWifToAddress( params.getBoolean("test"), params.getString("wif") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsPubToAddress")) {
      try {
        callbackContext.success( impl.btsPubToAddress( params.getBoolean("test"), params.getString("pubkey") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsIsValidAddress")) {
      try {
        callbackContext.success( impl.btsIsValidAddress( params.getBoolean("test"), params.getString("addy") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btcIsValidAddress")) {
      try {
        callbackContext.success( impl.btcIsValidAddress( params.getBoolean("test"), params.getString("addy") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsIsValidPubkey")) {
      try {
        callbackContext.success( impl.btsIsValidPubkey( params.getBoolean("test"), params.getString("pubkey") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("encryptString")) {
      try {
        callbackContext.success( impl.encryptString( params.getBoolean("test"), params.getString("data"), params.getString("password") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("decryptString")) {
      try {
        callbackContext.success( impl.decryptString( params.getBoolean("test"), params.getString("data"), params.getString("password") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("requestSignature")) {
      try {
        callbackContext.success( impl.requestSignature( params.getString("key"), params.getString("nonce"), params.getString("url"), params.getString("body") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("createMemo")) {
      try {
        callbackContext.success( impl.createMemo( params.getBoolean("test"), params.getString("fromPubkey"), params.getString("destPubkey"), params.getString("message"), params.getString("oneTimePriv") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("decryptMemo")) {
      try {
        callbackContext.success( impl.decryptMemo( params.getBoolean("test"), params.getString("oneTimeKey"), params.getString("encryptedMemo"), params.getString("privKey") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("createMnemonic")) {
      try {
        callbackContext.success( impl.createMnemonic(params.getInt("entropy")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("mnemonicToMasterKey")) {
      try {
        callbackContext.success( impl.mnemonicToMasterKey(params.getString("words")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("sha256")) {
      try {
        callbackContext.success( impl.sha256(params.getString("data")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("randomInteger")) {
      try {
        callbackContext.success( impl.randomInteger() );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("randomData")) {
      try {
        callbackContext.success( impl.randomData(params.getInt("length")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("skip32")) {
      try {
        callbackContext.success( impl.skip32(params.getInt("value"), params.getString("key"), params.getBoolean("encrypt")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("pbkdf2")) {
      try {
        callbackContext.success( impl.pbkdf2(params.getString("password"), params.getString("salt"), params.getInt("c"), params.getInt("dkLen")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    }

    return false;
  }
}


