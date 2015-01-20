package com.latincoin.bitwallet;

import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.security.SecureRandom;
import java.math.BigInteger;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.params.MainNetParams;

import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;

import com.subgraph.orchid.crypto.PRNGFixes;
import com.subgraph.orchid.encoders.Hex;

import de.schildbach.wallet.util.Crypto;

public class BitsharesPlugin extends CordovaPlugin {

  private NetworkParameters main = MainNetParams.get();
  private static final String PROD_PREFIX = "BTS";
  private static final String TEST_PREFIX = "DVS";

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    PRNGFixes.apply();
  }

  private JSONObject createMasterKey(Boolean test) throws JSONException {
    DeterministicKey dk = HDKeyDerivation.createMasterPrivateKey( new SecureRandom().generateSeed(32) );

    JSONObject result = new JSONObject();
    result.put("masterPrivateKey", dk.serializePrivB58());
    return result;
  }

  private byte[] sha512(byte[] bytes) {
    SHA512Digest digest = new SHA512Digest();
    digest.update(bytes, 0, bytes.length);
    byte[] ret = new byte[digest.getDigestSize()];
    digest.doFinal(ret, 0);
    return ret;
  }

  private byte[] ripemd160(byte[] bytes) {
    RIPEMD160Digest digest = new RIPEMD160Digest();
    digest.update(bytes, 0, bytes.length);
    byte[] ret = new byte[digest.getDigestSize()];
    digest.doFinal(ret, 0);
    return ret;
  }

  private String bts_pub_to_address(Boolean test, byte[] pubkey) {
    byte[] r = ripemd160( sha512(pubkey) );
    byte[] c = ripemd160( r );
    byte[] tmp = new byte[r.length+4];
    System.arraycopy(r, 0, tmp, 0, r.length);
    System.arraycopy(c, 0, tmp, r.length, 4);
    
    return (test ? TEST_PREFIX : PROD_PREFIX) + Base58.encode(tmp);
  }

  private String bts_encode_pubkey(Boolean test, byte[] pubkey) {
    byte[] r = ripemd160( pubkey );
    byte[] tmp = new byte[pubkey.length+4];
    System.arraycopy(pubkey, 0, tmp, 0, pubkey.length);
    System.arraycopy(r, 0, tmp, pubkey.length, 4);
    return (test ? TEST_PREFIX : PROD_PREFIX) + Base58.encode(tmp);
  }

  private byte[] bts_decode_pubkey(Boolean test, String pubkey) throws Exception {
    if(pubkey.indexOf(test ? TEST_PREFIX : PROD_PREFIX) != 0) throw new Exception("invalid prefix");
    byte[] data = Base58.decode(pubkey.substring(3));
    if(data.length != 37) throw new Exception("invalid length");
    byte[] c1 = Arrays.copyOfRange(data, 33, 37);
    byte[] pubkey_data = Arrays.copyOfRange(data, 0, 33);
    byte[] c2 = ripemd160(pubkey_data);
    if(!((c1[0] == c2[0] && c1[1] == c2[1] && c1[2] == c2[2] && c1[3] == c2[3]))) throw new Exception("invalid checksum");
    return pubkey_data;
  }

  private Boolean bts_is_valid_address(Boolean test, String addy) throws Exception {
    if(addy.indexOf(test ? TEST_PREFIX : PROD_PREFIX) != 0) throw new Exception("invalid prefix");
    byte[] data = Base58.decode(addy.substring(3));
    if(data.length != 24) throw new Exception("invalid length");
    byte[] c1 = Arrays.copyOfRange(data, 20, 24);
    byte[] c2 = ripemd160(Arrays.copyOfRange(data, 0, 20));
    if(!((c1[0] == c2[0] && c1[1] == c2[1] && c1[2] == c2[2] && c1[3] == c2[3]))) throw new Exception("invalid checksum");
    return true;
  }

  private JSONObject extractDataFromKey(Boolean test, String key) throws JSONException {

    DeterministicKey dk = DeterministicKey.deserializeB58(null, key);
    byte[] pubkey =  ECKey.publicKeyFromPrivate(dk.getPrivKey(), true);

    JSONObject result = new JSONObject();
    result.put("address", bts_pub_to_address(test, pubkey));
    result.put("pubkey" , bts_encode_pubkey(test, pubkey));
    result.put("privkey", dk.getPrivateKeyEncoded(main));
    return result;
  }

  private JSONObject extendedPublicFromPrivate(Boolean test, String key) throws JSONException {

    DeterministicKey dk = DeterministicKey.deserializeB58(null, key);

    JSONObject result = new JSONObject();
    result.put("extendedPublicKey", dk.serializePubB58());
    return result;

  }

  private JSONObject derivePrivate(Boolean test, String key, int deriv) throws JSONException {
    DeterministicKey dk = HDKeyDerivation.deriveChildKey(DeterministicKey.deserializeB58(null, key), new ChildNumber(deriv, false));
    JSONObject result = new JSONObject();
    result.put("extendedPrivateKey", dk.serializePrivB58());
    return result;
  }


  private byte[] compactSing(Sha256Hash hash, ECKey key) {
    ECKey.ECDSASignature sig = key.sign(hash).toCanonicalised();

    ECPoint pub = key.getPubKeyPoint();
    
    // Now we have to work backwards to figure out the recId needed to recover the signature.
    int recId = -1;
    for (int i = 0; i < 4; i++) {
        ECKey k = ECKey.recoverFromSignature(i, sig, hash, key.isCompressed());
        if (k != null && k.getPubKeyPoint().equals(pub)) {
            recId = i;
            break;
        }
    }
    if (recId == -1)
        throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
    int headerByte = recId + 27 + (key.isCompressed() ? 4 : 0);
    byte[] sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes for S
    sigData[0] = (byte)headerByte;
    System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32), 0, sigData, 1, 32);
    System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32), 0, sigData, 33, 32);
    return sigData;
  }
  
  private JSONObject compactSignatureForHash(Boolean test, String Wif, String hash) throws UnsupportedEncodingException, AddressFormatException, JSONException {
    ECKey key = new DumpedPrivateKey(null, Wif).getKey();
    byte[] signature = compactSing(new Sha256Hash(hash), key);
    JSONObject result = new JSONObject();
    result.put("compactSignatureForHash", new String(Hex.encode(signature), "UTF-8"));
    return result;
  }

  private JSONObject compactSignatureForMessage(Boolean test, String Wif, String msg) throws UnsupportedEncodingException, AddressFormatException, JSONException {
    String hash = new String(Hex.encode(Sha256Hash.create(msg.getBytes()).getBytes()), "UTF-8");
    return compactSignatureForHash(test, Wif, hash);
  }

  private JSONObject recoverPubkey(Boolean test, String signature, String msg) throws UnsupportedEncodingException, AddressFormatException, JSONException {
    byte[] sig_bytes = Hex.decode(signature);

    int recId = (int)sig_bytes[0];
    recId -= 27; recId &= 3;

    Sha256Hash hash = Sha256Hash.create(msg.getBytes());

    BigInteger r = new BigInteger(Arrays.copyOfRange(sig_bytes, 1,  33));
    BigInteger s = new BigInteger(Arrays.copyOfRange(sig_bytes, 33, 65));
    ECKey key = ECKey.recoverFromSignature(recId, new ECKey.ECDSASignature(r,s), hash, true);

    JSONObject result = new JSONObject();
    result.put("pubKey", key != null ? bts_encode_pubkey(test, key.getPubKey()) : "<null>");
    return result;
  }

  private JSONObject isValidKey(Boolean test, String key) throws JSONException {
    DeterministicKey dk = DeterministicKey.deserializeB58(null, key);
    JSONObject result = new JSONObject();
    result.put("is_valid", "true");
    return result;
  }

  private JSONObject isValidWif(Boolean test, String wif) throws JSONException, AddressFormatException {
    ECKey key = new DumpedPrivateKey(null, wif).getKey();
    JSONObject result = new JSONObject();
    result.put("is_valid", "true");
    return result;
  }

  private JSONObject btsWifToAddress(Boolean test, String wif) throws JSONException, AddressFormatException {
    ECKey key = new DumpedPrivateKey(null, wif).getKey();
    byte[] pubkey =  ECKey.publicKeyFromPrivate(key.getPrivKey(), true);

    JSONObject result = new JSONObject();
    result.put("addy", bts_pub_to_address(test, pubkey));
    return result;
  }

  private JSONObject btsPubToAddress(Boolean test, String pubkey) throws JSONException, Exception {
    String addy = bts_pub_to_address( test, bts_decode_pubkey(test, pubkey) );
    JSONObject result = new JSONObject();
    result.put("addy", addy);
    return result;
  } 

  private JSONObject btsIsValidAddress(Boolean test, String addy) throws JSONException, Exception {
    bts_is_valid_address( test, addy );
    JSONObject result = new JSONObject();
    result.put("is_valid", "true");
    return result;
  }

  private JSONObject btsIsValidPubkey(Boolean test, String pubkey) throws JSONException, Exception {
    byte[] pub = bts_decode_pubkey(test, pubkey);
    JSONObject result = new JSONObject();
    result.put("is_valid", "true");
    return result;
  }

  private JSONObject encryptString(Boolean test, String data, String password) throws JSONException, IOException {
    String encryptedData = Crypto.encrypt(data, password.toCharArray()).replaceAll("\n", "");
    JSONObject result = new JSONObject();
    result.put("encryptedData", encryptedData);
    return result;
  }

  private JSONObject decryptString(Boolean test, String data, String password) throws JSONException, IOException {
    String decryptedData = Crypto.decrypt(data.replaceAll("\n",""), password.toCharArray());
    JSONObject result = new JSONObject();
    result.put("decryptedData", decryptedData);
    return result;
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

    JSONObject params = new JSONObject();
    if(args.length() > 0)
      params = args.getJSONObject(0);

    if (action.equals("createMasterKey")) {
      try {
        callbackContext.success( createMasterKey(params.getBoolean("test")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else 
    if (action.equals("extractDataFromKey")) {
      try {
        callbackContext.success( extractDataFromKey( params.getBoolean("test"), params.getString("key") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("extendedPublicFromPrivate")) {
      try {
        callbackContext.success( extendedPublicFromPrivate( params.getBoolean("test"), params.getString("key") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("derivePrivate")) {
      try {
        callbackContext.success( derivePrivate( params.getBoolean("test"), params.getString("key"), params.getInt("deriv") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("compactSignatureForHash")) {
      try {
        callbackContext.success( compactSignatureForHash( params.getBoolean("test"), params.getString("wif"), params.getString("hash") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("compactSignatureForMessage")) {
      try {
        callbackContext.success( compactSignatureForMessage( params.getBoolean("test"), params.getString("wif"), params.getString("msg") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("recoverPubkey")) {
      try {
        callbackContext.success( recoverPubkey( params.getBoolean("test"), params.getString("signature"), params.getString("msg") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("isValidKey")) {
      try {
        callbackContext.success( isValidKey( params.getBoolean("test"), params.getString("key") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("isValidWif")) {
      try {
        callbackContext.success( isValidWif( params.getBoolean("test"), params.getString("wif") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsWifToAddress")) {
      try {
        callbackContext.success( btsWifToAddress( params.getBoolean("test"), params.getString("wif") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsPubToAddress")) {
      try {
        callbackContext.success( btsPubToAddress( params.getBoolean("test"), params.getString("pubkey") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsIsValidAddress")) {
      try {
        callbackContext.success( btsIsValidAddress( params.getBoolean("test"), params.getString("addy") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("btsIsValidPubkey")) {
      try {
        callbackContext.success( btsIsValidPubkey( params.getBoolean("test"), params.getString("pubkey") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("encryptString")) {
      try {
        callbackContext.success( encryptString( params.getBoolean("test"), params.getString("data"), params.getString("password") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("decryptString")) {
      try {
        callbackContext.success( decryptString( params.getBoolean("test"), params.getString("data"), params.getString("password") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    }

    return false;
  }
}


