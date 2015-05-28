package com.latincoin.bitwallet;

import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.math.BigInteger;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import com.google.common.base.Joiner;

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
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.PBKDF2SHA512;
import org.bitcoinj.params.MainNetParams;

import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.params.KeyParameter;

import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.InvalidCipherTextException;

import com.subgraph.orchid.crypto.PRNGFixes;
import com.subgraph.orchid.encoders.Hex;

import de.schildbach.wallet.util.Crypto;

import com.boivie.skip32.Skip32;

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

  private byte[] sha256(byte[] bytes) {
    SHA256Digest digest = new SHA256Digest();
    digest.update(bytes, 0, bytes.length);
    byte[] ret = new byte[digest.getDigestSize()];
    digest.doFinal(ret, 0);
    return ret;
  }

  private byte[] sha512(byte[] bytes) {
    SHA512Digest digest = new SHA512Digest();
    digest.update(bytes, 0, bytes.length);
    byte[] ret = new byte[digest.getDigestSize()];
    digest.doFinal(ret, 0);
    return ret;
  }

  private HMac createHmacSha256Digest(byte[] key) {
    SHA256Digest digest = new SHA256Digest();
    HMac hMac = new HMac(digest);
    hMac.init(new KeyParameter(key));
    return hMac;
  }

  private byte[] hmacSha256(HMac hmacSha256, byte[] input) {
    hmacSha256.reset();
    hmacSha256.update(input, 0, input.length);
    byte[] out = new byte[32];
    hmacSha256.doFinal(out, 0);
    return out;
  }

  private byte[] hmacSha256(byte[] key, byte[] data) {
    return hmacSha256(createHmacSha256Digest(key), data);
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

  private DeterministicKey fromB58(String parent, String key) {
    if ( key.isEmpty() )
      return null;
      
    if ( parent.isEmpty() )
      return DeterministicKey.deserializeB58(null, key);

    return DeterministicKey.deserializeB58(DeterministicKey.deserializeB58(null, parent), key);
  }
  
  private JSONObject extractDataFromKey(Boolean test, String grandParent, String parent, String key) throws UnsupportedEncodingException, JSONException {

    DeterministicKey dk = DeterministicKey.deserializeB58(fromB58(grandParent, parent), key);
    byte[] pubkey =  ECKey.publicKeyFromPrivate(dk.getPrivKey(), true);

    JSONObject result = new JSONObject();
    result.put("address", bts_pub_to_address(test, pubkey));
    result.put("pubkey" , bts_encode_pubkey(test, pubkey));
    result.put("privkey", dk.getPrivateKeyEncoded(main));
    result.put("privkey_hex", new String(Hex.encode(dk.getPrivKeyBytes()), "UTF-8"));
    return result;
  }

  private JSONObject derivePrivate(Boolean test, String grandParent, String parent, String key, int deriv) throws UnsupportedEncodingException, JSONException {
    
    DeterministicKey dk = HDKeyDerivation.deriveChildKey(DeterministicKey.deserializeB58(fromB58(grandParent, parent), key), new ChildNumber(deriv, true));
    String child = dk.serializePrivB58();
    JSONObject result = extractDataFromKey(test, parent, key, child);
    result.put("extendedPrivateKey", child);
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

  private JSONObject isValidKey(Boolean test, String grandParent, String parent, String key) throws JSONException {
    DeterministicKey dk = DeterministicKey.deserializeB58(fromB58(grandParent, parent), key);
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

  private JSONObject requestSignature(String key, String nonce, String url, String body) throws JSONException, IOException {
    JSONObject result = new JSONObject();
    String tmp = nonce + url + body;
    byte[] signature = hmacSha256(key.getBytes(), tmp.getBytes());
    result.put("signature", new String(Hex.encode(signature), "UTF-8"));
    return result;
  }

  private byte[] getSharedSecret(ECKey Qp, ECKey dd) {
    ECKey tmp = ECKey.fromPublicOnly( ECKey.compressPoint(Qp.getPubKeyPoint().multiply(dd.getPrivKey())) );
    byte[] Xk_b = Arrays.copyOfRange(tmp.getPubKey(), 1, 33);
    return sha512(Xk_b);
  }

  private JSONObject decryptMemo( Boolean test, String oneTimeKey, String encryptedMemo, String privKey) throws JSONException, IOException, Exception, InvalidCipherTextException {
    JSONObject result = new JSONObject();

    int _error       = 1;
    String _from     = "";
    String _from_sig = "";
    String _type     = "";
    String _message  = "";

    try {

      ECKey dd = new DumpedPrivateKey(null, privKey).getKey();
      ECKey Qp = ECKey.fromPublicOnly(bts_decode_pubkey(test, oneTimeKey));

      byte[] ss = getSharedSecret(Qp, dd);

      final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
      KeyParameter kp = new KeyParameter(Arrays.copyOfRange(ss, 0, 32));
      CipherParameters ivAndKey= new ParametersWithIV(kp, Arrays.copyOfRange(ss, 32, 32+16));
      cipher.init(false, ivAndKey);

      byte[] cipherBytes = Hex.decode(encryptedMemo); 

      final byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
      final int processLen = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
      final int doFinalLen = cipher.doFinal(decryptedBytes, processLen);

      byte[] memo_data = Arrays.copyOf(decryptedBytes, processLen + doFinalLen);

      byte[] message = new byte[19+32];
      Arrays.fill(message, (byte)0);

      _from     = bts_encode_pubkey(test, Arrays.copyOfRange(memo_data, 0, 33));
      _from_sig = new String( Hex.encode( Arrays.copyOfRange(memo_data, 33, 33+8) ), "UTF-8");

      System.arraycopy(memo_data, 33+8, message, 0,  19);

      _type     = new String( Hex.encode( Arrays.copyOfRange(memo_data, 33+8+19, 33+8+19+1)), "UTF-8");

      if(memo_data.length > 33+8+1+19) {
        System.arraycopy(memo_data, 33+8+1+19, message, 19,  32);
      }

      //_message = new String(message, "UTF-8");
      //
      
      int message_len = message.length;
      for(int i=0; i<message.length; i++)
      {
        if(message[i] == 0x00){
          message_len = i+1;
          break;
        }
      }

      _message = new String(message, 0, message_len, "UTF-8");
      _error = 0;
    }
    catch (Exception ex) {

    }

    result.put("from"     , _from);
    result.put("from_sig" , _from_sig);
    result.put("type"     , _type);
    result.put("message"  , _message);
    result.put("error"    , _error);

    return result;
  }

  private JSONObject createMemo(Boolean test, String fromPubkey, String destPubkey, String message, String oneTimePriv) throws JSONException, IOException, Exception, InvalidCipherTextException {
    JSONObject result = new JSONObject();
    //dest = (dd, Qd)
    //tmp  = (dp, Qp)
    //(xk, yk) = dp * Qd
    //ss = sha512(xk)
    //ss[:32] => key
    //ss[32:48] => iv

    //One time key
    ECKey dp = new DumpedPrivateKey(null, oneTimePriv).getKey();
    ECKey Qp = ECKey.fromPublicOnly( ECKey.compressPoint(dp.getPubKeyPoint()) );

    ECKey Qd = ECKey.fromPublicOnly(bts_decode_pubkey(test, destPubkey));

    byte[] ss = getSharedSecret(Qd, dp);

    //build memo data
    byte[] fromPubkey_b = bts_decode_pubkey(test, fromPubkey);
    byte[] message_b    = message.getBytes();

    byte[] memo_content = new byte[message_b.length > 19 ? 33+8+19+1+32 : 33+8+19+1]; 
    Arrays.fill(memo_content, (byte)0);

    //BTS_BLOCKCHAIN_MAX_MEMO_SIZE      = 19
    //BTS_BLOCKCHAIN_EXTENDED_MEMO_SIZE = 32
    //total=51

    System.arraycopy(fromPubkey_b, 0, memo_content,    0,       33);
    System.arraycopy(ss,           0, memo_content, 33+0,       8);
    System.arraycopy(message_b,    0, memo_content, 33+8,       Math.min(message_b.length, 19));

    if( message_b.length > 19 )
      System.arraycopy(message_b, 19, memo_content, 33+8+19+1,  Math.min(message_b.length-19, 32));

    final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
    KeyParameter kp = new KeyParameter(Arrays.copyOfRange(ss, 0, 32));
    CipherParameters ivAndKey= new ParametersWithIV(kp, Arrays.copyOfRange(ss, 32, 32+16));
    cipher.init(true, ivAndKey);

    final byte[] encryptedBytes = new byte[cipher.getOutputSize(memo_content.length)];
    final int processLen = cipher.processBytes(memo_content, 0, memo_content.length, encryptedBytes, 0);
    final int doFinalLen = cipher.doFinal(encryptedBytes, processLen);

    byte[] encrypted_memo_data = Arrays.copyOf(encryptedBytes, processLen + doFinalLen);

    result.put("one_time_key", bts_encode_pubkey(test, Qp.getPubKey()));
    result.put("encrypted_memo_data", new String(Hex.encode(encrypted_memo_data), "UTF-8"));
    return result;
  }

  private void initMnemonicInstance() throws IOException {
    if ( MnemonicCode.INSTANCE == null ) {
      //HACK!!
      String BIP39_ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";
      MnemonicCode.INSTANCE = new MnemonicCode(cordova.getActivity().getAssets().open("english.txt"), BIP39_ENGLISH_SHA256);
    }
  }

  private JSONObject createMnemonic( int entropy ) throws JSONException, IOException, Exception {
    initMnemonicInstance();
    JSONObject result = new JSONObject();
    String words = Joiner.on(" ").join( MnemonicCode.INSTANCE.toMnemonic(new SecureRandom().generateSeed(entropy/8)) ); 
    result.put("words", words);
    return result;
  }

  private JSONObject mnemonicToMasterKey( String words ) throws JSONException, IOException, Exception {
    JSONObject result = new JSONObject();
    byte[] seed = MnemonicCode.toSeed(Arrays.asList(words.split(" ")), "");

    DeterministicKey dk = HDKeyDerivation.createMasterPrivateKey(seed);

    result.put("masterPrivateKey", dk.serializePrivB58());
    return result;
  }

  private JSONObject sha256( String data ) throws JSONException, IOException, Exception {
    JSONObject result = new JSONObject();
    result.put("sha256", new String(Hex.encode(sha256(data.getBytes())), "UTF-8"));
    return result;
  }

  private JSONObject randomInteger()  throws JSONException, IOException, Exception {
    JSONObject result = new JSONObject();
    int _int = ByteBuffer.wrap(new SecureRandom().generateSeed(4)).getInt(); 
    result.put("int", _int);
    return result;
  }

  private JSONObject randomData(int length)  throws JSONException, IOException, Exception {
    JSONObject result = new JSONObject();
    byte[] random = new SecureRandom().generateSeed(length);
    result.put("random", new String(Hex.encode(random), "UTF-8"));
    return result;
  }

  private JSONObject skip32( int value, String skip32key, Boolean encrypt )  throws JSONException, IOException, Exception {
    JSONObject result = new JSONObject();
    byte[] key = Hex.decode(skip32key);
    int _skip32_int = encrypt ? Skip32.encrypt(value, key) : Skip32.decrypt(value, key); 
    result.put("skip32", _skip32_int);
    return result;
  }

  private JSONObject pbkdf2(String password, String salt, int c, int dkLen)  throws JSONException, IOException, Exception {
    JSONObject result = new JSONObject();
    byte[] key = PBKDF2SHA512.derive(password, salt, c, dkLen);
    result.put("key", new String(Hex.encode(key), "UTF-8"));
    result.put("key_hash", new String(Hex.encode(sha256(key)), "UTF-8"));
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
        callbackContext.success( extractDataFromKey( params.getBoolean("test"), params.getString("grandParent"), params.getString("parent"), params.getString("key") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("derivePrivate")) {
      try {
        callbackContext.success( derivePrivate( params.getBoolean("test"), params.getString("grandParent"), params.getString("parent"), params.getString("key"), params.getInt("deriv") ) );
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
        callbackContext.success( isValidKey( params.getBoolean("test"), params.getString("grandParent"), params.getString("parent"), params.getString("key") ) );
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
    } else
    if (action.equals("requestSignature")) {
      try {
        callbackContext.success( requestSignature( params.getString("key"), params.getString("nonce"), params.getString("url"), params.getString("body") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("createMemo")) {
      try {
        callbackContext.success( createMemo( params.getBoolean("test"), params.getString("fromPubkey"), params.getString("destPubkey"), params.getString("message"), params.getString("oneTimePriv") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("decryptMemo")) {
      try {
        callbackContext.success( decryptMemo( params.getBoolean("test"), params.getString("oneTimeKey"), params.getString("encryptedMemo"), params.getString("privKey") ) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("createMnemonic")) {
      try {
        callbackContext.success( createMnemonic(params.getInt("entropy")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("mnemonicToMasterKey")) {
      try {
        callbackContext.success( mnemonicToMasterKey(params.getString("words")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("sha256")) {
      try {
        callbackContext.success( sha256(params.getString("data")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("randomInteger")) {
      try {
        callbackContext.success( randomInteger() );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("randomData")) {
      try {
        callbackContext.success( randomData(params.getInt("length")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("skip32")) {
      try {
        callbackContext.success( skip32(params.getInt("value"), params.getString("key"), params.getBoolean("encrypt")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    } else
    if (action.equals("pbkdf2")) {
      try {
        callbackContext.success( pbkdf2(params.getString("password"), params.getString("salt"), params.getInt("c"), params.getInt("dkLen")) );
        return true;
      } catch (Exception e) {
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, e.toString()));
      }
    }


    return false;
  }
}


