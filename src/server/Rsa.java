package server;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Rsa {
    public String KEY_ALGORITHM = "RSA";
    private String PUBLIC_KEY = "RSAPublicKey";
    private String PRIVATE_KEY = "RSAPrivateKey";
    private int MAX_ENCRYPT_BLOCK = 117;
    private int MAX_DECRYPT_BLOCK = 128;
    public String SIGN_ALGORITHMS = "SHA1WithRSA";

    public Rsa() {
    }

    public Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(this.KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap(2);
        keyMap.put(this.PUBLIC_KEY, publicKey);
        keyMap.put(this.PRIVATE_KEY, privateKey);
        return keyMap;
    }

    public String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key)keyMap.get(this.PRIVATE_KEY);
        return new String(Base64.encode(key.getEncoded()));
    }

    public String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key)keyMap.get(this.PUBLIC_KEY);
        return new String(Base64.encode(key.getEncoded()));
    }

    public byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
        byte[] keyBytes = Base64.decode(key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(this.KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(1, privateKey);
        byte[] tmp = cipher.doFinal(data);
        return tmp;
    }

    public byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
        byte[] keyBytes = Base64.decode(key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(this.KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(2, publicKey);
        return cipher.doFinal(data);
    }

    public byte[] encryptByPublicKey(byte[] data, String key, Cipher cipher) throws Exception {
        byte[] keyBytes = Base64.decode(key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(this.KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        cipher.init(1, publicKey);
        byte[] output = cipher.doFinal(data);
        return output;
    }

    public byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        byte[] keyBytes = Base64.decode(key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(this.KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(2, privateKey);
        return cipher.doFinal(data);
    }

    public String Encrypt(String strSrc, String encName) {
        MessageDigest md = null;
        String strDes = null;
        byte[] bt = strSrc.getBytes();

        try {
            if (encName == null || encName.equals("")) {
                encName = "MD5";
            }

            md = MessageDigest.getInstance(encName);
            md.update(bt);
            String str = "sh1bit:";
            byte[] shabt = md.digest();
            strDes = this.ByteToHex(shabt);

            for(int i = 0; i < shabt.length; ++i) {
                str = str + shabt[i] + ",";
            }

            return strDes;
        } catch (NoSuchAlgorithmException var9) {
            return null;
        }
    }

    public String ByteToHex(byte[] byteArray) {
        StringBuffer StrBuff = new StringBuffer();

        for(int i = 0; i < byteArray.length; ++i) {
            if (Integer.toHexString(255 & byteArray[i]).length() == 1) {
                StrBuff.append("0").append(Integer.toHexString(255 & byteArray[i]));
            } else {
                StrBuff.append(Integer.toHexString(255 & byteArray[i]));
            }
        }

        return StrBuff.toString();
    }

    private byte charToByte(char c) {
        return (byte)"0123456789ABCDEF".indexOf(c);
    }

    public String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src != null && src.length > 0) {
            for(int i = 0; i < src.length; ++i) {
                int v = src[i] & 255;
                String hv = Integer.toHexString(v);
                if (hv.length() < 2) {
                    stringBuilder.append(0);
                }

                stringBuilder.append(hv);
            }

            return stringBuilder.toString();
        } else {
            return null;
        }
    }

    public byte[] hexStringToBytes(String hexString) {
        if (hexString != null && !hexString.equals("")) {
            hexString = hexString.toUpperCase();
            int length = hexString.length() / 2;
            char[] hexChars = hexString.toCharArray();
            byte[] d = new byte[length];

            for(int i = 0; i < length; ++i) {
                int pos = i * 2;
                d[i] = (byte)(this.charToByte(hexChars[pos]) << 4 | this.charToByte(hexChars[pos + 1]));
            }

            return d;
        } else {
            return null;
        }
    }
}
