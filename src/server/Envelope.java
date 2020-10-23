package server;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Envelope {
    private Rsa rsa = new Rsa();
    private ThrDES thrDES = new ThrDES();

    public Envelope() {
    }

    public String getPassword(int count, boolean letters, boolean numbers) {
        Random random = new Random();
        return random.random(count, 0,0,letters, numbers,(char[])null);
    }

    private String getPassword(int count) {
        return this.getPassword(count, true, true);
    }

    public byte[] seal_Sessionkey(X509Certificate cert, Cipher cipher, SecretKey sessionKey) throws Exception {
        byte[] o_keyHeader = new byte[]{0, 0, -92, 0, 0, 0, 102, 3, 0, 0, 2, 1};
        byte[] o_EncSessionkey = new byte[140];

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            PublicKey publickey = cert.getPublicKey();
            byte[] bPublickey = publickey.getEncoded();
            String sPublkey = new String(Base64.encode(bPublickey));
            byte[] encodedData = this.rsa.encryptByPublicKey(sessionKey.getEncoded(), sPublkey, cipher);
            System.arraycopy(encodedData, 0, o_EncSessionkey, 0, encodedData.length);
            System.arraycopy(o_keyHeader, 0, o_EncSessionkey, encodedData.length, o_keyHeader.length);
            byte[] tmp = new byte[o_EncSessionkey.length];

            for(int i = 0; i < o_EncSessionkey.length; ++i) {
                tmp[i] = o_EncSessionkey[o_EncSessionkey.length - i - 1];
            }

            return tmp;
        } catch (Exception var13) {
            throw new Exception("seal_Sessionkey error:" + var13.getMessage());
        }
    }

    public Map seal_Orignal(int i_symmAlgo, byte[] Orginal, Cipher cipher) throws Exception {
        try {
            Map map = new HashMap();
            byte[] key = this.getPassword(24).getBytes();
            String symmAlgo = "DESede";
            SecretKey sessionKey = new SecretKeySpec(key, symmAlgo);
            map.put("sessionKey", sessionKey);
            map.put("o_Secret", this.thrDES.encryptMode(sessionKey.getEncoded(), Orginal, cipher));
            return map;
        } catch (Exception var9) {
            throw new Exception("seal_Orignal error:" + var9.getMessage());
        }
    }

    public byte[] open_Orginal(byte[] sessionKey, byte[] enc_Orginal, Cipher cipher) throws Exception {
        byte[] o_Orginal = (byte[])null;
        o_Orginal = this.thrDES.decryptMode(sessionKey, enc_Orginal, cipher);
        return o_Orginal;
    }

    public byte[] open_SessionKey(byte[] enc_SessionKey, byte[] keyFile) throws Exception {
        byte[] o_Sessionkey = new byte[100];
        String var4 = "";

        try {
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyFile);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
            byte[] bPrivatekey = priKey.getEncoded();
            String sPrivatekey = new String(Base64.encode(bPrivatekey));
            byte[] tmp = new byte[enc_SessionKey.length - 12];

            for(int i = 0; i < enc_SessionKey.length - 12; ++i) {
                tmp[i] = enc_SessionKey[enc_SessionKey.length - i - 1];
            }

            o_Sessionkey = this.rsa.decryptByPrivateKey(tmp, sPrivatekey);
            return o_Sessionkey;
        } catch (Exception var12) {
            throw new Exception("open_SessionKey error:" + var12.getMessage());
        }
    }

    public String open_Envelope(String KeyLable, String Password, String in_Data) {
        String restult = "";
        return restult;
    }

    public String seal_Envelope(String i_encCert, int i_symmAlgo, String i_inData) {
        String restult = "";
        DESedeKeyGenerator generator = new DESedeKeyGenerator();
        byte[] DesedeKey = generator.generateKey();
        byte[] enc_data = i_encCert.getBytes();
        StreamCipher cipher = new RC4Engine();
        cipher.init(true, new KeyParameter(DesedeKey));
        byte[] cipherText = new byte[enc_data.length];

        try {
            cipher.processBytes(enc_data, 0, enc_data.length, cipherText, 0);
        } catch (Exception var11) {
            ;
        }

        return restult;
    }
}
