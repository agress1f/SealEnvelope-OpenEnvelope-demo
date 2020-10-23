package server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ThrDES {
    private String Algorithm = "DESede";

    public ThrDES() {
    }

    public byte[] encryptMode(byte[] keybyte, byte[] src, Cipher cipher) throws Exception {
        try {
            SecretKey deskey = new SecretKeySpec(keybyte, this.Algorithm);
            cipher.init(1, deskey);
            byte[] b = cipher.doFinal(src);
            return b;
        } catch (Exception var6) {
            throw new Exception("encryptMode error:" + var6.getMessage());
        }
    }

    public byte[] decryptMode(byte[] keybyte, byte[] src, Cipher cipher) throws Exception {
        try {
            SecretKey deskey = new SecretKeySpec(keybyte, this.Algorithm);
            cipher.init(2, deskey);
            byte[] b = cipher.doFinal(src);
            return b;
        } catch (Exception var6) {
            throw new Exception("decryptMode error:" + var6.getMessage());
        }
    }

    public String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";

        for(int n = 0; n < b.length; ++n) {
            stmp = Integer.toHexString(b[n] & 255);
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }

            if (n < b.length - 1) {
                hs = hs + ":";
            }
        }

        return hs.toUpperCase();
    }
}
