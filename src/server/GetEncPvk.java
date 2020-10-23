package server;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class GetEncPvk {
    public GetEncPvk() {
    }

    public byte[] getKey(String password, byte[] enckey) throws Exception {
        try {
            ASN1InputStream asn1InputStream = new ASN1InputStream(enckey);
            ASN1Sequence asn1Sequence = (ASN1Sequence)asn1InputStream.readObject();
            byte[] contentEnckey = ((ASN1OctetString)asn1Sequence.getObjectAt(1)).getOctets();
            byte[] salt = ((ASN1OctetString)((ASN1Sequence)((ASN1Sequence)asn1Sequence.getObjectAt(0)).getObjectAt(1)).getObjectAt(0)).getOctets();
            int count = ((ASN1Integer)((ASN1Sequence)((ASN1Sequence)asn1Sequence.getObjectAt(0)).getObjectAt(1)).getObjectAt(1)).getValue().intValue();
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
            PBEKeySpec passwordKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey deskey = kf.generateSecret(passwordKeySpec);
            Cipher c1 = Cipher.getInstance("PBEWithMD5AndDES");
            c1.init(2, deskey, pbeParamSpec);
            byte[] desc = c1.doFinal(contentEnckey);
            return desc;
        } catch (Exception var14) {
            throw new Exception("please confirm the key file or protecting password");
        }
    }
}
