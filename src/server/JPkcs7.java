package server;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.*;

public class JPkcs7 {
    private String envelopedDataType = new String("1.2.840.113549.1.7.3");
    private String envelopedDataVersion = "1";
    private String recipientInfoVersion = "1";
    private String encryptedContentInfocontentType = new String("1.2.840.113549.1.7.3");
    private String contentEncryptionAlgorithm = new String("1.2.840.113549.3.7");

    public JPkcs7() {
    }

    public byte[] makePKCS7ENC(X509Certificate[] certs, byte[] Orginal, int algoType, Cipher sessionKeyCipher, Cipher sealOrignalChipher) throws Exception {
        try {
            Envelope envelope = new Envelope();
            Map map = envelope.seal_Orignal(algoType, Orginal, sealOrignalChipher);
            ASN1ObjectIdentifier asn1ObjectIdentifier = this.MakeMajorVersion();
            ASN1Integer envelopedDataVersion = this.MakeEnvelopedDataVersion();
            List recipientInfoList = new ArrayList();

            for(int i = 0; i < certs.length; ++i) {
                Map recipientInfoMap = new HashMap();
                recipientInfoMap.put("cert", certs[i]);
                recipientInfoMap.put("recipientInfoVersion", this.recipientInfoVersion);
                byte[] cert = envelope.seal_Sessionkey(certs[i], sessionKeyCipher, (SecretKey)map.get("sessionKey"));
                recipientInfoMap.put("encryptedKey", cert);
                recipientInfoList.add(recipientInfoMap);
            }

            DERSet recipientInfos = this.MakeRecipientInfos(recipientInfoList);
            DERSequence encryptedContentInfoSequence = this.MakeEncryptedContentInfo((byte[])map.get("o_Secret"));
            ASN1Encodable[] asn1Encodable = new ASN1Encodable[]{envelopedDataVersion, recipientInfos, encryptedContentInfoSequence};
            DERSequence envelopedDataInfoSequence = new DERSequence(asn1Encodable);
            asn1Encodable = new ASN1Encodable[]{asn1ObjectIdentifier, envelopedDataInfoSequence};
            DERSequence envelopedData = new DERSequence(asn1Encodable);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DEROutputStream derOutputStream = new DEROutputStream(byteArrayOutputStream);
            derOutputStream.writeObject(envelopedData);
            derOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (Exception var18) {
            throw new Exception("makePKCS7ENC error:" + var18.getMessage());
        }
    }

    private ASN1ObjectIdentifier MakeMajorVersion() {
        ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(this.envelopedDataType);
        return asn1ObjectIdentifier;
    }

    private ASN1Integer MakeEnvelopedDataVersion() {
        return new ASN1Integer(new BigInteger(this.envelopedDataVersion));
    }

    private DERSet MakeRecipientInfos(List recipientInfoList) throws Exception {
        if (recipientInfoList == null) {
            throw new Exception("recipientInfoList null");
        } else {
            Iterator iterator = recipientInfoList.iterator();
            DERSequence[] recipientInfossSequences = new DERSequence[recipientInfoList.size()];

            for(int i = 0; i < recipientInfoList.size(); ++i) {
                Map recipientInfoMap = (Map)recipientInfoList.get(i);
                String recipientInfoVersionString = (String)recipientInfoMap.get("recipientInfoVersion");
                ASN1Integer recipientInfoVersion = new ASN1Integer(new BigInteger(recipientInfoVersionString));
                X509Certificate cert = (X509Certificate)recipientInfoMap.get("cert");
                JcaX509CertificateHolder jcaX509CertificateHolder = new JcaX509CertificateHolder(cert);
                X500Name x500Name = jcaX509CertificateHolder.getIssuer();
                RDN[] issuerRdns = x500Name.getRDNs();
                DERSet[] derSets = new DERSet[issuerRdns.length];

                DERSequence issuerInfo;
                for(int j = 0; j < issuerRdns.length; ++j) {
                    RDN issuerRdn = issuerRdns[j];
                    ASN1ObjectIdentifier asn1ObjectIdentifier = issuerRdn.getFirst().getType();
                    DERBMPString derbmpString = new DERBMPString(issuerRdn.getFirst().getValue().toString());
                    ASN1Encodable[] anAsn1Encodables = new ASN1Encodable[]{asn1ObjectIdentifier, derbmpString};
                    issuerInfo = new DERSequence(anAsn1Encodables);
                    DERSet derSet = new DERSet(issuerInfo);
                    derSets[j] = derSet;
                }

                DERSequence derSequence = new DERSequence(derSets);
                ASN1Encodable[] asn1Encodables = (ASN1Encodable[])null;
                String snString = this.byteToArray(cert.getSerialNumber().toByteArray());
                byte[] sn = this.hexStringToBytes(snString);
                ASN1Integer asn1Integer = new ASN1Integer(sn);
                asn1Encodables = new ASN1Encodable[]{derSequence, asn1Integer};
                issuerInfo = new DERSequence(asn1Encodables);
                ASN1ObjectIdentifier keyEncryptionAlgorithm = new ASN1ObjectIdentifier("1.2.840.113549.1.1.5");
                DERNull derNull = DERNull.INSTANCE;
                asn1Encodables = new ASN1Encodable[]{keyEncryptionAlgorithm, derNull};
                DERSequence keyEncryptionAlgorithmsSequence = new DERSequence(asn1Encodables);
                byte[] encryptedKeybytes = (byte[])recipientInfoMap.get("encryptedKey");
                DEROctetString encryptedKeyoOctetString = new DEROctetString(encryptedKeybytes);
                asn1Encodables = new ASN1Encodable[]{recipientInfoVersion, issuerInfo, keyEncryptionAlgorithmsSequence, encryptedKeyoOctetString};
                DERSequence recipientInfossSequence = new DERSequence(asn1Encodables);
                recipientInfossSequences[i] = recipientInfossSequence;
            }

            DERSet recipientInfossSet = new DERSet(recipientInfossSequences);
            return recipientInfossSet;
        }
    }

    private DERSequence MakeEncryptedContentInfo(byte[] encryptData) throws Exception {
        try {
            ASN1ObjectIdentifier encryptedContentInfocontentTypeObjectIdentifier = new ASN1ObjectIdentifier(this.encryptedContentInfocontentType);
            ASN1ObjectIdentifier contentEncryptionAlgorithmObjectIdentifier = new ASN1ObjectIdentifier(this.contentEncryptionAlgorithm);
            DERNull derNull = DERNull.INSTANCE;
            ASN1Encodable[] asn1Encodables = new ASN1Encodable[]{contentEncryptionAlgorithmObjectIdentifier, derNull};
            DERSequence contentEncryptionAlgorithmSequence = new DERSequence(asn1Encodables);
            DEROctetString encryptDataoOctetString = new DEROctetString(encryptData);
            asn1Encodables = new ASN1Encodable[]{encryptedContentInfocontentTypeObjectIdentifier, contentEncryptionAlgorithmSequence, encryptDataoOctetString};
            DERSequence encryptedContentInfoseqSequence = new DERSequence(asn1Encodables);
            return encryptedContentInfoseqSequence;
        } catch (Exception var9) {
            throw new Exception("MakeEncryptedContentInfo error:" + var9.getMessage());
        }
    }

    public byte[] openPKCS7ENC(byte[] keyFile, String encString, Cipher cipher) throws Exception {
        try {
            byte[] encbytes = Base64.decode(encString);
            ASN1InputStream asn1InputStream = new ASN1InputStream(encbytes);
            ASN1Sequence asn1Sequence = (ASN1Sequence)asn1InputStream.readObject();
            byte[] encSessionKey = ((ASN1OctetString)((ASN1Sequence)((ASN1Set)((ASN1Sequence)asn1Sequence.getObjectAt(1)).getObjectAt(1)).getObjectAt(0)).getObjectAt(3)).getOctets();
            Envelope envelope = new Envelope();
            byte[] sessionKey = envelope.open_SessionKey(encSessionKey, keyFile);
            byte[] encOrginal = ((ASN1OctetString)((ASN1Sequence)((ASN1Sequence)asn1Sequence.getObjectAt(1)).getObjectAt(2)).getObjectAt(2)).getOctets();
            byte[] orginal = envelope.open_Orginal(sessionKey, encOrginal, cipher);
            return orginal;
        } catch (Exception var12) {
            throw new Exception("openPKCS7ENC error:" + var12.getMessage());
        }
    }

    private byte[] hexStringToBytes(String hexString) {
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

    private byte charToByte(char c) {
        return (byte)"0123456789ABCDEF".indexOf(c);
    }

    public String byteToArray(byte[] data) {
        String result = "";

        for(int i = 0; i < data.length; ++i) {
            result = result + Integer.toHexString(data[i] & 255 | 256).toUpperCase().substring(1, 3);
        }

        return result;
    }
}