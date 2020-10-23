
package psic;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import server.ClientConf;
import server.GetEncPvk;
import server.JPkcs7;
import server.Util;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
/**
 * Created with IntelliJ IDEA.
 * User: GZH
 * Date: 2020/10/12
 * Time: 16:39
 * Description: No Description
 */

public class SHAWApp {
    //֤������
    private String ksType = "PKCS7";
    private CertificateFactory cf = null;
    private static final Map algMap = new HashMap();

    public SHAWApp() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            this.cf = CertificateFactory.getInstance("X.509", "BC");
            algMap.put(32772, "sha1withrsa");
            algMap.put(32780, "sha256withrsa");
            algMap.put(32771, "md5withrsa");
            System.out.println("SHAWApp��ʼ���ɹ�");
        } catch (Exception var) {
            System.out.println("SHAWApp��ʼ���쳣��" + var.getMessage());
        }

    }

    /**
     * ��������ǩ��
     * @param srcMsg Դ��Ϣ
     * @param charSet �ַ�����
     * @param certPath ֤��·��
     * @param certPwd ֤������
     * @return
     */
    public byte[] signMessage(String srcMsg, String charSet, String certPath, String certPwd){
        String priKeyName = null;
        //֤������תchar����
        char[] passphrase = certPwd.toCharArray();
        try{
            Provider provider = new BouncyCastleProvider();
            //���BouncyCastleProvider��Ϊ��ȫ�ṩ
            Security.addProvider(provider);

            // ����֤��
            KeyStore ks = KeyStore.getInstance(ksType);//KeyStore����Կ��ĳ����࣬���ڹ�����Կ��֤��
            ks.load(new FileInputStream(certPath), passphrase);

            //����������ϲ�Ϊ�գ��ƶ�����һ��Ԫ��
            if (ks.aliases().hasMoreElements()) {
                priKeyName = ks.aliases().nextElement();
            }

            Certificate cert = (Certificate) ks.getCertificate(priKeyName);

            // ��ȡ˽Կ
            PrivateKey prikey = (PrivateKey) ks.getKey(priKeyName, passphrase);
            //X509֤�������,��ӵ�֤���б���
            X509Certificate cerx509 = (X509Certificate) cert;
            List<Certificate> certList = new ArrayList<Certificate>();
            certList.add(cerx509);

            CMSTypedData msg = (CMSTypedData) new CMSProcessableByteArray(
                    srcMsg.getBytes(charSet));

            Store certs = new JcaCertStore(certList);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner sha1Signer = new JcaContentSignerBuilder(
                    "SHA1withRSA").setProvider("BC").build(prikey);

            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                            .build()).build(sha1Signer, cerx509));

            gen.addCertificates(certs);

            CMSSignedData sigData = gen.generate(msg, true);
            //����ǩ����byte����
            return Base64.encode(sigData.getEncoded());

        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ��֤����ǩ��
     * @param signedData
     * @return
     */
    public boolean signedDataVerify(byte[] signedData) {
        boolean verifyRet = true;
        try {
            // �½�PKCS#7ǩ�����ݴ������
            CMSSignedData sign = new CMSSignedData(signedData);

            // ���BouncyCastle��Ϊ��ȫ�ṩ
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // ���֤����Ϣ
            Store certs = sign.getCertificates();

            // ���ǩ������Ϣ
            SignerInformationStore signers = sign.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();

            // ���ж��ǩ������Ϣʱ��Ҫȫ����֤
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();

                // ֤����
                Collection certCollection = certs.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder) certIt
                        .next();

                // ��֤����ǩ��
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider("BC").build(cert))) {
                    verifyRet = true;
                } else {
                    verifyRet = false;
                }
            }

        } catch (Exception e) {
            verifyRet = false;
            e.printStackTrace();
            System.out.println("��֤����ǩ��ʧ��");
        }
        return verifyRet;
    }

    /**
     * ��ȡ֤��
     * @param keyLabel ��Կ��ǩ
     * @param certType �ַ�����
     * @return  ����֤������
     */

    public String ShawGetCert(String keyLabel, int certType) {
        String result = "";
        Object[] objs = new Object[]{certType};
        if (!Util.paramCheck(objs)) {
            System.out.println("��Ҫ����β���Ϊ�ջ�null");
            return result;
        } else {
            String certPath = "";
            String certTypePath = "";
            try {
                ClientConf conf = new ClientConf();
                //��ȡ���õĵ�ַ
                String configPath = conf.CONFIG_PATH;
                //���keyLabelΪ�գ���ȡkeyLabel��ǩ�µ�����
                if (keyLabel == null || "".equals(keyLabel)) {
                    keyLabel = conf.getParamValue("KeyLabel");
                }
                certPath = configPath.substring(0, configPath.indexOf("Client.conf")) + keyLabel + System.getProperty("file.separator");
            } catch (Exception var) {
                System.out.println("��ȡ�����ļ�ʧ�ܣ�" + var.getMessage());
                return result;
            }
            try {
                String certTypeString = "";
                if (certType == 1) {
                    certTypeString = "-CertEx.cer";
                } else {
                    if (certType != 2) {
                        throw new Exception("��������");
                    }
                    certTypeString = "-CertSig.cer";
                }
                //֤�����͵ĵ�ַ��֤���ַ/keyLabel/֤������
                certTypePath = certPath + keyLabel + certTypeString;
                FileInputStream fileInputStream = new FileInputStream(certTypePath);
                byte[] b = new byte[fileInputStream.available()];
                fileInputStream.read(b);
                fileInputStream.close();
                result = (new BASE64Encoder()).encode(b);
            } catch (Exception var) {
                System.out.println("��ȡ֤��ʧ�ܣ�" + var.getMessage());
            }
            return result;
        }
    }

    /**
     * ��ȡ֤��·��
     * @param keyLabel ��Կ��ǩ
     * @param certType �ַ�����
     * @return  ����֤��·��
     */
    public String getCertPath(String keyLabel, int certType){
        Object[] objs = new Object[]{certType};
        String certPath = "";
        String certTypePath = "";
        if (!Util.paramCheck(objs)) {
            System.out.println("��Ҫ����β���Ϊ�ջ�null");
            return certPath;
        } else {

            try {
                ClientConf conf = new ClientConf();
                //��ȡ���õĵ�ַ
                String configPath = conf.CONFIG_PATH;
                //���keyLabelΪ�գ���ȡkeyLabel��ǩ�µ�����
                if (keyLabel == null || "".equals(keyLabel)) {
                    keyLabel = conf.getParamValue("KeyLabel");
                }
                certPath = configPath.substring(0, configPath.indexOf("Client.conf")) + keyLabel + System.getProperty("file.separator");
            } catch (Exception var) {
                System.out.println("��ȡ�����ļ�ʧ�ܣ�" + var.getMessage());
                return certPath;
            }
        }
        return certPath;
    }

    /**
     * �����ŷ����
     * @param i_encCert  ֤��
     * @param i_symmAlgo �����㷨
     * @param i_inData  ԭʼ����
     * @return  ���������ŷ���ܺ������
     */

    public String ShawSealEnvelope(String i_encCert, int i_symmAlgo, byte[] i_inData) {
        String base64Res = "";
        Object[] objs = new Object[]{i_encCert, i_symmAlgo, i_inData};
        if (!Util.paramCheck(objs)) {
            System.out.println("��Ҫ����β���Ϊ�ջ�null");
            return base64Res;
        } else {
            try {
                //��������base64����
                byte[] certBytes = org.bouncycastle.util.encoders.Base64.decode(i_encCert);
                InputStream inputStream = new ByteArrayInputStream(certBytes);
                X509Certificate cert = (X509Certificate)this.cf.generateCertificate(inputStream);
                X509Certificate[] certs = new X509Certificate[]{cert};
                JPkcs7 jPkcs7 = new JPkcs7();
                //cipher����ʹ��֮ǰ����Ҫ��ʼ��������������("����ģʽ���߽���ģʽ","�ܳ�","����")
                Cipher sessionKeyCipher = Cipher.getInstance("RSA/None/PKCS1Padding");
                //?
                Cipher sealOrignalChipher = Cipher.getInstance("DESede");
                //make
                byte[] resBytes = jPkcs7.makePKCS7ENC(certs, i_inData, i_symmAlgo, sessionKeyCipher, sealOrignalChipher);
                base64Res = new String(org.bouncycastle.util.encoders.Base64.encode(resBytes));
                //String����
                return base64Res;
            } catch (Exception var) {
                System.out.println("�ŷ����ʧ�ܣ�" + var.getMessage());
                return base64Res;
            }
        }
    }

    /**
     * �����ŷ����
     * @param keyLabel  ��Կ��ǩ
     * @param keyPasswd ��Կ
     * @param i_inData  �����ŷ�
     * @return  ���������ŷ���ܺ������
     */

    public byte[] ShawOpenEnvelope(String keyLabel, String keyPasswd, String i_inData) {
        byte[] orginal = (byte[])null;
        //ԭʼ�ŷ�
        Object[] objs = new Object[]{i_inData};
        if (!Util.paramCheck(objs)) {
            System.out.println("��Ҫ����β���Ϊ�ջ�null");
            return orginal;
        } else {
            try {
                String certAndKeyPath = "";
                String keyPath = "";

                try {
                    ClientConf conf = new ClientConf();
                    String configPath = conf.CONFIG_PATH;
                    if (keyLabel == null || "".equals(keyLabel)) {
                        keyLabel = conf.getParamValue("KeyLabel");
                    }
                    //·����ȡ
                    certAndKeyPath = configPath.substring(0, configPath.indexOf("Client.conf")) + keyLabel + System.getProperty("file.separator");
                    keyPath = certAndKeyPath + "pvkExh";
                } catch (Exception var) {
                    System.out.println("��ȡ�����ļ�ʧ�ܣ�" + var.getMessage());
                    return orginal;
                }
                FileInputStream fileInputStream = new FileInputStream(keyPath);
                //��ȡ
                byte[] keyFile = new byte[fileInputStream.available()];
                fileInputStream.read(keyFile);
                fileInputStream.close();
                GetEncPvk getEncPvk = new GetEncPvk();
                //��ȡ˽Կ
                if (!"".equals(keyPasswd) && keyPasswd != null) {
                    keyFile = getEncPvk.getKey(keyPasswd, keyFile);
                }
                JPkcs7 jPkcs7 = new JPkcs7();
                //�����׼���
                Cipher openlOrignalChipher = Cipher.getInstance("DESede");
                //��ȡԭʼ��Ϣ
                orginal = jPkcs7.openPKCS7ENC(keyFile, i_inData, openlOrignalChipher);
                return orginal;
            } catch (Exception var) {
                System.out.println("�ŷ����ʧ�ܣ�" + var.getMessage());
                return orginal;
            }
        }
    }

    //����
    public static void main(String[] args) throws Exception {

        String keyLabel = "Test1024";
        SHAWApp shawApp = new SHAWApp();
        String certS = shawApp.ShawGetCert(keyLabel, 2);
        String certPath = shawApp.getCertPath(keyLabel,2);
        System.out.println("����֤����Ϣ��" + certS);

        byte[] sign = shawApp.signMessage(new String("123"),"utf8",certPath,"");
        String signMessage = sign.toString();
        System.out.println("����ǩ������"+signMessage);

        String encryption = shawApp.ShawSealEnvelope(certS, 26625,sign);
        System.out.println("�����ŷ���ܽ��:" + encryption);

        byte[] decryption = shawApp.ShawOpenEnvelope(keyLabel, "", encryption);
        String result12 = new String(decryption);
        System.out.println("�����ŷ���ܽ��:" + result12);

        boolean result = shawApp.signedDataVerify(decryption);
        System.out.println("��֤����ǩ�������"+result);

    }
}
