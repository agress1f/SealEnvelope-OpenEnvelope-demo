
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
    //证书类型
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
            System.out.println("SHAWApp初始化成功");
        } catch (Exception var) {
            System.out.println("SHAWApp初始化异常：" + var.getMessage());
        }

    }

    /**
     * 生成数字签名
     * @param srcMsg 源信息
     * @param charSet 字符编码
     * @param certPath 证书路径
     * @param certPwd 证书密码
     * @return
     */
    public byte[] signMessage(String srcMsg, String charSet, String certPath, String certPwd){
        String priKeyName = null;
        //证书密码转char数组
        char[] passphrase = certPwd.toCharArray();
        try{
            Provider provider = new BouncyCastleProvider();
            //添加BouncyCastleProvider作为安全提供
            Security.addProvider(provider);

            // 加载证书
            KeyStore ks = KeyStore.getInstance(ksType);//KeyStore是秘钥库的抽象类，用于管理秘钥和证书
            ks.load(new FileInputStream(certPath), passphrase);

            //如果别名集合不为空，移动到下一个元素
            if (ks.aliases().hasMoreElements()) {
                priKeyName = ks.aliases().nextElement();
            }

            Certificate cert = (Certificate) ks.getCertificate(priKeyName);

            // 获取私钥
            PrivateKey prikey = (PrivateKey) ks.getKey(priKeyName, passphrase);
            //X509证书抽象类,添加到证书列表中
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
            //返回签名：byte数组
            return Base64.encode(sigData.getEncoded());

        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 验证数字签名
     * @param signedData
     * @return
     */
    public boolean signedDataVerify(byte[] signedData) {
        boolean verifyRet = true;
        try {
            // 新建PKCS#7签名数据处理对象
            CMSSignedData sign = new CMSSignedData(signedData);

            // 添加BouncyCastle作为安全提供
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // 获得证书信息
            Store certs = sign.getCertificates();

            // 获得签名者信息
            SignerInformationStore signers = sign.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();

            // 当有多个签名者信息时需要全部验证
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();

                // 证书链
                Collection certCollection = certs.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder) certIt
                        .next();

                // 验证数字签名
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
            System.out.println("验证数字签名失败");
        }
        return verifyRet;
    }

    /**
     * 获取证书
     * @param keyLabel 密钥标签
     * @param certType 字符编码
     * @return  返回证书内容
     */

    public String ShawGetCert(String keyLabel, int certType) {
        String result = "";
        Object[] objs = new Object[]{certType};
        if (!Util.paramCheck(objs)) {
            System.out.println("必要的入参不能为空或null");
            return result;
        } else {
            String certPath = "";
            String certTypePath = "";
            try {
                ClientConf conf = new ClientConf();
                //获取配置的地址
                String configPath = conf.CONFIG_PATH;
                //如果keyLabel为空，获取keyLabel标签下的内容
                if (keyLabel == null || "".equals(keyLabel)) {
                    keyLabel = conf.getParamValue("KeyLabel");
                }
                certPath = configPath.substring(0, configPath.indexOf("Client.conf")) + keyLabel + System.getProperty("file.separator");
            } catch (Exception var) {
                System.out.println("读取配置文件失败：" + var.getMessage());
                return result;
            }
            try {
                String certTypeString = "";
                if (certType == 1) {
                    certTypeString = "-CertEx.cer";
                } else {
                    if (certType != 2) {
                        throw new Exception("参数有误");
                    }
                    certTypeString = "-CertSig.cer";
                }
                //证书类型的地址：证书地址/keyLabel/证书类型
                certTypePath = certPath + keyLabel + certTypeString;
                FileInputStream fileInputStream = new FileInputStream(certTypePath);
                byte[] b = new byte[fileInputStream.available()];
                fileInputStream.read(b);
                fileInputStream.close();
                result = (new BASE64Encoder()).encode(b);
            } catch (Exception var) {
                System.out.println("获取证书失败：" + var.getMessage());
            }
            return result;
        }
    }

    /**
     * 获取证书路径
     * @param keyLabel 密钥标签
     * @param certType 字符编码
     * @return  返回证书路径
     */
    public String getCertPath(String keyLabel, int certType){
        Object[] objs = new Object[]{certType};
        String certPath = "";
        String certTypePath = "";
        if (!Util.paramCheck(objs)) {
            System.out.println("必要的入参不能为空或null");
            return certPath;
        } else {

            try {
                ClientConf conf = new ClientConf();
                //获取配置的地址
                String configPath = conf.CONFIG_PATH;
                //如果keyLabel为空，获取keyLabel标签下的内容
                if (keyLabel == null || "".equals(keyLabel)) {
                    keyLabel = conf.getParamValue("KeyLabel");
                }
                certPath = configPath.substring(0, configPath.indexOf("Client.conf")) + keyLabel + System.getProperty("file.separator");
            } catch (Exception var) {
                System.out.println("读取配置文件失败：" + var.getMessage());
                return certPath;
            }
        }
        return certPath;
    }

    /**
     * 数字信封加密
     * @param i_encCert  证书
     * @param i_symmAlgo 密码算法
     * @param i_inData  原始数据
     * @return  返回数字信封加密后的内容
     */

    public String ShawSealEnvelope(String i_encCert, int i_symmAlgo, byte[] i_inData) {
        String base64Res = "";
        Object[] objs = new Object[]{i_encCert, i_symmAlgo, i_inData};
        if (!Util.paramCheck(objs)) {
            System.out.println("必要的入参不能为空或null");
            return base64Res;
        } else {
            try {
                //参数进行base64解码
                byte[] certBytes = org.bouncycastle.util.encoders.Base64.decode(i_encCert);
                InputStream inputStream = new ByteArrayInputStream(certBytes);
                X509Certificate cert = (X509Certificate)this.cf.generateCertificate(inputStream);
                X509Certificate[] certs = new X509Certificate[]{cert};
                JPkcs7 jPkcs7 = new JPkcs7();
                //cipher对象使用之前还需要初始化，共三个参数("加密模式或者解密模式","密匙","向量")
                Cipher sessionKeyCipher = Cipher.getInstance("RSA/None/PKCS1Padding");
                //?
                Cipher sealOrignalChipher = Cipher.getInstance("DESede");
                //make
                byte[] resBytes = jPkcs7.makePKCS7ENC(certs, i_inData, i_symmAlgo, sessionKeyCipher, sealOrignalChipher);
                base64Res = new String(org.bouncycastle.util.encoders.Base64.encode(resBytes));
                //String类型
                return base64Res;
            } catch (Exception var) {
                System.out.println("信封加密失败：" + var.getMessage());
                return base64Res;
            }
        }
    }

    /**
     * 数字信封解密
     * @param keyLabel  密钥标签
     * @param keyPasswd 密钥
     * @param i_inData  数字信封
     * @return  返回数字信封解密后的内容
     */

    public byte[] ShawOpenEnvelope(String keyLabel, String keyPasswd, String i_inData) {
        byte[] orginal = (byte[])null;
        //原始信封
        Object[] objs = new Object[]{i_inData};
        if (!Util.paramCheck(objs)) {
            System.out.println("必要的入参不能为空或null");
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
                    //路径获取
                    certAndKeyPath = configPath.substring(0, configPath.indexOf("Client.conf")) + keyLabel + System.getProperty("file.separator");
                    keyPath = certAndKeyPath + "pvkExh";
                } catch (Exception var) {
                    System.out.println("读取配置文件失败：" + var.getMessage());
                    return orginal;
                }
                FileInputStream fileInputStream = new FileInputStream(keyPath);
                //读取
                byte[] keyFile = new byte[fileInputStream.available()];
                fileInputStream.read(keyFile);
                fileInputStream.close();
                GetEncPvk getEncPvk = new GetEncPvk();
                //获取私钥
                if (!"".equals(keyPasswd) && keyPasswd != null) {
                    keyFile = getEncPvk.getKey(keyPasswd, keyFile);
                }
                JPkcs7 jPkcs7 = new JPkcs7();
                //密码套件？
                Cipher openlOrignalChipher = Cipher.getInstance("DESede");
                //获取原始信息
                orginal = jPkcs7.openPKCS7ENC(keyFile, i_inData, openlOrignalChipher);
                return orginal;
            } catch (Exception var) {
                System.out.println("信封解密失败：" + var.getMessage());
                return orginal;
            }
        }
    }

    //测试
    public static void main(String[] args) throws Exception {

        String keyLabel = "Test1024";
        SHAWApp shawApp = new SHAWApp();
        String certS = shawApp.ShawGetCert(keyLabel, 2);
        String certPath = shawApp.getCertPath(keyLabel,2);
        System.out.println("加密证书信息：" + certS);

        byte[] sign = shawApp.signMessage(new String("123"),"utf8",certPath,"");
        String signMessage = sign.toString();
        System.out.println("数字签名内容"+signMessage);

        String encryption = shawApp.ShawSealEnvelope(certS, 26625,sign);
        System.out.println("数字信封加密结果:" + encryption);

        byte[] decryption = shawApp.ShawOpenEnvelope(keyLabel, "", encryption);
        String result12 = new String(decryption);
        System.out.println("数字信封解密结果:" + result12);

        boolean result = shawApp.signedDataVerify(decryption);
        System.out.println("验证数字签名结果："+result);

    }
}
