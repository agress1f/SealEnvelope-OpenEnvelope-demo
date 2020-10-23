package server;

import java.lang.reflect.Method;

public class Base64 {
/*
* String base64Str
* 为传入的字符串
* */
    public static String reverseBase64Data(String base64Str){
        try {
            byte[] tdata = new byte[0];
            tdata = decodeBase64(base64Str);
            byte tmp[] = new byte[tdata.length];
            for (int i = 0; i < tdata.length; i++) {
                tmp[i] = tdata[tdata.length - i - 1];
            }
            return  encodeBase64(tmp);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    //编码
    public static String encodeBase64(byte[]input) throws Exception {
        Class clazz= Class.forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");
        Method mainMethod= clazz.getMethod("encode", byte[].class);
        mainMethod.setAccessible(true);
        Object retObj=mainMethod.invoke(null, new Object[]{input});
        return (String)retObj;
    }

    //译码
    public static byte[] decodeBase64(String input) throws Exception {
        Class clazz= Class.forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");
        Method mainMethod= clazz.getMethod("decode", String.class);
        mainMethod.setAccessible(true);
        Object retObj=mainMethod.invoke(null, input);
        return (byte[])retObj;
    }

}
