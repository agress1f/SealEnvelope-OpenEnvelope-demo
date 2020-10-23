package server;

//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;

public class Util {
    private static final char[] DIGITS_LOWER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final char[] DIGITS_UPPER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public Util() {
    }

    public static byte[] intToBytes(int num) {
        byte[] bytes = new byte[]{(byte)(255 & num >> 0), (byte)(255 & num >> 8), (byte)(255 & num >> 16), (byte)(255 & num >> 24)};
        return bytes;
    }

    public static int byteToInt(byte[] bytes) {
        int num = 0;
        int temp = (255 & bytes[0]) << 0;
        num = num | temp;
        temp = (255 & bytes[1]) << 8;
        num |= temp;
        temp = (255 & bytes[2]) << 16;
        num |= temp;
        temp = (255 & bytes[3]) << 24;
        num |= temp;
        return num;
    }

    public static byte[] longToBytes(long num) {
        byte[] bytes = new byte[8];

        for(int i = 0; i < 8; ++i) {
            bytes[i] = (byte)((int)(255L & num >> i * 8));
        }

        return bytes;
    }

    public static byte[] byteConvert32Bytes(BigInteger n) {
        byte[] tmpd = (byte[])null;
        if (n == null) {
            return null;
        } else {
            if (n.toByteArray().length == 33) {
                tmpd = new byte[32];
                System.arraycopy(n.toByteArray(), 1, tmpd, 0, 32);
            } else if (n.toByteArray().length == 32) {
                tmpd = n.toByteArray();
            } else {
                tmpd = new byte[32];

                for(int i = 0; i < 32 - n.toByteArray().length; ++i) {
                    tmpd[i] = 0;
                }

                System.arraycopy(n.toByteArray(), 0, tmpd, 32 - n.toByteArray().length, n.toByteArray().length);
            }

            return tmpd;
        }
    }

    public static BigInteger byteConvertInteger(byte[] b) {
        if (b[0] < 0) {
            byte[] temp = new byte[b.length + 1];
            temp[0] = 0;
            System.arraycopy(b, 0, temp, 1, b.length);
            return new BigInteger(temp);
        } else {
            return new BigInteger(b);
        }
    }

    public static String getHexString(byte[] bytes) {
        return getHexString(bytes, true);
    }

    public static String getHexString(byte[] bytes, boolean upperCase) {
        String ret = "";

        for(int i = 0; i < bytes.length; ++i) {
            ret = ret + Integer.toString((bytes[i] & 255) + 256, 16).substring(1);
        }

        return upperCase ? ret.toUpperCase() : ret;
    }

    public static void printHexString(byte[] bytes) {
        for(int i = 0; i < bytes.length; ++i) {
            String hex = Integer.toHexString(bytes[i] & 255);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }

            System.out.print("0x" + hex.toUpperCase() + ",");
        }

        System.out.println("");
    }

    public static String bytesToHexString(byte[] src){
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString != null && !hexString.equals("")) {
            hexString = hexString.toUpperCase();
            int length = hexString.length() / 2;
            char[] hexChars = hexString.toCharArray();
            byte[] d = new byte[length];

            for(int i = 0; i < length; ++i) {
                int pos = i * 2;
                d[i] = (byte)(charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
            }

            return d;
        } else {
            return null;
        }
    }

    public static byte charToByte(char c) {
        return (byte)"0123456789ABCDEF".indexOf(c);
    }

    public static char[] encodeHex(byte[] data) {
        return encodeHex(data, true);
    }

    public static char[] encodeHex(byte[] data, boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    protected static char[] encodeHex(byte[] data, char[] toDigits) {
        int l = data.length;
        char[] out = new char[l << 1];
        int i = 0;

        for(int var5 = 0; i < l; ++i) {
            out[var5++] = toDigits[(240 & data[i]) >>> 4];
            out[var5++] = toDigits[15 & data[i]];
        }

        return out;
    }

    public static String encodeHexString(byte[] data) {
        return encodeHexString(data, true);
    }

    public static String encodeHexString(byte[] data, boolean toLowerCase) {
        return encodeHexString(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    protected static String encodeHexString(byte[] data, char[] toDigits) {
        return new String(encodeHex(data, toDigits));
    }

    public static byte[] decodeHex(char[] data) {
        int len = data.length;
        if ((len & 1) != 0) {
            throw new RuntimeException("Odd number of characters.");
        } else {
            byte[] out = new byte[len >> 1];
            int i = 0;

            for(int j = 0; j < len; ++i) {
                int f = toDigit(data[j], j) << 4;
                ++j;
                f |= toDigit(data[j], j);
                ++j;
                out[i] = (byte)(f & 255);
            }

            return out;
        }
    }

    protected static int toDigit(char ch, int index) {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new RuntimeException("Illegal hexadecimal character " + ch + " at index " + index);
        } else {
            return digit;
        }
    }

    public static String StringToAsciiString(String content) {
        String result = "";
        int max = content.length();

        for(int i = 0; i < max; ++i) {
            char c = content.charAt(i);
            String b = Integer.toHexString(c);
            result = result + b;
        }

        return result;
    }

    public static String hexStringToString(String hexString, int encodeType) {
        String result = "";
        int max = hexString.length() / encodeType;

        for(int i = 0; i < max; ++i) {
            char c = (char)hexStringToAlgorism(hexString.substring(i * encodeType, (i + 1) * encodeType));
            result = result + c;
        }

        return result;
    }

    public static int hexStringToAlgorism(String hex) {
        hex = hex.toUpperCase();
        int max = hex.length();
        int result = 0;

        for(int i = max; i > 0; --i) {
            char c = hex.charAt(i - 1);
            //int algorism = false;
            int algorism;
            if (c >= '0' && c <= '9') {
                algorism = c - 48;
            } else {
                algorism = c - 55;
            }

            result = (int)((double)result + Math.pow(16.0D, (double)(max - i)) * (double)algorism);
        }

        return result;
    }

    public static String hexStringToBinary(String hex) {
        hex = hex.toUpperCase();
        String result = "";
        int max = hex.length();

        for(int i = 0; i < max; ++i) {
            char c = hex.charAt(i);
            switch(c) {
                case '0':
                    result = result + "0000";
                    break;
                case '1':
                    result = result + "0001";
                    break;
                case '2':
                    result = result + "0010";
                    break;
                case '3':
                    result = result + "0011";
                    break;
                case '4':
                    result = result + "0100";
                    break;
                case '5':
                    result = result + "0101";
                    break;
                case '6':
                    result = result + "0110";
                    break;
                case '7':
                    result = result + "0111";
                    break;
                case '8':
                    result = result + "1000";
                    break;
                case '9':
                    result = result + "1001";
                case ':':
                case ';':
                case '<':
                case '=':
                case '>':
                case '?':
                case '@':
                default:
                    break;
                case 'A':
                    result = result + "1010";
                    break;
                case 'B':
                    result = result + "1011";
                    break;
                case 'C':
                    result = result + "1100";
                    break;
                case 'D':
                    result = result + "1101";
                    break;
                case 'E':
                    result = result + "1110";
                    break;
                case 'F':
                    result = result + "1111";
            }
        }

        return result;
    }

    public static String AsciiStringToString(String content) {
        String result = "";
        int length = content.length() / 2;

        for(int i = 0; i < length; ++i) {
            String c = content.substring(i * 2, i * 2 + 2);
            int a = hexStringToAlgorism(c);
            char b = (char)a;
            String d = String.valueOf(b);
            result = result + d;
        }

        return result;
    }

    public static String algorismToHexString(int algorism, int maxLength) {
        String result = "";
        result = Integer.toHexString(algorism);
        if (result.length() % 2 == 1) {
            result = "0" + result;
        }

        return patchHexString(result.toUpperCase(), maxLength);
    }

    public static String byteToString(byte[] bytearray) {
        String result = "";
        int length = bytearray.length;

        for(int i = 0; i < length; ++i) {
            char temp = (char)bytearray[i];
            result = result + temp;
        }

        return result;
    }

    public static int binaryToAlgorism(String binary) {
        int max = binary.length();
        int result = 0;

        for(int i = max; i > 0; --i) {
            char c = binary.charAt(i - 1);
            int algorism = c - 48;
            result = (int)((double)result + Math.pow(2.0D, (double)(max - i)) * (double)algorism);
        }

        return result;
    }

    public static String algorismToHEXString(int algorism) {
        String result = "";
        result = Integer.toHexString(algorism);
        if (result.length() % 2 == 1) {
            result = "0" + result;
        }

        result = result.toUpperCase();
        return result;
    }

    public static String patchHexString(String str, int maxLength) {
        String temp = "";

        for(int i = 0; i < maxLength - str.length(); ++i) {
            temp = "0" + temp;
        }

        str = (temp + str).substring(0, maxLength);
        return str;
    }

    public static int parseToInt(String s, int defaultInt, int radix) {
        boolean var3 = false;

        int i;
        try {
            i = Integer.parseInt(s, radix);
        } catch (NumberFormatException var5) {
            i = defaultInt;
        }

        return i;
    }

    public static int parseToInt(String s, int defaultInt) {
        boolean var2 = false;

        int i;
        try {
            i = Integer.parseInt(s);
        } catch (NumberFormatException var4) {
            i = defaultInt;
        }

        return i;
    }

    public static byte[] hexToByte(String hex) throws IllegalArgumentException {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException();
        } else {
            char[] arr = hex.toCharArray();
            byte[] b = new byte[hex.length() / 2];
            int i = 0;
            int j = 0;

            for(int l = hex.length(); i < l; ++j) {
                String swap = "" + arr[i++] + arr[i];
                int byteint = Integer.parseInt(swap, 16) & 255;
                b[j] = (new Integer(byteint)).byteValue();
                ++i;
            }

            return b;
        }
    }

    public static String byteToHex(byte[] b) {
        if (b == null) {
            throw new IllegalArgumentException("Argument b ( byte array ) is null! ");
        } else {
            String hs = "";
            String stmp = "";

            for(int n = 0; n < b.length; ++n) {
                stmp = Integer.toHexString(b[n] & 255);
                if (stmp.length() == 1) {
                    hs = hs + "0" + stmp;
                } else {
                    hs = hs + stmp;
                }
            }

            return hs.toUpperCase();
        }
    }

    public static byte[] subByte(byte[] input, int startIndex, int length) {
        byte[] bt = new byte[length];

        for(int i = 0; i < length; ++i) {
            bt[i] = input[i + startIndex];
        }

        return bt;
    }

    public static void reverse(byte[] array, int startIndexInclusive, int endIndexExclusive) {
        if(array != null) {
            int i = startIndexInclusive < 0?0:startIndexInclusive;

            for(int j = Math.min(array.length, endIndexExclusive) - 1; j > i; ++i) {
                byte tmp = array[j];
                array[j] = array[i];
                array[i] = tmp;
                --j;
            }

        }
    }

    public static void reverse(byte[] array) {
        if(array != null) {
            reverse((byte[])array, 0, array.length);
        }
    }

    public static void write(byte[] bt, String filepath) {
        FileOutputStream fout = null;

        try {
            fout = new FileOutputStream(filepath);
            fout.write(bt);
            return;
        } catch (Exception var68) {
            System.out.println("关闭文件失败: " + var68.toString());
        } finally {
            if(fout != null) {
                try {
                    fout.flush();
                } catch (Exception var66) {
                    ;
                } finally {
                    try {
                        fout.close();
                    } catch (Exception var65) {
                        System.out.println("关闭文件失败: " + var65.toString());
                    }

                }
            }

        }

    }

    public static byte[] read(String filepath) {
        ByteArrayOutputStream b_out = null;
        FileInputStream fin = null;
        byte[] buf = new byte[1024];
        byte[] b_arr = new byte[0];

        byte[] var9;
        try {
            b_out = new ByteArrayOutputStream();
            fin = new FileInputStream(filepath);

            int readSize;
            while((readSize = fin.read(buf, 0, buf.length)) != -1) {
                b_out.write(buf, 0, readSize);
                b_out.flush();
            }

            b_arr = b_out.toByteArray();
            return b_arr;
        } catch (Exception var21) {
            var9 = new byte[0];
        } finally {
            if(b_out != null) {
                try {
                    b_out.close();
                } catch (Exception var20) {
                    System.out.println("关闭ByteArrayOutputStream异常: " + var20.toString());
                }
            }

            if(fin != null) {
                try {
                    fin.close();
                } catch (Exception var19) {
                    System.out.println("关闭文件异常: " + var19.toString());
                }
            }

        }

        return var9;
    }

    public static boolean paramCheck(Object[] obj) {
        boolean result = true;

        for(int i = 0; i < obj.length; ++i) {
            if (String.class.isInstance(obj[i])) {
                if ("".equals((String)obj[i]) || obj[i] == null) {
                    result = false;
                }
            } else if (obj[i] instanceof byte[]) {
                if (obj[i] == null || ((byte[])obj[i]).length == 0) {
                    result = false;
                }
            } else if (obj[i] instanceof Integer) {
                if (obj[i] == null) {
                    result = false;
                }
            } else {
                result = false;
            }
        }

        return result;
    }
}
