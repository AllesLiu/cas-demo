package com.dh.core.utils;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;

/**
 * MD5自定义加盐加密工具类
 * @author: Alles
 * @Date: 2020-06-01 16:45
 * @version: V1.0
 */
public class MD5Util implements PasswordEncoder {
    /**
     * Title: MD5加密 生成32位md5码
     * @author Alles
     * @param inStr
     * @return 返回32位md5码
     * @throws Exception
     */
    public static String md5Encode(String inStr) throws Exception {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }
        byte[] byteArray = inStr.getBytes("UTF-8");
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }
    /**
     * Title: MD5加密
     * @author Alles
     * @param inStr
     * @return
     */
    public static String string2MD5(String inStr) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }
        char[] charArray = inStr.toCharArray();
        byte[] byteArray = new byte[charArray.length];

        for (int i = 0; i < charArray.length; i++)
            byteArray[i] = (byte) charArray[i];
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16)
                hexValue.append("0");
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();

    }

    /**
     * Title: 加密解密算法 执行一次加密，两次解密
     * @author Alles
     * @param inStr
     * @return
     */
    public static String convertMD5(String inStr) {

        char[] a = inStr.toCharArray();
        for (int i = 0; i < a.length; i++) {
            a[i] = (char) (a[i] ^ 't');
        }
        String s = new String(a);
        return s;

    }
    public static String md5Decode(String str) {
        return convertMD5(convertMD5(str));
    }

    public static void main(String[] args) {//e10adc3949ba59abbe56e057f20f883e
        String s = new String("123456");
        System.out.println(md5Decode("a6aeb3ffa55fc7d664406af9c3bd0f1b"));
        System.out.println("原始：" + s);
        System.out.println("MD5后：" + string2MD5(s));
        System.out.println("加密的：" + convertMD5(s));
        System.out.println("解密的：" + convertMD5(convertMD5(s)));
    }

    /**
     * 对输入的密码加密过程
     */
    @Override
    public String encode(CharSequence inputPwd) {
        System.out.println("inputPwd===" + inputPwd);
        System.out.println("string2MD5==" + string2MD5(inputPwd.toString()));
        return string2MD5(inputPwd.toString());
    }

    /**
     * 密码校验过程
     */
    @Override
    public boolean matches(CharSequence inputPwd, String dbPwd) {
        // 判断密码是否存在
        if (inputPwd == null) {
            return false;
        }
        System.out.println("inputPwd==" + inputPwd + "  " + "dbPwd==" + dbPwd);
        if(dbPwd.contentEquals(this.encode(inputPwd))){
            return true;
        }
        return false;
    }
}
