package burp.utils;


import burp.IBurpExtenderCallbacks;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Utils {
    public static IBurpExtenderCallbacks Callback;
    private static MessageDigest md;
    private static Random rand = new Random();

    public static int GetRandomNumber(int min, int max) {
        return rand.nextInt(max - min + 1) + min;
    }

    public static Boolean GetRandomBoolean() {
        return rand.nextInt(100) > 50;
    }

    public static String GetRandomString(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = rand.nextInt(str.length() - 1);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    public static byte[] byteMerger(byte[] bt1, byte[] bt2) {
        byte[] bt3 = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }

    public static String getCurrentTimeMillis() {
        return String.valueOf(System.currentTimeMillis());
    }

    public static byte[] MD5(byte[] src) {
        if (md == null) {
            try {
                md = MessageDigest.getInstance("md5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("MD5 not found!");
            }
        }
        byte[] secretBytes = null;
        secretBytes = md.digest(src);
        return secretBytes;
    }
}
