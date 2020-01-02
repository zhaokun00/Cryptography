import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import  java.util.*;

public class Cryptography {

    public static void byteAndString() {

        /*
        3、String(byte[] bytes, Charset charset)
          通过使用指定的 charset解码指定的 byte数组，构造一个新的 String

        4、byte[] getBytes(Charset charset)
          把JVM内存中unicode形式的String按encoding制定的编码，转成字节流
          使用给定的 charset 将此 String 编码到 byte 序列，并将结果存储到新的 byte 数组

//        byte bytes[] = new byte[] { 50, 0, -1, 28, -24 };
//
//        String string = new String(bytes,"UTF-8");
//
//        System.out.println(string);
//        byte[] ret = string.getBytes("utf-8");
//
//        for (int i = 0;i < ret.length;i++) {
//
//            System.out.println(ret[i]);
//        }

         */
    }

    /*测试DES对称加密算法*/
    public static void testdes() throws Exception {

        String key = "12345678"; //对称加密的秘钥
        String data = "1234"; //传输数据

        {
            String enData = TestDes.encrypt(key, data);

            System.out.println("加密后的数据:" + enData);

            String deData = TestDes.decrypt(key, enData);

            System.out.println("解密后的数据:" + deData);
        }

        {
            String iv = "12345678"; //用于分组模式的初始化向量
            String enData = TestDes.encrypt(key, data, iv);

            System.out.println("加密后的数据:" + enData);

            String deData = TestDes.decrypt(key, enData, iv);

            System.out.println("解密后的数据:" + deData);
        }

    }

    public static void test3des() throws Exception {

        //3DES密钥长度为24字节
        String key = "1234567887654321abcdefgi"; //对称加密的秘钥
        String data = "1234abcdefhasofhoiashfoisadhf"; //传输数据

        {
            String enData = TestDes.encrypt(key, data);

            System.out.println("加密后的数据:" + enData);

            String deData = TestDes.decrypt(key, enData);

            System.out.println("解密后的数据:" + deData);
        }

        {
            String iv = "12345678"; //用于分组模式的初始化向量
            String enData = TestDes.encrypt(key, data, iv);

            System.out.println("加密后的数据:" + enData);

            String deData = TestDes.decrypt(key, enData, iv);

            System.out.println("解密后的数据:" + deData);
        }

    }

    public static void testBase64() throws Exception {

        String data = "qianyang123";

        String en = Base64Code.encode(data);

        System.out.println("编码后数据:" + en);

        //String de = Base64Code.decode(en);

        String de = Base64Code.decode("cWlhbnlhbmcxMjMK");

        System.out.println("解码后数据:" + de);
    }

    public static void testRsa() throws Exception {


        RSA.genKeyPair();
        String data = "qianyang123";

        String en = RSA.encrypt(RSA.publicKeyString,data);

        System.out.println("编码后数据:" + en);

        String de = RSA.decrypt(RSA.privateKeyString,en);

        System.out.println("解码后数据:" + de);
    }

    public static void main(String args[]) throws Exception {

        System.out.println("Hello Cryptography");

        //testdes();
        //test3des();

        //testBase64();

        //testRsa();


    }

}

//对称加密算法............................................................
//DES加密类
class TestDes {

    private final static String CODE = "utf-8"; //定义编码
    private final static String CRYPTO = "DES"; //定义加密算法
    private final static String CRYPTOBLOCK = "DES/CBC/PKCS5Padding"; //加密算法/工作模式/填充方式,"DESede/ECB/PKCS5Padding"

    public static String encrypt(String key, String data) throws Exception {

        //生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTO);

        //用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

        byte[] bt = cipher.doFinal(data.getBytes(CODE));

        String str = new BASE64Encoder().encode(bt);

        return str;
    }

    public static String encrypt(String key, String data,String iv) throws Exception {

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTOBLOCK);

        IvParameterSpec v = new IvParameterSpec(iv.getBytes(CODE));
        AlgorithmParameterSpec paramSpec = v;

        //用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey,paramSpec);

        byte[] bt = cipher.doFinal(data.getBytes(CODE));

        String str = new BASE64Encoder().encode(bt);

        return str;
    }

    public static String decrypt(String key, String data) throws Exception {

        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(CRYPTO);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);

        byte[] bt = cipher.doFinal(buf);

        String str = new String(bt,CODE);

        return str;
    }

    public static String decrypt(String key, String data,String iv) throws Exception {

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTOBLOCK);

        IvParameterSpec v = new IvParameterSpec(iv.getBytes(CODE));
        AlgorithmParameterSpec paramSpec = v;

        //用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey,paramSpec);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);

        byte[] bt = cipher.doFinal(buf);

        String str = new String(bt,CODE);

        return str;
    }
}

//3DES加密类
class Test3Des {

    private final static String CODE = "utf-8"; //定义编码
//    private final static String CRYPTO = "DESede"; //定义加密算法
//    private final static String CRYPTOBLOCK = "DESede/CBC/PKCS5Padding"; //加密算法/工作模式/填充方式,"DESede/ECB/PKCS5Padding"
      private final static String CRYPTO = "AES"; //定义加密算法
      private final static String CRYPTOBLOCK = "AES/ECB/PKCS5Padding"; //加密算法/工作模式/填充方式,"DESede/ECB/PKCS5Padding"
    public static String encrypt(String key, String data) throws Exception {

        //生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTO);

        //用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

        byte[] bt = cipher.doFinal(data.getBytes(CODE));

        String str = new BASE64Encoder().encode(bt);

        return str;
    }

    public static String encrypt(String key, String data,String iv) throws Exception {

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTOBLOCK);

        IvParameterSpec v = new IvParameterSpec(iv.getBytes(CODE));
        AlgorithmParameterSpec paramSpec = v;

        //用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey,paramSpec);

        byte[] bt = cipher.doFinal(data.getBytes(CODE));

        String str = new BASE64Encoder().encode(bt);

        return str;
    }

    public static String decrypt(String key, String data) throws Exception {

        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(CRYPTO);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);

        byte[] bt = cipher.doFinal(buf);

        String str = new String(bt,CODE);

        return str;
    }

    public static String decrypt(String key, String data,String iv) throws Exception {

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTOBLOCK);

        IvParameterSpec v = new IvParameterSpec(iv.getBytes(CODE));
        AlgorithmParameterSpec paramSpec = v;

        //用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey,paramSpec);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);

        byte[] bt = cipher.doFinal(buf);

        String str = new String(bt,CODE);

        return str;
    }
}

//3DES加密类
class TestAes {

    private final static String CODE = "utf-8"; //定义编码
    private final static String CRYPTO = "AES"; //定义加密算法
    private final static String CRYPTOBLOCK = "AES/ECB/PKCS5Padding"; //加密算法/工作模式/填充方式,"AES/ECB/PKCS5Padding"
    public static String encrypt(String key, String data) throws Exception {

        //生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTO);

        //用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

        byte[] bt = cipher.doFinal(data.getBytes(CODE));

        String str = new BASE64Encoder().encode(bt);

        return str;
    }

    public static String encrypt(String key, String data,String iv) throws Exception {

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTOBLOCK);

        IvParameterSpec v = new IvParameterSpec(iv.getBytes(CODE));
        AlgorithmParameterSpec paramSpec = v;

        //用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey,paramSpec);

        byte[] bt = cipher.doFinal(data.getBytes(CODE));

        String str = new BASE64Encoder().encode(bt);

        return str;
    }

    public static String decrypt(String key, String data) throws Exception {

        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(CRYPTO);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);

        byte[] bt = cipher.doFinal(buf);

        String str = new String(bt,CODE);

        return str;
    }

    public static String decrypt(String key, String data,String iv) throws Exception {

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key.getBytes(CODE));

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO);
        SecretKey securekey = keyFactory.generateSecret(dks);

        //Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CRYPTOBLOCK);

        IvParameterSpec v = new IvParameterSpec(iv.getBytes(CODE));
        AlgorithmParameterSpec paramSpec = v;

        //用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey,paramSpec);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);

        byte[] bt = cipher.doFinal(buf);

        String str = new String(bt,CODE);

        return str;
    }
}

//非对称加密算法............................................................

/*在window上和linux上,编码后的数值不一样,但是同样都可以解码*/
class Base64Code {

    //base64 编码
    public static String encode(String data) throws Exception {

          //第1种方式Base64
        return new String(new BASE64Encoder().encode(data.getBytes("utf-8")));

        //第2种方式Base64
//        Base64.Encoder encoder = Base64.getEncoder();
//
//        return new String(encoder.encodeToString(data.getBytes("utf-8")));
    }

    //base64 解码
    public static String decode(String data) throws Exception {

//        BASE64Decoder decoder = new BASE64Decoder();
//        byte[] buf = decoder.decodeBuffer(data);
//
//        return new String(buf,"utf-8");

        Base64.Decoder decoder = Base64.getDecoder();

        return new String(decoder.decode(data.getBytes("utf-8")));
    }

}

class RSA {

    public static String publicKeyString;
    public static String privateKeyString;

    public static void genKeyPair() throws NoSuchAlgorithmException {

        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为96-1024位
        keyPairGen.initialize(1024,new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();       // 得到公钥

        // 得到公钥字符串
        publicKeyString = new String(new BASE64Encoder().encode(publicKey.getEncoded())); //进行base64编码
        // 得到私钥字符串
        privateKeyString = new String(new BASE64Encoder().encode((privateKey.getEncoded())));

        System.out.println("公钥:" + publicKeyString);
        System.out.println("私钥:" + privateKeyString);
    }

    public static String encrypt( String publicKey,String data) throws Exception{

        //base64编码的公钥
        byte[] decoded = new BASE64Decoder().decodeBuffer(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] bt = cipher.doFinal(data.getBytes("UTF-8"));

        String outStr = new String(new BASE64Encoder().encode(bt));

        return outStr;
    }

    public static String decrypt(String privateKey,String data) throws Exception{

        //64位解码加密后的字符串
        byte[] inputByte = new BASE64Decoder().decodeBuffer(data);
        //base64编码的私钥
        byte[] decoded = new BASE64Decoder().decodeBuffer(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte),"UTF-8");

        return outStr;
    }
}
