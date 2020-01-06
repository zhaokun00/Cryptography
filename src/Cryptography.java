import sun.misc.BASE64Decoder;

import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
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
        String data = "12345678"; //传输数据

        {
            String enData = TestDes.encrypt(key, data);

            System.out.println("加密后的数据:" + enData);

            //当密钥错误时,会抛出异常,解密失败
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

//        RSA.writeKeyToFile("F:\\zk\\Cryptography\\src\\public_key.pem",RSA.publicKeyString);
//        RSA.writeKeyToFile("F:\\zk\\Cryptography\\src\\private_key.pem",RSA.privateKeyString);

        String data = "qianyang123";

        //用公钥加密用私钥解密
//        {
//            String en = RSA.encrypt(RSA.publicKeyString,data);
//
//            System.out.println("编码后数据:" + en);
//
//            //当私钥不对时,解密会失败,在java中会抛出异常
//            String de = RSA.decrypt(RSA.privateKeyString,en);
//
//            System.out.println("解码后数据:" + de);
//        }

        //私钥加密用公钥解密
//        {
//            String en = RSA.encrypt1(RSA.privateKeyString,data);
//
//            System.out.println("编码后数据:" + en);
//
//            //当私钥不对时,解密会失败,在java中会抛出异常
//            String de = RSA.decrypt1(RSA.publicKeyString,en);
//
//            System.out.println("解码后数据:" + de);
//        }

        {
            StringBuilder sb = new StringBuilder();

            //openssl生成的公钥和私钥
//            String publicKey = RSA.loadKeyByFile("F:\\zk\\Cryptography\\src\\rsa_public_key.pem");
//            String priKey = RSA.loadKeyByFile("F:\\zk\\Cryptography\\src\\pkcs8_rsa_private_key.pem");

            //java内部生成的公钥和私钥
              String publicKey = RSA.loadKeyByFile("F:\\zk\\Cryptography\\src\\public_key.pem");
              String priKey = RSA.loadKeyByFile("F:\\zk\\Cryptography\\src\\private_key.pem");

//            String en = RSA.encrypt(publicKey,data);
//
//            System.out.println("编码后数据:" + en);
//
//            //当私钥不对时,解密会失败,在java中会抛出异常
//            String de = RSA.decrypt(priKey,en);
//
//            System.out.println("解码后数据:" + de);

              String en = RSA.encrypt1(priKey,data);

              System.out.println("编码后数据:" + en);

             //当私钥不对时,解密会失败,在java中会抛出异常
             String de = RSA.decrypt1(publicKey,en);

             System.out.println("解码后数据:" + de);

        }
    }

    public static void testFunction() throws Exception {

        String data = "1";

        String md5 = TestFunction.md5(data);

        System.out.println("md5:" + md5);

        String sha = TestFunction.sha(data);
        System.out.println("sha:" + sha);

    }

    public static void testMac() throws Exception {

        String key = "Secret_Key";
        String data = "Hello World!";
        String type = "HmacSHA256";

        String result = TestMac.encode(key,data,type);

        System.out.println(result);
    }

    public static void testSign() throws Exception {

        String data = "12345678";

        RSA.genKeyPair();

        //用私钥来进行签名
        String sign = TestSign.sign(data,RSA.privateKeyString,"utf-8");

        System.out.println("sign:" + sign);

        //用公钥来进行验证
        boolean result = TestSign.vertify(data,sign,RSA.publicKeyString,"utf-8");

        System.out.println("result:" + result);

    }

    public static void main(String args[]) throws Exception {

        //System.out.println("Hello Cryptography");

        //testdes();
        //test3des();
        //testBase64();
        testRsa();
        //testFunction();
        //testMac();
        //testSign();
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
//        return new String(new BASE64Encoder().encode(data.getBytes("utf-8")));

        //第2种方式Base64
        Base64.Encoder encoder = Base64.getEncoder();

        return new String(encoder.encodeToString(data.getBytes("utf-8")));
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

//        System.out.println("公钥:" + publicKeyString);
//        System.out.println("私钥:" + privateKeyString);
    }

    //使用公钥进行加密
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

    //使用公钥进行加密
    public static String encrypt1( String privateKey,String data) throws Exception{

        byte[] decoded = new BASE64Decoder().decodeBuffer(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, priKey);

        byte[] bt = cipher.doFinal(data.getBytes("UTF-8"));

        String outStr = new String(new BASE64Encoder().encode(bt));

        return outStr;
    }

    //使用私钥进行解密
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

    //使用公钥进行解密
    public static String decrypt1(String publicKey,String data) throws Exception{

        byte[] inputByte = new BASE64Decoder().decodeBuffer(data);
        //base64编码的私钥
        byte[] decoded = new BASE64Decoder().decodeBuffer(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        String outStr = new String(cipher.doFinal(inputByte),"UTF-8");

        return outStr;
    }

    public static String loadKeyByFile(String path) throws Exception {

        BufferedReader br = new BufferedReader(new FileReader(path));
        String readLine = null;

        StringBuilder sb = new StringBuilder();

        while ((readLine = br.readLine()) != null) {
            if (readLine.charAt(0) == '-') {
                continue;
            } else {
                sb.append(readLine);
                sb.append("\r\n");
            }
        }
        br.close();
        return sb.toString();
    }

    public static void writeKeyToFile(String path,String data) throws Exception {

        FileWriter fw = new FileWriter(path);
        BufferedWriter bw = new BufferedWriter(fw);

        bw.write(data);

        bw.flush();
        bw.close();
        fw.close();
    }

}

//单向散列函数
class TestFunction {

    private static char[] hex = {'0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    //echo -n 'hello' | md5sum | cut -d ' ' -f1,linux下计算MD5值
    public static String md5(String data) throws Exception {

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        byte[] ciphertext = messageDigest.digest(data.getBytes("UTF-8"));

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < ciphertext.length; i++) {
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(hex[(ciphertext[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(hex[(ciphertext[i] & 0x0f)]);
        }
        return stringBuilder.toString();
    }

    public static String sha(String data) throws Exception {

        //SHA-256
        //SHA-1
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");

        byte[] ciphertext = messageDigest.digest(data.getBytes("UTF-8"));

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < ciphertext.length; i++) {
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(hex[(ciphertext[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(hex[(ciphertext[i] & 0x0f)]);
        }
        return stringBuilder.toString();
    }
}

class TestMac {

    private static char[] hex = {'0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String encode(String key,String data, String type) throws Exception {

        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), type);
        Mac mac = Mac.getInstance(keySpec.getAlgorithm());
        mac.init(keySpec);

       byte[] ciphertext = mac.doFinal(data.getBytes("UTF-8"));

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < ciphertext.length; i++) {
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(hex[(ciphertext[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(hex[(ciphertext[i] & 0x0f)]);
        }
        return stringBuilder.toString();
    }
}

class TestSign {

    public static final String SIGN_ALGORITHMS = "SHA1WithRSA"; //SHA1WithRSA SHA256WithRSA MD5withRSA

    public static String sign(String content, String privateKey, String encode) throws Exception {

        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(privateKey));

        KeyFactory keyf = KeyFactory.getInstance("RSA");
        PrivateKey priKey = keyf.generatePrivate(priPKCS8);

        java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS);

        signature.initSign(priKey);
        signature.update(content.getBytes(encode));

        byte[] signed = signature.sign();

        return new BASE64Encoder().encode(signed);
    }

    public static boolean vertify(String content, String sign, String publicKey, String encode) throws Exception {

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = new BASE64Decoder().decodeBuffer(publicKey);

            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

            java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update(content.getBytes(encode));

            boolean bverify = signature.verify(new BASE64Decoder().decodeBuffer(sign));

            return bverify;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}