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

public class Cryptography {

    /*测试DES对称加密算法*/
    public static void testdes() throws Exception {

        String key = "12345678"; //对称加密的秘钥
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

    public static void test3des() throws Exception {

        String key = "12345678"; //对称加密的秘钥
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
    public static void main(String args[]) throws Exception {

        System.out.println("Hello Cryptography");

        //testdes();
        //test3des();
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
