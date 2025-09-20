// 源码中的 TokenUtil.java生成随机数文件
package offsec.answer;

import java.util.Base64;
import java.util.Random;

public class TokenUtil {

    public static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
    public static final String NUMBERS = "1234567890";
    public static final String SYMBOLS = "!@#$%^&*()";
    public static final String CHARSET = CHAR_LOWER + CHAR_LOWER.toUpperCase() + NUMBERS + SYMBOLS;

    public static final int TOKEN_LENGTH = 42;

    public static String createToken(int userId) {
        Random random = new Random(System.currentTimeMillis());
        StringBuilder sb = new StringBuilder();
        byte[] encbytes = new byte[TOKEN_LENGTH];

        for (int i = 0; i < TOKEN_LENGTH; i++) {
            sb.append(CHARSET.charAt(random.nextInt(CHARSET.length())));
        }

        byte[] bytes = sb.toString().getBytes();

        for (int i = 0; i < bytes.length; i++) {
            encbytes[i] = (byte) (bytes[i] ^ (byte) userId);
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(encbytes);
    }

    public static void main(String[] args) {
        int userId = 5;
        String tok = createToken(userId);
        System.out.println("token= " + tok);
    }

}
