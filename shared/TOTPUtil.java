package shared;

import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TOTPUtil {

    // Validates a TOTP token against the user's secret
    public static boolean validateTOTP(String base32Secret, String userCode) {
        long timeIndex = getTimeIndex();
        for (int i = -1; i <= 1; i++) {  // Allow small clock skew
            String generatedCode = generateTOTP(base32Secret, timeIndex + i);
            if (generatedCode != null && generatedCode.equals(userCode)) {
                return true;
            }
        }
        return false;
    }

    // Generate TOTP for a specific time interval
    private static String generateTOTP(String base32Secret, long timeIndex) {
        try {
            byte[] key = Base32Decoder.decode(base32Secret);
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (timeIndex & 0xFF);
                timeIndex >>= 8;
            }

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;
            int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

            int otp = binary % 1_000_000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static long getTimeIndex() {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        return currentTimeSeconds / 30;  // 30-second time steps
    }
}
