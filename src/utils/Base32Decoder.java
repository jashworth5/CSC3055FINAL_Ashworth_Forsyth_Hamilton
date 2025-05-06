package utils;

public class Base32Decoder {
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static byte[] decode(String base32) {
        base32 = base32.replace("=", "").toUpperCase();

        byte[] bytes = new byte[base32.length() * 5 / 8];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;

        for (char c : base32.toCharArray()) {
            int val = BASE32_CHARS.indexOf(c);
            if (val < 0) throw new IllegalArgumentException("Invalid Base32 character: " + c);

            buffer <<= 5;
            buffer |= val & 31;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                bytes[index++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        return bytes;
    }
}
