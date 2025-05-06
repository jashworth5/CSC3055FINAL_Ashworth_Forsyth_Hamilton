package utils;

import java.util.Scanner;

public class TOTPTest {
    public static void main(String[] args) {
        // Base32 secret for testing (encodes to "Hello!")
        String base32Secret = "JBSWY3DPEHPK3PXP";

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter TOTP code: ");
        String userCode = scanner.nextLine();

        boolean isValid = TOTPUtil.validateTOTP(base32Secret, userCode);
        if (isValid) {
            System.out.println("Code is valid.");
        } else {
            System.out.println("Code is invalid.");
        }

        scanner.close();
    }
}

