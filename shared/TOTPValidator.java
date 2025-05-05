package shared;

public class TOTPValidator {
    private final String base32Secret;

    public TOTPValidator(String base32Secret) {
        this.base32Secret = base32Secret;
    }

    public boolean validateCode(String userCode) {
        return TOTPUtil.validateTOTP(base32Secret, userCode);
    }

    // Static version for quick calls
    public static boolean validateTOTP(String base32Secret, String userCode) {
        return TOTPUtil.validateTOTP(base32Secret, userCode);
    }
}