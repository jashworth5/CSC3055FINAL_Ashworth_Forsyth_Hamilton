package server;

import shared.TOTPUtil;

public class TOTPValidator {
    private final String base32Secret;

    public TOTPValidator(String base32Secret) {
        this.base32Secret = base32Secret;
    }

    public boolean validateCode(String userCode) {
        return TOTPUtil.validateTOTP(base32Secret, userCode);
    }
}
