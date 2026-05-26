package io.compprov.trust.exception;

/** Thrown when the cryptographic signature or timestamp fails validation. */
public class InvalidSignatureException extends CompProvTrustException {

    public enum Code {
        PAYLOAD_NOT_FOUND,
        PAYLOAD_TAMPERED,
        SIGNATURE_TAMPERED,
        SIGNATURE_INVALID,
        SIGNER_CERT_STATUS_NOT_VALIDATED,
        TIMESTAMP_NOT_PROCESSED,
        TIMESTAMP_IMPRINT_NOT_FOUND,
        TIMESTAMP_IMPRINT_TAMPERED,
        TIMESTAMP_SIGNATURE_TAMPERED,
        TIMESTAMP_WRONG_TYPE,
        TIMESTAMP_COVERS_WRONG_DATA,
        TIMESTAMP_INVALID,
        SIGNATURE_NOT_VALID
    }

    private final Code code;

    public InvalidSignatureException(Code code, String msg) {
        super(msg);
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
