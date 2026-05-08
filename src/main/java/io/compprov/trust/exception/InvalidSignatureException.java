package io.compprov.trust.exception;

/** Thrown when the cryptographic signature or timestamp fails validation. */
public class InvalidSignatureException extends CompProvTrustException {

    public InvalidSignatureException(String msg) {
        super(msg);
    }
}
