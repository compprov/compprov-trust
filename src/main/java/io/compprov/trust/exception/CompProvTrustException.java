package io.compprov.trust.exception;

/**
 * ComProv trust exception, all other exceptions are inherited from this one
 */
public class CompProvTrustException extends Exception {

    public CompProvTrustException() {
    }

    public CompProvTrustException(String message) {
        super(message);
    }

    public CompProvTrustException(String message, Throwable cause) {
        super(message, cause);
    }
}
