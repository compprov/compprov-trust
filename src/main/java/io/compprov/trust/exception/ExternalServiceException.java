package io.compprov.trust.exception;

/**
 * Thrown when DSS signing process fails.
 */
public class ExternalServiceException extends CompProvTrustException {

    public ExternalServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
