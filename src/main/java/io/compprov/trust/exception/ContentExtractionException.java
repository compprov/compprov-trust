package io.compprov.trust.exception;

/** Thrown when the signed payload cannot be extracted or read from the JAdES envelope. */
public class ContentExtractionException extends CompProvTrustException {

    public ContentExtractionException(String message, Throwable cause) {
        super(message, cause);
    }

    public ContentExtractionException(String message) {
        super(message);
    }
}
