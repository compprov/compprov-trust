package io.compprov.trust.exception;

/** Thrown when the document contains more than one signature or more than one timestamp. */
public class AmbiguousDataException extends CompProvTrustException {
    public AmbiguousDataException(String msg) {
        super(msg);
    }
}
