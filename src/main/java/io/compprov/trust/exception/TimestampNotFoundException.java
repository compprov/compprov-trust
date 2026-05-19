package io.compprov.trust.exception;

/** Thrown when the JAdES document contains no TSP timestamp. */
public class TimestampNotFoundException extends CompProvTrustException {

    public TimestampNotFoundException() {
    }

    public TimestampNotFoundException(String message) {
        super(message);
    }
}
