package io.compprov.trust;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import io.compprov.trust.exception.AmbiguousDataException;
import io.compprov.trust.exception.ContentExtractionException;
import io.compprov.trust.exception.InvalidSignatureException;
import io.compprov.trust.exception.InvalidSignatureException.Code;
import io.compprov.trust.exception.NonSignedContentException;
import io.compprov.trust.exception.TimestampNotFoundException;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Validates an enveloping JAdES Baseline-LT document and extracts its payload.
 * <p>
 * Expects exactly one signature and one TSP timestamp. Any deviation — unsigned content,
 * multiple signers, missing or invalid timestamp — is reported as a {@link io.compprov.trust.exception.CompProvTrustException}.
 * <p>
 * Instances are created with {@link #builder(TrustedCertificateSource)}:
 * <pre>{@code
 * Verifier verifier = Verifier.builder(trustSource).build();
 * }</pre>
 */
public class Verifier {

    private final TrustedCertificateSource trustSource;
    private final boolean allowMissingRevocationData;

    private Verifier(Builder builder) {
        this.trustSource = builder.trustSource;
        this.allowMissingRevocationData = builder.allowMissingRevocationData;
    }

    /**
     * Starts building a {@code Verifier}.
     *
     * @param trustSource trusted certificate source against which the signing certificate chain is validated,
     *                    e.g. the root certificate of the Certificate Authority that issued the signer certificate,
     *                    or the signer certificate itself when it is self-signed
     * @return a new builder
     */
    public static Builder builder(TrustedCertificateSource trustSource) {
        return new Builder(trustSource);
    }

    /**
     * Loads all certificates from a PKCS#12 keystore into a {@link TrustedCertificateSource}.
     *
     * @param p12Stream input stream of the {@code .p12} / {@code .pfx} file
     * @param password  keystore password; {@code null} if the keystore has no password
     * @return a trust source containing every certificate found in the keystore, ready to be passed to
     * {@link #builder(TrustedCertificateSource)}
     */
    public static TrustedCertificateSource loadPkcs12(InputStream p12Stream, char[] password) {
        final var certSource = new KeyStoreCertificateSource(p12Stream, "PKCS12", password);
        final var trustSource = new CommonTrustedCertificateSource();
        for (var certificate : certSource.getCertificates()) {
            trustSource.addCertificate(certificate);
        }
        return trustSource;
    }

    /**
     * Validates the given JAdES document and returns the extracted payload and metadata.
     *
     * @param jadesJson JAdES JSON Serialization string, as produced by {@link Signer#signJson}
     * @return verified payload and signature metadata
     * @throws NonSignedContentException  if the document contains no signature or no signed payload
     * @throws InvalidSignatureException  if the cryptographic signature or timestamp is invalid, or the document
     *                                    declares an unsupported format version (see {@link Signer#CONTENT_TYPE_V1})
     * @throws AmbiguousDataException     if the document contains more than one signature or timestamp
     * @throws ContentExtractionException if the signed payload cannot be read
     * @throws TimestampNotFoundException if the signature contains no TSP timestamp
     */
    public VerifiedData verify(String jadesJson)
            throws NonSignedContentException, AmbiguousDataException,
            InvalidSignatureException, ContentExtractionException, TimestampNotFoundException {
        final var document = new InMemoryDocument(jadesJson.getBytes(UTF_8));

        final var verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trustSource);

        final var validator = new JAdESDocumentValidatorFactory().create(document);
        validator.setCertificateVerifier(verifier);

        final var reports = validator.validateDocument();
        final var simpleReport = reports.getSimpleReport();

        final var signatureList = simpleReport.getSignatureIdList();
        if (signatureList.isEmpty()) {
            throw new NonSignedContentException();
        } else if (signatureList.size() > 1) {
            throw new AmbiguousDataException("Multiple signatures detected");
        }
        final var sigId = signatureList.get(0);

        final var signatureDetails = validator.getSignatureById(sigId);
        if (!signatureDetails.getSignatureCryptographicVerification().isReferenceDataFound()) {
            throw new InvalidSignatureException(Code.PAYLOAD_NOT_FOUND, "isReferenceDataFound=false. "
                    + signatureDetails.getSignatureCryptographicVerification().getErrorMessage());
        }
        if (!signatureDetails.getSignatureCryptographicVerification().isReferenceDataIntact()) {
            throw new InvalidSignatureException(Code.SIGNED_DATA_TAMPERED, "isReferenceDataIntact=false. "
                    + signatureDetails.getSignatureCryptographicVerification().getErrorMessage());
        }
        if (!signatureDetails.getSignatureCryptographicVerification().isSignatureIntact()) {
            throw new InvalidSignatureException(Code.SIGNATURE_TAMPERED, "isSignatureIntact=false. "
                    + signatureDetails.getSignatureCryptographicVerification().getErrorMessage());
        }
        if (!signatureDetails.getSignatureCryptographicVerification().isSignatureValid()) {
            throw new InvalidSignatureException(Code.SIGNATURE_INVALID, "isSignatureValid=false. "
                    + signatureDetails.getSignatureCryptographicVerification().getErrorMessage());
        }
        // cty lives in the signed header, so it can only be trusted after the signature is proven intact.
        // DSS returns "" for an absent header; documents without cty predate format versioning and are v1
        final var contentType = ((JAdESSignature) signatureDetails).getJws().getProtectedHeaderValueAsString("cty");
        if (contentType != null && !contentType.isBlank() && !normalizeMediaType(contentType).equals(normalizeMediaType(Signer.CONTENT_TYPE_V1))) {
            throw new InvalidSignatureException(Code.UNSUPPORTED_FORMAT, "Unsupported content type: " + contentType);
        }
        final var signerCertStatusValidated = !reports.getDiagnosticData().getSignatureById(sigId)
                .getSigningCertificate().foundRevocations().getRelatedRevocationData().isEmpty();
        if (!signerCertStatusValidated && !allowMissingRevocationData) {
            throw new InvalidSignatureException(Code.SIGNER_CERT_STATUS_NOT_VALIDATED,
                    sigId + " signing certificate status is not validated. " +
                    "If a self-signed certificate was used, build the Verifier with allowMissingRevocationData(true)");
        }

        final var signerChainIds = new HashSet<>(reports.getDiagnosticData().getSignatureCertificateChainIds(sigId));
        final var signerChain = signatureDetails.getCertificates()
                .stream()
                .filter(cert -> signerChainIds.contains(cert.getDSSIdAsString()))
                .map(cert -> cert.getCertificate())
                .toList();

        final var docs = validator.getOriginalDocuments(sigId);
        if (docs.isEmpty()) {
            throw new NonSignedContentException();
        } else if (docs.size() > 1) {
            throw new ContentExtractionException("Multiple docs");
        }
        final String payloadJson;
        try {
            payloadJson = new String(docs.get(0).openStream().readAllBytes(), UTF_8);
        } catch (IOException e) {
            throw new ContentExtractionException("failed to read", e);
        }

        final var timestamps = signatureDetails.getAllTimestamps();
        if (timestamps.isEmpty()) {
            throw new TimestampNotFoundException();
        } else if (timestamps.size() > 1) {
            throw new AmbiguousDataException("Multiple timestamps detected");
        }
        final var timestamp = timestamps.get(0);
        final var tspChain = timestamp.getCertificates()
                .stream()
                .map(cert -> cert.getCertificate())
                .toList();
        if (timestamp.getTimeStampType() != TimestampType.SIGNATURE_TIMESTAMP) {
            throw new InvalidSignatureException(Code.TIMESTAMP_WRONG_TYPE, "Invalid timestamp type: " + timestamp.getTimeStampType());
        }
        if (!timestamp.isProcessed()) {
            throw new InvalidSignatureException(Code.TIMESTAMP_NOT_PROCESSED, "timestamp.isProcessed=false");
        }
        if (!timestamp.isMessageImprintDataFound()) {
            throw new InvalidSignatureException(Code.TIMESTAMP_IMPRINT_NOT_FOUND, "timestamp.isMessageImprintDataFound=false");
        }
        if (!timestamp.isMessageImprintDataIntact()) {
            throw new InvalidSignatureException(Code.TIMESTAMP_IMPRINT_TAMPERED, "timestamp.isMessageImprintDataIntact=false");
        }
        if (!timestamp.isSignatureIntact()) {
            throw new InvalidSignatureException(Code.TIMESTAMP_SIGNATURE_TAMPERED, "timestamp.isSignatureIntact=false");
        }

        final var tspMessageImprint = timestamp.getMessageImprint();
        final var encodedSignatureValue = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signatureDetails.getSignatureValue()).getBytes(UTF_8);
        final byte[] sigDig;
        try {
            sigDig = tspMessageImprint.getAlgorithm().getMessageDigest().digest(encodedSignatureValue);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidSignatureException(Code.TIMESTAMP_INVALID,
                    "unsupported timestamp digest algorithm: " + tspMessageImprint.getAlgorithm(), e);
        }
        if (!Arrays.equals(tspMessageImprint.getValue(), sigDig)) {
            throw new InvalidSignatureException(Code.TIMESTAMP_COVERS_WRONG_DATA, "timestamp.matchData(sig)=false");
        }
        if (!timestamp.isValid()) {
            throw new InvalidSignatureException(Code.TIMESTAMP_INVALID, "timestamp.isValid=false");
        }

        if (!simpleReport.isValid(sigId)) {
            throw new InvalidSignatureException(Code.SIGNATURE_NOT_VALID, sigId + " is not valid");
        }

        final var timestampWrapper = reports.getDiagnosticData().getTimestampById(timestamp.getDSSIdAsString());
        final var timestampZdt = ZonedDateTime.ofInstant(
                timestampWrapper.getProductionTime().toInstant(), ZoneOffset.UTC);

        return new VerifiedData(payloadJson, timestampZdt, tspChain, signerChain, signerCertStatusValidated);
    }

    /**
     * Per RFC 7515 section 4.1.10, a {@code cty} value without '/' implies the {@code application/} prefix.
     */
    private static String normalizeMediaType(String mediaType) {
        final var lower = mediaType.trim().toLowerCase(Locale.ROOT);
        return lower.contains("/") ? lower : "application/" + lower;
    }

    /**
     * Immutable result of a successful {@link Verifier#verify} call.
     *
     * @param payloadJson               the original JSON payload extracted from the JAdES envelope
     * @param signedTimestamp           UTC timestamp issued by the TSP service at signing time. Make sure the CPG was
     *                                  created at expected date and time.
     * @param tspChain                  certificate chain of the TSP authority. Make sure the chain is trusted by you.
     * @param signerChain               certificate chain of the content signer. Make sure the chain is trusted by you.
     * @param signerCertStatusValidated {@code true} if revocation data (CRL or OCSP) was found for
     *                                  the signing certificate; {@code false} for self-signed certificates
     *                                  or when revocation status could not be confirmed — callers should
     *                                  decide whether to accept such signatures based on their policy
     */
    public record VerifiedData(
            String payloadJson,
            ZonedDateTime signedTimestamp,
            List<X509Certificate> tspChain,
            List<X509Certificate> signerChain,
            boolean signerCertStatusValidated) {
    }

    /**
     * Builder for {@link Verifier}.
     */
    public static final class Builder {

        private final TrustedCertificateSource trustSource;
        private boolean allowMissingRevocationData;

        private Builder(TrustedCertificateSource trustSource) {
            this.trustSource = Objects.requireNonNull(trustSource, "trustSource");
        }

        /**
         * Set to {@code true} to accept signatures whose signing certificate has no revocation data
         * (CRL or OCSP), e.g. self-signed certificates. Defaults to {@code false}, which is recommended
         * for production. The outcome is reported in {@link VerifiedData#signerCertStatusValidated()}.
         *
         * @param allow whether missing revocation data is tolerated
         * @return this builder
         */
        public Builder allowMissingRevocationData(boolean allow) {
            this.allowMissingRevocationData = allow;
            return this;
        }

        /**
         * @return a configured {@link Verifier}
         */
        public Verifier build() {
            return new Verifier(this);
        }
    }
}
