package io.compprov.trust;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
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
import org.jose4j.base64url.Base64Url;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Validates an enveloping JAdES Baseline-LT document and extracts its payload.
 * <p>
 * Expects exactly one signature and one TSP timestamp. Any deviation — unsigned content,
 * multiple signers, missing or invalid timestamp — is reported as a {@link io.compprov.trust.exception.CompProvTrustException}.
 */
public class Verifier {

    private final Optional<TrustedCertificateSource> trustSource;

    /**
     * Creates a {@code Verifier} without a trust anchor.
     */
    public Verifier() {
        this.trustSource = Optional.empty();
    }

    /**
     * Creates a {@code Verifier} with the given trust anchor.
     *
     * @param trustSource trusted certificate source against which the signing certificate is
     *                    validated. For production use, prefer certificates issued by a trusted Certificate Authority
     *                    and use {@code Verifier()} constructor
     */
    public Verifier(TrustedCertificateSource trustSource) {
        this.trustSource = Optional.ofNullable(trustSource);
    }

    /**
     * Loads all certificates from a PKCS#12 keystore into a {@link TrustedCertificateSource}.
     *
     * @param p12Stream input stream of the {@code .p12} / {@code .pfx} file
     * @param password  keystore password; {@code null} if the keystore has no password
     * @return a trust source containing every certificate found in the keystore
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
     * @throws InvalidSignatureException  if the cryptographic signature or timestamp is invalid
     * @throws AmbiguousDataException     if the document contains more than one signature or timestamp
     * @throws ContentExtractionException if the signed payload cannot be read
     * @throws TimestampNotFoundException if the signature contains no TSP timestamp
     */
    public VerifiedData verify(String jadesJson)
            throws NonSignedContentException, AmbiguousDataException,
            InvalidSignatureException, ContentExtractionException, TimestampNotFoundException {
        return verify(jadesJson, true);
    }

    /**
     * Validates the given JAdES document and returns the extracted payload and metadata.
     *
     * @param jadesJson                                 JAdES JSON Serialization string, as produced by {@link Signer#signJson}
     * @param requireSigningCertificateStatusValidation recommended to use {@code true} for production.
     *                                                  For testing purposes and self-signed certificated could be set
     *                                                  to {@code false}
     * @return verified payload and signature metadata
     * @throws NonSignedContentException  if the document contains no signature or no signed payload
     * @throws InvalidSignatureException  if the cryptographic signature or timestamp is invalid
     * @throws AmbiguousDataException     if the document contains more than one signature or timestamp
     * @throws ContentExtractionException if the signed payload cannot be read
     * @throws TimestampNotFoundException if the signature contains no TSP timestamp
     */
    public VerifiedData verify(String jadesJson, boolean requireSigningCertificateStatusValidation)
            throws NonSignedContentException, AmbiguousDataException,
            InvalidSignatureException, ContentExtractionException, TimestampNotFoundException {
        final var document = new InMemoryDocument(jadesJson.getBytes(UTF_8));

        final var verifier = new CommonCertificateVerifier();
        trustSource.ifPresent(ts -> verifier.setTrustedCertSources(ts));

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
            throw new InvalidSignatureException(Code.PAYLOAD_TAMPERED, "isReferenceDataIntact=false. "
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
        final var signerCertStatusValidated = !reports.getDiagnosticData().getSignatureById(sigId)
                .getSigningCertificate().foundRevocations().getRelatedRevocationData().isEmpty();
        if ((!signerCertStatusValidated) && (requireSigningCertificateStatusValidation)) {
            throw new InvalidSignatureException(Code.SIGNER_CERT_STATUS_NOT_VALIDATED,
                    sigId + " signing certificate status is not validated. " +
                    "If self-signed certificates were used, specify TrustedCertificateSource when create Verifier and" +
                    " verify signature using method verify(jadesJson, false)");
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
        final var encodedSignatureValue = Base64Url.encode(signatureDetails.getSignatureValue()).getBytes(UTF_8);
        final byte[] sigDig;
        try {
            sigDig = tspMessageImprint.getAlgorithm().getMessageDigest().digest(encodedSignatureValue);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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
}
