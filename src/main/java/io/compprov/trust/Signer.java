package io.compprov.trust;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import io.compprov.trust.exception.AmbiguousDataException;
import io.compprov.trust.exception.ContentExtractionException;
import io.compprov.trust.exception.ExternalServiceException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Objects;

/**
 * Signs JSON content as an enveloping JAdES Baseline-LT signature.
 * <p>
 * The produced document is a self-contained JWS JSON Serialization structure that embeds
 * the original payload, the signing certificate chain, and a long-term timestamp
 * obtained from an external TSP (Time-Stamp Protocol) service.
 * <p>
 * Instances are created with {@link #builder(SignatureTokenConnection)}:
 * <pre>{@code
 * Signer signer = Signer.builder(Signer.loadPkcs12(p12Stream, password))
 *         .tspUrl("http://timestamp.digicert.com")
 *         .build();
 * }</pre>
 */
public class Signer {

    /**
     * Format version marker written to the signed {@code cty} (content type) JWS header.
     * {@link Verifier} rejects documents carrying any other value.
     */
    public static final String CONTENT_TYPE_V1 = "vnd.compprov.trust.v1+json";

    private final SignatureTokenConnection signatureToken;
    private final TSPSource tspSource;
    private final TrustedCertificateSource trustSource;
    private final boolean allowMissingRevocationData;

    private Signer(Builder builder) {
        this.signatureToken = builder.signatureToken;
        this.tspSource = Objects.requireNonNull(builder.tspSource, "TSP source is not set");
        this.trustSource = builder.trustSource;
        this.allowMissingRevocationData = builder.allowMissingRevocationData;
    }

    /**
     * Starts building a {@code Signer}.
     *
     * @param signatureToken signature token holding the signing key; must contain exactly one key pair
     * @return a new builder
     */
    public static Builder builder(SignatureTokenConnection signatureToken) {
        return new Builder(signatureToken);
    }

    /**
     * Loads a PKCS#12 token from the given stream.
     *
     * @param p12Stream input stream of the {@code .p12} / {@code .pfx} file
     * @param password  keystore password
     * @return a signature token ready to be passed to {@link #builder(SignatureTokenConnection)}
     */
    public static Pkcs12SignatureToken loadPkcs12(InputStream p12Stream, char[] password) {
        return new Pkcs12SignatureToken(p12Stream, new KeyStore.PasswordProtection(password));
    }

    /**
     * Signs the given JSON string and returns a JAdES Baseline-LT envelope as a JSON string.
     *
     * @param jsonContent JSON payload to sign
     * @return JAdES JSON Serialization document containing the payload, signature, certificate chain,
     * and embedded timestamp
     * @throws ContentExtractionException if the keystore contains no key, or if the signed document
     *                                    cannot be serialized
     * @throws AmbiguousDataException     if the keystore contains more than one key pair
     * @throws ExternalServiceException   if the DSS signing or timestamping operation fails
     */
    public String signJson(String jsonContent)
            throws ContentExtractionException, AmbiguousDataException, ExternalServiceException {
        final var keys = signatureToken.getKeys();
        if (keys.isEmpty()) {
            throw new ContentExtractionException("key pair is not found");
        } else if (keys.size() > 1) {
            throw new AmbiguousDataException("multiple key pairs detected");
        }
        final var privateKey = keys.get(0);

        final var parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(privateKey.getCertificate());
        parameters.setCertificateChain(privateKey.getCertificateChain());
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        parameters.setIncludeCertificateChain(true);
        parameters.setContentType(CONTENT_TYPE_V1);
        parameters.bLevel().setTrustAnchorBPPolicy(false);

        final var verifier = new CommonCertificateVerifier();
        if (trustSource != null) {
            verifier.addTrustedCertSources(trustSource);
        }
        if (allowMissingRevocationData) {
            verifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        }

        final var service = new JAdESService(verifier);
        service.setTspSource(tspSource);

        final DSSDocument signedDocument;
        try {
            final var documentToSign = new InMemoryDocument(jsonContent.getBytes(StandardCharsets.UTF_8));
            final var dataToSign = service.getDataToSign(documentToSign, parameters);
            final var signatureValue = signatureToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            signedDocument = service.signDocument(documentToSign, parameters, signatureValue);
        } catch (DSSException e) {
            throw new ExternalServiceException("Failed to sign: " + e.getMessage(), e);
        }

        try {
            final var baos = new ByteArrayOutputStream();
            signedDocument.writeTo(baos);
            return baos.toString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ContentExtractionException("failed to extract payload", e);
        }
    }

    /**
     * Builder for {@link Signer}. A TSP source must be set via {@link #tspUrl(String)} or
     * {@link #tspSource(TSPSource)}; everything else is optional.
     */
    public static final class Builder {

        private final SignatureTokenConnection signatureToken;
        private TSPSource tspSource;
        private TrustedCertificateSource trustSource;
        private boolean allowMissingRevocationData;

        private Builder(SignatureTokenConnection signatureToken) {
            this.signatureToken = Objects.requireNonNull(signatureToken, "signatureToken");
        }

        /**
         * Uses an HTTP TSP endpoint.
         *
         * @param url URL of the TSP service, e.g. {@code http://timestamp.digicert.com}
         * @return this builder
         */
        public Builder tspUrl(String url) {
            final var source = new OnlineTSPSource(Objects.requireNonNull(url, "url"));
            source.setDataLoader(new CommonsDataLoader());
            this.tspSource = source;
            return this;
        }

        /**
         * Uses a pre-configured TSP source.
         *
         * @param tspSource TSP source
         * @return this builder
         */
        public Builder tspSource(TSPSource tspSource) {
            this.tspSource = Objects.requireNonNull(tspSource, "tspSource");
            return this;
        }

        /**
         * Sets the trusted certificate source used during signing-time validation. Optional.
         *
         * @param trustSource trusted certificate source
         * @return this builder
         */
        public Builder trustSource(TrustedCertificateSource trustSource) {
            this.trustSource = trustSource;
            return this;
        }

        /**
         * Set to {@code true} for self-signed certificates to suppress missing-revocation-data errors
         * during signing. Defaults to {@code false}, which is what certificates issued by a trusted CA need.
         *
         * @param allow whether missing revocation data (CRL/OCSP) is tolerated
         * @return this builder
         */
        public Builder allowMissingRevocationData(boolean allow) {
            this.allowMissingRevocationData = allow;
            return this;
        }

        /**
         * @return a configured {@link Signer}
         * @throws NullPointerException if no TSP source was set
         */
        public Signer build() {
            return new Signer(this);
        }
    }
}
