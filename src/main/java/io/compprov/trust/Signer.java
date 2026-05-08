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
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import io.compprov.trust.exception.AmbiguousDataException;
import io.compprov.trust.exception.ContentExtractionException;
import io.compprov.trust.exception.ExternalServiceException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

/**
 * Signs JSON content as an enveloping JAdES Baseline-LT signature.
 * <p>
 * The produced document is a self-contained JWS JSON Serialization structure that embeds
 * the original payload, the signing certificate chain, and a long-term timestamp
 * obtained from an external TSP (Time-Stamp Protocol) service.
 */
public class Signer {

    private final Pkcs12SignatureToken signatureToken;
    private final OnlineTSPSource tspSource;
    private final TrustedCertificateSource trustSource;

    /**
     * Creates a {@code Signer} with an HTTP TSP endpoint.
     *
     * @param signatureToken PKCS#12 token holding the signing key; must contain exactly one key pair
     * @param tspSource      URL of the TSP service, e.g. {@code http://timestamp.digicert.com}
     * @param trustSource    trusted certificate source used during signing-time validation; may be {@code null}
     */
    public Signer(Pkcs12SignatureToken signatureToken, String tspSource, TrustedCertificateSource trustSource) {
        this.signatureToken = signatureToken;
        this.trustSource = trustSource;
        this.tspSource = new OnlineTSPSource(tspSource);
        this.tspSource.setDataLoader(new CommonsDataLoader());
    }

    /**
     * Creates a {@code Signer} with a pre-configured TSP source.
     *
     * @param signatureToken PKCS#12 token holding the signing key; must contain exactly one key pair
     * @param tspSource      pre-configured TSP source
     * @param trustSource    trusted certificate source used during signing-time validation; may be {@code null}
     */
    public Signer(Pkcs12SignatureToken signatureToken, OnlineTSPSource tspSource, TrustedCertificateSource trustSource) {
        this.signatureToken = signatureToken;
        this.tspSource = tspSource;
        this.trustSource = trustSource;
    }

    /**
     * Loads a PKCS#12 token from the given stream.
     *
     * @param p12Stream input stream of the {@code .p12} / {@code .pfx} file
     * @param password  keystore password
     * @return a signature token ready to be passed to a {@link Signer} constructor
     */
    public static Pkcs12SignatureToken loadPkcs12(InputStream p12Stream, char[] password) {
        return new Pkcs12SignatureToken(p12Stream, new KeyStore.PasswordProtection(password));
    }

    /**
     * Signs the given JSON string and returns a JAdES Baseline-LT envelope as a JSON string.
     *
     * @param jsonContent          JSON payload to sign; must be valid UTF-8
     * @param skipSignerValidation set to {@code true} for self-signed certificates to suppress
     *                             missing-revocation-data errors during signing; {@code false} for
     *                             certificates issued by a trusted CA
     * @return JAdES JSON Serialization document containing the payload, signature, certificate chain,
     *         and embedded timestamp
     * @throws ContentExtractionException if the keystore contains no key, or if the signed document
     *                                    cannot be serialized
     * @throws AmbiguousDataException     if the keystore contains more than one key pair
     * @throws ExternalServiceException   if the DSS signing or timestamping operation fails
     */
    public String signJson(String jsonContent, boolean skipSignerValidation)
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
        parameters.bLevel().setTrustAnchorBPPolicy(false);

        final var verifier = new CommonCertificateVerifier();
        if (trustSource != null) {
            verifier.addTrustedCertSources(trustSource);
        }
        if (skipSignerValidation) {
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
            throw new ExternalServiceException("Failed to sign", e);
        }

        try {
            final var baos = new ByteArrayOutputStream();
            signedDocument.writeTo(baos);
            return baos.toString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ContentExtractionException("failed to extract payload", e);
        }
    }
}
