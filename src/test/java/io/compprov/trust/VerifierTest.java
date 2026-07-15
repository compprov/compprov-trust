package io.compprov.trust;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.compprov.core.DefaultComputationEnvironment;
import io.compprov.trust.exception.AmbiguousDataException;
import io.compprov.trust.exception.InvalidSignatureException;
import io.compprov.trust.exception.NonSignedContentException;
import io.compprov.trust.exception.TimestampNotFoundException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class VerifierTest {

    private String signedJson;
    private Verifier verifier;
    private X509Certificate signerCertificate;
    private X509Certificate tspCertificate;
    private CertificateFactory certificateFactory;

    @BeforeEach
    void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        signedJson = new String(VerifierTest.class.getResourceAsStream("/signed.json").readAllBytes());
        final var b64SignerCert = new String(VerifierTest.class.getResourceAsStream("/signer.cer").readAllBytes());
        final var b64TspCert = new String(VerifierTest.class.getResourceAsStream("/tsp.cer").readAllBytes());

        certificateFactory = CertificateFactory.getInstance("x.509", BouncyCastleProvider.PROVIDER_NAME);
        signerCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(Base64.decode(b64SignerCert)));
        tspCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(Base64.decode(b64TspCert)));
        final var trust = new CommonTrustedCertificateSource();
        trust.addCertificate(new CertificateToken(signerCertificate));
        verifier = new Verifier(trust);
    }

    @Test
    void verify() throws Exception {
        final var cpgJson = new String(VerifierTest.class.getResourceAsStream("/cpg.json").readAllBytes());
        final var result = verifier.verify(signedJson, false);

        //for test purposes
        assertEquals(1, result.signerChain().size());
        assertEquals(3, result.tspChain().size());
        assertEquals(cpgJson, result.payloadJson());

        //we use self-signed certificate for test purposes, should be true in production
        assertFalse(result.signerCertStatusValidated());

        //Avoid post-execution data manipulation
        // - make sure the CPG was created at expected date and time
        assertEquals(ZonedDateTime.parse("2026-05-08T06:18:03Z"), result.signedTimestamp());
        // - make sure we trust used tsp certificate
        assertTrue(result.tspChain().stream().anyMatch(tspCertificate::equals));

        //Avoid CPG substitution
        //make sure the signer certificate is the one we expected
        assertEquals(signerCertificate, reParseCertificate(result.signerChain().get(0)));

        //CPG contains expected values
        //Recompute and compare result and other important values
        final var env = DefaultComputationEnvironment.create();
        final var snapshot = env.fromJson(cpgJson);
        final var ctx = env.compute(snapshot);
        final var recomputedResult = (BigDecimal) ctx.findSingleVariable("result").getValue();
        assertEquals(BigDecimal.valueOf(-2), recomputedResult);
    }

    @Test
    void verifyFailsForPlainJson() {
        assertThrows(NonSignedContentException.class, () -> verifier.verify("{\"a\":\"b\"}", false));
    }

    @Test
    void verifyFailsForMultipleSignatures() {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var signatures = (ArrayNode) root.get("signatures");
        signatures.add(signatures.get(0).deepCopy());

        assertThrows(AmbiguousDataException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
    }

    @Test
    void verifyFailsForMultipleTimestamps() {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var sig = root.get("signatures").get(0);
        final var etsiU = (ArrayNode) sig.get("header").get("etsiU");

        final var etsiU0 = etsiU.get(0).asString();
        byte[] etsiU0Bytes = java.util.Base64.getUrlDecoder().decode(etsiU0);
        final var sigTstJson = (ObjectNode) mapper.readTree(etsiU0Bytes);
        final var tstTokens = (ArrayNode) sigTstJson.get("sigTst").get("tstTokens");
        tstTokens.add(tstTokens.get(0).deepCopy());

        etsiU.set(0, mapper.getNodeFactory().stringNode(
                java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(sigTstJson))));

        assertThrows(AmbiguousDataException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
    }

    @Test
    void verifyFailsForMissingTimestamp() {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var sig = root.get("signatures").get(0);
        ((ObjectNode) sig.get("header")).remove("etsiU");

        assertThrows(TimestampNotFoundException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
    }

    @Test
    void verifyFailsForMissingPayload() {
        final var mapper = new ObjectMapper();
        final var root = (ObjectNode) mapper.readTree(signedJson);
        root.remove("payload");

        var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
        assertEquals(InvalidSignatureException.Code.PAYLOAD_NOT_FOUND, ex.getCode());
    }

    @Test
    void verifyFailsForTamperedPayload() {
        final var mapper = new ObjectMapper();
        final var root = (ObjectNode) mapper.readTree(signedJson);
        final var orig = root.get("payload").asString();
        final var flipped = (orig.charAt(0) == 'e') ? 'f' : 'e';
        root.put("payload", flipped + orig.substring(1));

        final var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
        assertEquals(InvalidSignatureException.Code.PAYLOAD_TAMPERED, ex.getCode());
    }

    @Test
    void verifyFailsForTamperedTSP() {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var sig = root.get("signatures").get(0);
        final var etsiU = (ArrayNode) sig.get("header").get("etsiU");

        // etsiU[0] is base64url-encoded JSON containing sigTst.tstTokens[0].val (DER timestamp token)
        final var etsiU0 = etsiU.get(0).asString();
        final var etsiU0Bytes = java.util.Base64.getUrlDecoder().decode(etsiU0);
        final var sigTstJson = (ObjectNode) mapper.readTree(etsiU0Bytes);

        final var tstToken = (ObjectNode) sigTstJson.get("sigTst").get("tstTokens").get(0);
        final var val = tstToken.get("val").asString();
        // Decode the DER bytes and flip a byte in the TSA signature, which sits at the end of the CMS structure
        final var tstBytes = java.util.Base64.getDecoder().decode(val);
        tstBytes[tstBytes.length - 5] ^= (byte) 0xFF;
        tstToken.put("val", java.util.Base64.getEncoder().encodeToString(tstBytes));

        etsiU.set(0, mapper.getNodeFactory().stringNode(
                java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(sigTstJson))));

        final var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
        assertEquals(InvalidSignatureException.Code.TIMESTAMP_SIGNATURE_TAMPERED, ex.getCode());
    }

    @Test
    void verifyFailsForWrongTimestampType() {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var sig = root.get("signatures").get(0);
        final var etsiU = (ArrayNode) sig.get("header").get("etsiU");

        final var etsiU0 = etsiU.get(0).asString();
        final var etsiU0Bytes = java.util.Base64.getUrlDecoder().decode(etsiU0);
        final var sigTstJson = (ObjectNode) mapper.readTree(etsiU0Bytes);

        // Rename sigTst → arcTst so DSS classifies the token as ARCHIVE_TIMESTAMP
        final var sigTstValue = sigTstJson.remove("sigTst");
        sigTstJson.set("arcTst", sigTstValue);

        etsiU.set(0, mapper.getNodeFactory().stringNode(
                java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(sigTstJson))));

        final var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
        assertEquals(InvalidSignatureException.Code.TIMESTAMP_WRONG_TYPE, ex.getCode());
    }

    @Test
    void verifyFailsForTSPWithSubstitutedMessageImprint() throws Exception {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var sig = root.get("signatures").get(0);
        final var etsiU = (ArrayNode) sig.get("header").get("etsiU");

        final var etsiU0 = etsiU.get(0).asString();
        final var etsiU0Bytes = java.util.Base64.getUrlDecoder().decode(etsiU0);
        final var sigTstJson = mapper.readTree(etsiU0Bytes);
        final var tstTokenNode = (ObjectNode) sigTstJson.get("sigTst").get("tstTokens").get(0);
        final var existingDer = java.util.Base64.getDecoder().decode(tstTokenNode.get("val").asString());

        // Preserve the original messageImprint so the new token covers the same signature bytes
        final var existingToken = new TimeStampToken(new CMSSignedData(existingDer));
        final var hashAlgOid = existingToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm();
        final var imprintDigest = existingToken.getTimeStampInfo().getMessageImprintDigest();
        imprintDigest[0] = (byte) (imprintDigest[0] ^ 0xFF);

        // Build an untrusted TSA key/cert — not added to any trust source
        final var untrustedKp = SelfSignedGenerator.generateKeyPair();
        final var untrustedCert = SelfSignedGenerator.generateTsaSelfSigned(untrustedKp, "CN=untrusted-tsa", 1);

        final var dcp = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        final var contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(untrustedKp.getPrivate());
        final var signerInfoGen = new JcaSignerInfoGeneratorBuilder(dcp).build(contentSigner, untrustedCert);
        final var tsGen = new TimeStampTokenGenerator(
                signerInfoGen,
                dcp.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier("0.4.0.194112.1.1"));
        tsGen.addCertificates(new CollectionStore<>(java.util.List.of(new JcaX509CertificateHolder(untrustedCert))));

        final var reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        final var newToken = tsGen.generate(reqGen.generate(hashAlgOid, imprintDigest), BigInteger.ONE, new Date());
        tstTokenNode.put("val", java.util.Base64.getEncoder().encodeToString(newToken.getEncoded()));

        etsiU.set(0, mapper.getNodeFactory().stringNode(
                java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(sigTstJson))));

        var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
        assertEquals(InvalidSignatureException.Code.TIMESTAMP_IMPRINT_TAMPERED, ex.getCode());
    }

    @Test
    void verifyFailsForWrongTrustAnchor() throws Exception {
        final var kp = SelfSignedGenerator.generateKeyPair();
        final var cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=wrong", 1);
        final var wrongTrust = new CommonTrustedCertificateSource();
        wrongTrust.addCertificate(new CertificateToken(cert));

        final var ex = assertThrows(InvalidSignatureException.class, () -> new Verifier(wrongTrust).verify(signedJson, false));
        assertEquals(InvalidSignatureException.Code.SIGNATURE_NOT_VALID, ex.getCode());
    }

    @Test
    void verifyUntrustedTSP() throws Exception {
        final var mapper = new ObjectMapper();
        final var root = mapper.readTree(signedJson);
        final var sig = root.get("signatures").get(0);
        final var etsiU = (ArrayNode) sig.get("header").get("etsiU");

        final var etsiU0 = etsiU.get(0).asString();
        final var etsiU0Bytes = java.util.Base64.getUrlDecoder().decode(etsiU0);
        final var sigTstJson = mapper.readTree(etsiU0Bytes);
        final var tstTokenNode = (ObjectNode) sigTstJson.get("sigTst").get("tstTokens").get(0);
        final var existingDer = java.util.Base64.getDecoder().decode(tstTokenNode.get("val").asString());

        // Preserve the original messageImprint so the new token covers the same signature bytes
        final var existingToken = new TimeStampToken(new CMSSignedData(existingDer));
        final var hashAlgOid = existingToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm();
        final var imprintDigest = existingToken.getTimeStampInfo().getMessageImprintDigest();

        // Build an untrusted TSA key/cert — not added to any trust source
        final var untrustedKp = SelfSignedGenerator.generateKeyPair();
        final var untrustedCert = SelfSignedGenerator.generateTsaSelfSigned(untrustedKp, "CN=untrusted-tsa", 1);

        final var dcp = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        final var contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(untrustedKp.getPrivate());
        final var signerInfoGen = new JcaSignerInfoGeneratorBuilder(dcp).build(contentSigner, untrustedCert);
        final var tsGen = new TimeStampTokenGenerator(
                signerInfoGen,
                dcp.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier("0.4.0.194112.1.1"));
        tsGen.addCertificates(new CollectionStore<>(java.util.List.of(new JcaX509CertificateHolder(untrustedCert))));

        final var reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        final var newToken = tsGen.generate(reqGen.generate(hashAlgOid, imprintDigest), BigInteger.ONE, new Date());
        tstTokenNode.put("val", java.util.Base64.getEncoder().encodeToString(newToken.getEncoded()));

        etsiU.set(0, mapper.getNodeFactory().stringNode(
                java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(sigTstJson))));

        // - this is why it is important to explicitly check TSP certificate
        final var result = verifier.verify(mapper.writeValueAsString(root), false);
        assertFalse(result.tspChain().stream().anyMatch(tspCertificate::equals));
    }

    @Test
    void verifyFailsWithoutSigningCertificateStatusValidation() {
        final var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(signedJson));
        assertEquals(InvalidSignatureException.Code.SIGNER_CERT_STATUS_NOT_VALIDATED, ex.getCode());
    }

    private X509Certificate reParseCertificate(X509Certificate certificate) throws CertificateException {
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }
}
