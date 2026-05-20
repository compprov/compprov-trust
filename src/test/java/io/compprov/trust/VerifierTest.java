package io.compprov.trust;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import io.compprov.core.DefaultComputationEnvironment;
import io.compprov.trust.exception.InvalidSignatureException;
import io.compprov.trust.exception.NonSignedContentException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

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
        String b64SignerCert = new String(VerifierTest.class.getResourceAsStream("/signer.cer").readAllBytes());
        String b64TspCert = new String(VerifierTest.class.getResourceAsStream("/tsp.cer").readAllBytes());

        certificateFactory = CertificateFactory.getInstance("x.509", BouncyCastleProvider.PROVIDER_NAME);
        signerCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(Base64.decode(b64SignerCert)));
        tspCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(Base64.decode(b64TspCert)));
        TrustedCertificateSource trust = new CommonTrustedCertificateSource();
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
        assertEquals(tspCertificate, reParseCertificate(result.tspChain().get(0)));

        //Avoid CPG substitution
        //make sure the signer certificate is the one we expected
        assertEquals(signerCertificate, reParseCertificate(result.signerChain().get(0)));

        //CPG contains expected values
        //Recompute and compare result and other important values
        final var env = new DefaultComputationEnvironment();
        final var snapshot = env.fromJson(cpgJson);
        final var ctx = env.compute(snapshot);
        BigDecimal recomputedResult = (BigDecimal) ctx.findSingleVariable("result").getValue();
        assertEquals(BigDecimal.valueOf(-2), recomputedResult);
    }

    @Test
    void verifyFailsForPlainJson() {
        assertThrows(NonSignedContentException.class, () -> verifier.verify("{\"a\":\"b\"}", false));
    }

    @Test
    void verifyFailsForTamperedPayload() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = (ObjectNode) mapper.readTree(signedJson);
        String orig = root.get("payload").asText();
        char flipped = (orig.charAt(0) == 'e') ? 'f' : 'e';
        root.put("payload", flipped + orig.substring(1));

        assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
    }

    @Test
    void verifyFailsForTamperedSignature() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = (ObjectNode) mapper.readTree(signedJson);
        ObjectNode sig = (ObjectNode) ((ArrayNode) root.get("signatures")).get(0);
        String origSig = sig.get("signature").asText();
        // Change the first character — it is in a full 4-char group so the decoded bytes definitely differ.
        // Changing only the last char of a 2-char trailing group does not work: those bits are base64 padding
        // and are discarded when decoding, leaving the signature bytes identical.
        char first = origSig.charAt(0);
        char flipped = (first == 'w') ? 'x' : 'w';
        sig.put("signature", flipped + origSig.substring(1));

        assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
    }

    @Test
    void verifyFailsForTamperedTSP() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = (ObjectNode) mapper.readTree(signedJson);
        ObjectNode sig = (ObjectNode) ((ArrayNode) root.get("signatures")).get(0);
        ArrayNode etsiU = (ArrayNode) sig.get("header").get("etsiU");

        // etsiU[0] is base64url-encoded JSON containing sigTst.tstTokens[0].val (DER timestamp token)
        String etsiU0 = etsiU.get(0).asText();
        byte[] etsiU0Bytes = java.util.Base64.getUrlDecoder().decode(etsiU0);
        ObjectNode sigTstJson = (ObjectNode) mapper.readTree(etsiU0Bytes);

        ObjectNode tstToken = (ObjectNode) ((ArrayNode) sigTstJson.get("sigTst").get("tstTokens")).get(0);
        String val = tstToken.get("val").asText();
        // Decode the DER bytes and flip a byte in the TSA signature, which sits at the end of the CMS structure
        byte[] tstBytes = java.util.Base64.getDecoder().decode(val);
        tstBytes[tstBytes.length - 5] ^= 0xFF;
        tstToken.put("val", java.util.Base64.getEncoder().encodeToString(tstBytes));

        etsiU.set(0, mapper.getNodeFactory().textNode(
                java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(sigTstJson))));

        assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root), false));
    }

    @Test
    void verifyFailsForWrongTrustAnchor() throws Exception {
        var kp = SelfSignedGenerator.generateKeyPair();
        var cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=wrong", 1);
        TrustedCertificateSource wrongTrust = new CommonTrustedCertificateSource();
        wrongTrust.addCertificate(new CertificateToken(cert));

        assertThrows(InvalidSignatureException.class, () -> new Verifier(wrongTrust).verify(signedJson, false));
    }

    @Test
    void verifyFailsWithoutSigningCertificateStatusValidation() throws Exception {
        assertThrows(InvalidSignatureException.class, () -> verifier.verify(signedJson));
    }

    private X509Certificate reParseCertificate(X509Certificate certificate) throws CertificateException {
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }
}
