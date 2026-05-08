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
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class VerifierTest {

    private String signedJson;
    private Verifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        signedJson = new String(VerifierTest.class.getResourceAsStream("/signed.json").readAllBytes());
        String b64Cert = new String(VerifierTest.class.getResourceAsStream("/cert.cer").readAllBytes());
        X509Certificate x509Cert = (X509Certificate) CertificateFactory.getInstance("x.509")
                .generateCertificate(new ByteArrayInputStream(Base64.decode(b64Cert)));
        TrustedCertificateSource trust = new CommonTrustedCertificateSource();
        trust.addCertificate(new CertificateToken(x509Cert));
        verifier = new Verifier(trust);
    }

    @Test
    void verify() throws Exception {
        final var cpgJson = new String(VerifierTest.class.getResourceAsStream("/cpg.json").readAllBytes());
        final var result = verifier.verify(signedJson);

        assertEquals(ZonedDateTime.parse("2026-05-08T06:18:03Z[UTC]"), result.signedTimestamp());
        assertFalse(result.signerCertStatusValidated());
        assertEquals(1, result.signerChain().size());
        assertEquals(3, result.tspChain().size());
        assertEquals(cpgJson, result.payloadJson());

        final var env = new DefaultComputationEnvironment();
        final var snapshot = env.fromJson(cpgJson);
        final var ctx = env.compute(snapshot);
        BigDecimal recomputedResult = (BigDecimal) ctx.findSingleVariable("result").getValue();
        assertEquals(BigDecimal.valueOf(-2), recomputedResult);
    }

    @Test
    void verifyFailsForPlainJson() {
        assertThrows(NonSignedContentException.class, () -> verifier.verify("{\"a\":\"b\"}"));
    }

    @Test
    void verifyFailsForTamperedPayload() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = (ObjectNode) mapper.readTree(signedJson);
        String orig = root.get("payload").asText();
        char flipped = (orig.charAt(0) == 'e') ? 'f' : 'e';
        root.put("payload", flipped + orig.substring(1));

        assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root)));
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

        assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root)));
    }

    @Test
    void verifyFailsForWrongTrustAnchor() throws Exception {
        var kp = SelfSignedGenerator.generateKeyPair();
        var cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=wrong", 1);
        TrustedCertificateSource wrongTrust = new CommonTrustedCertificateSource();
        wrongTrust.addCertificate(new CertificateToken(cert));

        assertThrows(InvalidSignatureException.class, () -> new Verifier(wrongTrust).verify(signedJson));
    }
}
