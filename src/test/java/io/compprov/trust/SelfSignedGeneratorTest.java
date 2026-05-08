package io.compprov.trust;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

public class SelfSignedGeneratorTest {

    @Test
    void generateKeyPair_returnsEcKeyPair() throws Exception {
        KeyPair kp = SelfSignedGenerator.generateKeyPair();

        assertNotNull(kp);
        assertEquals("EC", kp.getPublic().getAlgorithm());
        assertEquals("EC", kp.getPrivate().getAlgorithm());
    }

    @Test
    void generateSelfSigned_producesValidCertificate() throws Exception {
        KeyPair kp = SelfSignedGenerator.generateKeyPair();
        X509Certificate cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=test-service", 30);

        assertNotNull(cert);
        assertEquals("CN=test-service", cert.getSubjectX500Principal().getName());
        cert.checkValidity();
        cert.verify(kp.getPublic()); // verifies the cert is self-signed with this key pair
    }

    @Test
    void buildPkcs12_roundtripAsSignerToken() throws Exception {
        KeyPair kp = SelfSignedGenerator.generateKeyPair();
        X509Certificate cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=roundtrip", 1);
        char[] password = "secret".toCharArray();
        byte[] p12Bytes = SelfSignedGenerator.buildPkcs12(kp, cert, password);

        assertNotNull(p12Bytes);
        assertTrue(p12Bytes.length > 0);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12Bytes), password);
        assertTrue(ks.isKeyEntry("key"));

        var token = Signer.loadPkcs12(new ByteArrayInputStream(p12Bytes), password);
        assertEquals(1, token.getKeys().size());
        assertNotNull(token.getKeys().get(0).getCertificate());
    }
}
