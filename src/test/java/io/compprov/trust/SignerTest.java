package io.compprov.trust;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import io.compprov.trust.exception.AmbiguousDataException;
import io.compprov.trust.exception.ContentExtractionException;
import io.compprov.trust.exception.ExternalServiceException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class SignerTest {

    @Disabled("Calls external TSP service")
    @Test
    void sign() throws Exception {
        final var cpgJson = new String(SignerTest.class.getResourceAsStream("/cpg.json").readAllBytes());

        final var kp = SelfSignedGenerator.generateKeyPair();
        final var cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=compprov-test", 365);
        final var p12 = SelfSignedGenerator.buildPkcs12(kp, cert, "123".toCharArray());

        final var sigToken = Signer.loadPkcs12(new ByteArrayInputStream(p12), "123".toCharArray());
        final var trustStore = Verifier.loadPkcs12(new ByteArrayInputStream(p12), "123".toCharArray());

        final var signer = new Signer(sigToken, "http://timestamp.digicert.com", Optional.of(trustStore));
        final var signed = signer.signJson(cpgJson, true);
        System.out.println("Signed: " + signed);
    }

    @Test
    void signFailsForEmptyKeystore() throws Exception {
        final var ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        final var baos = new ByteArrayOutputStream();
        ks.store(baos, "test".toCharArray());

        final var token = Signer.loadPkcs12(new ByteArrayInputStream(baos.toByteArray()), "test".toCharArray());
        final var signer = new Signer(token, "http://not-needed.example.com", Optional.empty());

        assertThrows(ContentExtractionException.class, () -> signer.signJson("{}"));
    }

    @Test
    void signFailsForMultipleKeys() throws Exception {
        final var kp1 = SelfSignedGenerator.generateKeyPair();
        final var kp2 = SelfSignedGenerator.generateKeyPair();
        final var cert1 = SelfSignedGenerator.generateSelfSigned(kp1, "CN=key1", 1);
        final var cert2 = SelfSignedGenerator.generateSelfSigned(kp2, "CN=key2", 1);

        final var pass = "pass".toCharArray();
        final var ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("key1", kp1.getPrivate(), pass, new X509Certificate[]{cert1});
        ks.setKeyEntry("key2", kp2.getPrivate(), pass, new X509Certificate[]{cert2});
        final var baos = new ByteArrayOutputStream();
        ks.store(baos, pass);

        final var token = Signer.loadPkcs12(new ByteArrayInputStream(baos.toByteArray()), pass);
        final var signer = new Signer(token, "http://not-needed.example.com", Optional.empty());

        assertThrows(AmbiguousDataException.class, () -> signer.signJson("{}"));
    }

    @Test
    void signFailsForBrokenTsp() throws Exception {
        final var kp = SelfSignedGenerator.generateKeyPair();
        final var cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=test", 1);
        final var p12 = SelfSignedGenerator.buildPkcs12(kp, cert, "pass".toCharArray());

        final var token = Signer.loadPkcs12(new ByteArrayInputStream(p12), "pass".toCharArray());
        final TSPSource brokenTsp = (digestAlgorithm, digest) -> { throw new DSSException("TSP unavailable"); };
        final var signer = new Signer(token, brokenTsp, Optional.empty());

        assertThrows(ExternalServiceException.class, () -> signer.signJson("{}", true));
    }
}
