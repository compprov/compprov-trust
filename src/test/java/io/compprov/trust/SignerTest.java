package io.compprov.trust;

import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import io.compprov.trust.exception.AmbiguousDataException;
import io.compprov.trust.exception.ContentExtractionException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

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

        final var signer = new Signer(sigToken, "http://timestamp.digicert.com", trustStore);
        final var signed = signer.signJson(cpgJson, true);
        System.out.println("Signed: " + signed);
    }

    @Test
    void signFailsForEmptyKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, "test".toCharArray());

        Pkcs12SignatureToken token = Signer.loadPkcs12(new ByteArrayInputStream(baos.toByteArray()), "test".toCharArray());
        Signer signer = new Signer(token, "http://not-needed.example.com", null);

        assertThrows(ContentExtractionException.class, () -> signer.signJson("{}", false));
    }

    @Test
    void signFailsForMultipleKeys() throws Exception {
        var kp1 = SelfSignedGenerator.generateKeyPair();
        var kp2 = SelfSignedGenerator.generateKeyPair();
        var cert1 = SelfSignedGenerator.generateSelfSigned(kp1, "CN=key1", 1);
        var cert2 = SelfSignedGenerator.generateSelfSigned(kp2, "CN=key2", 1);

        char[] pass = "pass".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("key1", kp1.getPrivate(), pass, new X509Certificate[]{cert1});
        ks.setKeyEntry("key2", kp2.getPrivate(), pass, new X509Certificate[]{cert2});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, pass);

        Pkcs12SignatureToken token = Signer.loadPkcs12(new ByteArrayInputStream(baos.toByteArray()), pass);
        Signer signer = new Signer(token, "http://not-needed.example.com", null);

        assertThrows(AmbiguousDataException.class, () -> signer.signJson("{}", false));
    }
}
