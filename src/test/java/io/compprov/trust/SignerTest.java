package io.compprov.trust;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;

public class SignerTest {

    @Disabled("Disabled to not call external services")
    @Test
    public void sign() throws Exception {

        final var cpgJson = new String(VerifierTest.class.getResourceAsStream("/cpg.json").readAllBytes());

        final var kp = SelfSignedGenerator.generateKeyPair();
        final var cert = SelfSignedGenerator.generateSelfSigned(kp, "CN=compprov-test", 365);
        final var p12 = SelfSignedGenerator.buildPkcs12(kp, cert, "123".toCharArray());

        final var sigToken = Signer.loadPkcs12(new ByteArrayInputStream(p12), "123".toCharArray());
        final var trustStore = Verifier.loadPkcs12(new ByteArrayInputStream(p12), "123".toCharArray());

        final var signer = new Signer(sigToken, "http://timestamp.digicert.com", trustStore);
        final var signed = signer.signJson(cpgJson, true);
        System.out.println("Signed: " + signed);
    }
}
