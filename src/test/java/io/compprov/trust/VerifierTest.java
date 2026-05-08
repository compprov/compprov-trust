package io.compprov.trust;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import io.compprov.core.DefaultComputationEnvironment;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifierTest {

    @Test
    public void verify() throws Exception {

        final var cpgJson = new String(VerifierTest.class.getResourceAsStream("/cpg.json").readAllBytes());
        String signed = new String(VerifierTest.class.getResourceAsStream("/signed.json").readAllBytes());
        String b64Cert = new String(VerifierTest.class.getResourceAsStream("/cert.cer").readAllBytes());
        X509Certificate x509Cert = (X509Certificate) CertificateFactory.getInstance("x.509")
                .generateCertificate(new ByteArrayInputStream(Base64.decode(b64Cert)));

        TrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(new CertificateToken(x509Cert));
        final var verifier = new Verifier(trustedCertificateSource);
        final var verifiedData = verifier.verify(signed);
        Assertions.assertNotNull(verifiedData.signedTimestamp());
        Assertions.assertFalse(verifiedData.signerCertStatusValidated());
        Assertions.assertEquals(1, verifiedData.signerChain().size());
        Assertions.assertEquals(3, verifiedData.tspChain().size());
        Assertions.assertEquals(cpgJson, verifiedData.payloadJson());

        final var env = new DefaultComputationEnvironment();
        final var snapshot = env.fromJson(cpgJson);
        final var ctx = env.compute(snapshot);
        BigDecimal recomputedResult = (BigDecimal) ctx.findSingleVariable("result").getValue();
        Assertions.assertEquals(BigDecimal.valueOf(-2), recomputedResult);
    }
}
