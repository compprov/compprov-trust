package io.compprov.trust;

import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Offline TSP for tests. DSS refuses LT-level augmentation when every chain is self-signed,
 * so the TSA certificate is issued by a throwaway test CA.
 */
final class LocalTsp {

    private LocalTsp() {
    }

    static KeyEntityTSPSource create() throws Exception {
        final var caKp = SelfSignedGenerator.generateKeyPair();
        final var caCert = SelfSignedGenerator.generateSelfSigned(caKp, "CN=compprov-test-ca", 1);
        final var tsaKp = SelfSignedGenerator.generateKeyPair();

        final var now = System.currentTimeMillis();
        final var builder = new JcaX509v3CertificateBuilder(
                caCert, BigInteger.valueOf(now), new Date(now), new Date(now + TimeUnit.DAYS.toMillis(1)),
                new X500Principal("CN=compprov-test-tsa"), tsaKp.getPublic());
        builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        final var contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKp.getPrivate());
        final var tsaCert = new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));

        final var tsp = new KeyEntityTSPSource(tsaKp.getPrivate(), tsaCert, List.of(tsaCert, caCert));
        tsp.setTsaPolicy("1.2.3.4");
        return tsp;
    }
}
