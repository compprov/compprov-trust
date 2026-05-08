package io.compprov.trust;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Utility for generating self-signed EC key pairs and PKCS#12 keystores.
 * <p>
 * Intended for local development and testing only. In production, use certificates
 * issued by a trusted Certificate Authority so that
 * {@link Verifier.VerifiedData#signerCertStatusValidated()} returns {@code true}.
 */
public class SelfSignedGenerator {

    /**
     * Generates a new EC key pair on the {@code secp256r1} curve.
     *
     * @return a freshly generated {@link KeyPair}
     * @throws NoSuchAlgorithmException           if EC is not supported by the JVM
     * @throws InvalidAlgorithmParameterException if {@code secp256r1} is not available
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Issues a self-signed X.509 certificate for the given key pair.
     *
     * @param keyPair the key pair to certify
     * @param dn      X.500 distinguished name, e.g. {@code CN=my-service,O=Example}
     * @param days    certificate validity period in days from now
     * @return a self-signed {@link X509Certificate}
     * @throws Exception if certificate generation fails
     */
    public static X509Certificate generateSelfSigned(KeyPair keyPair, String dn, int days) throws Exception {
        final var now = System.currentTimeMillis();
        final var startDate = new Date(now);
        final var endDate = new Date(now + TimeUnit.DAYS.toMillis(days));

        final var dnName = new X500Name(dn);
        final var certSerialNumber = new BigInteger(Long.toString(now));

        final var contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        final var certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Packages the given key pair and certificate into a PKCS#12 keystore.
     *
     * @param keyPair  the key pair whose private key is stored
     * @param cert     the corresponding certificate
     * @param password keystore protection password
     * @return PKCS#12 keystore bytes suitable for passing to {@link Signer#loadPkcs12}
     * @throws Exception if keystore creation fails
     */
    public static byte[] buildPkcs12(KeyPair keyPair, X509Certificate cert, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        ks.setKeyEntry("key", keyPair.getPrivate(), password, new X509Certificate[]{cert});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, password);
        return baos.toByteArray();
    }
}
