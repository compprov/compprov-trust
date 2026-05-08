package io.compprov.trust;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Convenience utility for generating self-signed EC key pairs and PKCS#12 keystores.
 * <p>
 * Self-signed certificates carry no revocation data, so {@link Verifier.VerifiedData#signerCertStatusValidated()}
 * will always be {@code false} for documents signed with them. For production use, prefer certificates
 * issued by a trusted Certificate Authority.
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
     * @throws OperatorCreationException if building the content signer fails
     * @throws CertificateException      if converting the certificate structure fails
     */
    public static X509Certificate generateSelfSigned(KeyPair keyPair, String dn, int days)
            throws OperatorCreationException, CertificateException {
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
     * @throws KeyStoreException        if the PKCS12 keystore type is unavailable
     * @throws CertificateException     if any certificate in the chain cannot be stored
     * @throws IOException              if the keystore cannot be serialized
     * @throws NoSuchAlgorithmException if the keystore integrity algorithm is unavailable
     */
    public static byte[] buildPkcs12(KeyPair keyPair, X509Certificate cert, char[] password)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        ks.setKeyEntry("key", keyPair.getPrivate(), password, new X509Certificate[]{cert});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, password);
        return baos.toByteArray();
    }
}
