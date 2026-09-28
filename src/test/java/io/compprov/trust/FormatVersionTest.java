package io.compprov.trust;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import io.compprov.trust.exception.InvalidSignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class FormatVersionTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private KeyPair signerKp;
    private KeyEntityTSPSource tsp;
    private String signed;
    private Verifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        final var cpgJson = new String(FormatVersionTest.class.getResourceAsStream("/cpg.json").readAllBytes());
        final var pass = "pass".toCharArray();

        signerKp = SelfSignedGenerator.generateKeyPair();
        final var signerCert = SelfSignedGenerator.generateSelfSigned(signerKp, "CN=compprov-test", 1);
        final var p12 = SelfSignedGenerator.buildPkcs12(signerKp, signerCert, pass);
        tsp = LocalTsp.create();

        final var trust = Verifier.loadPkcs12(new ByteArrayInputStream(p12), pass);
        signed = Signer.builder(Signer.loadPkcs12(new ByteArrayInputStream(p12), pass))
                .tspSource(tsp).trustSource(trust).allowMissingRevocationData(true).build()
                .signJson(cpgJson);
        verifier = Verifier.builder(trust).allowMissingRevocationData(true).build();
    }

    @Test
    void signerWritesV1ContentType() throws Exception {
        assertEquals(Signer.CONTENT_TYPE_V1, protectedHeader(signed).get("cty").asString());
        verifier.verify(signed);
    }

    @Test
    void verifyAcceptsLegacyDocumentWithoutContentType() throws Exception {
        verifier.verify(resign(h -> h.remove("cty")));
    }

    @Test
    void verifyAcceptsFullMediaTypeForm() throws Exception {
        verifier.verify(resign(h -> h.put("cty", "Application/" + Signer.CONTENT_TYPE_V1)));
    }

    @Test
    void verifyRejectsUnknownFormatVersion() throws Exception {
        final var v2 = resign(h -> h.put("cty", "vnd.compprov.trust.v2+json"));

        final var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(v2));
        assertEquals(InvalidSignatureException.Code.UNSUPPORTED_FORMAT, ex.getCode());
    }

    @Test
    void verifyReportsTamperingNotFormatWhenContentTypeChangedWithoutResigning() throws Exception {
        final var root = (ObjectNode) mapper.readTree(signed);
        final var sig = (ObjectNode) root.get("signatures").get(0);
        final var header = protectedHeader(signed);
        header.put("cty", "vnd.compprov.trust.v2+json");
        sig.put("protected", Base64.getUrlEncoder().withoutPadding().encodeToString(mapper.writeValueAsBytes(header)));

        final var ex = assertThrows(InvalidSignatureException.class, () -> verifier.verify(mapper.writeValueAsString(root)));
        assertEquals(InvalidSignatureException.Code.SIGNED_DATA_TAMPERED, ex.getCode());
    }

    private ObjectNode protectedHeader(String doc) {
        final var sig = mapper.readTree(doc).get("signatures").get(0);
        return (ObjectNode) mapper.readTree(Base64.getUrlDecoder().decode(sig.get("protected").asString()));
    }

    /**
     * Rewrites the protected header, re-signs it with the signer key and re-timestamps the new signature value,
     * producing a document that is valid apart from whatever the header change means.
     */
    private String resign(Consumer<ObjectNode> headerMutator) throws Exception {
        final var b64u = Base64.getUrlEncoder().withoutPadding();
        final var root = (ObjectNode) mapper.readTree(signed);
        final var sig = (ObjectNode) root.get("signatures").get(0);

        final var header = protectedHeader(signed);
        headerMutator.accept(header);
        final var protectedB64 = b64u.encodeToString(mapper.writeValueAsBytes(header));

        final var ecdsa = Signature.getInstance("SHA256withECDSAinP1363Format");
        ecdsa.initSign(signerKp.getPrivate());
        ecdsa.update((protectedB64 + "." + root.get("payload").asString()).getBytes(US_ASCII));
        final var sigValueB64 = b64u.encodeToString(ecdsa.sign());
        sig.put("protected", protectedB64);
        sig.put("signature", sigValueB64);

        final var imprint = MessageDigest.getInstance("SHA-256").digest(sigValueB64.getBytes(US_ASCII));
        final var token = tsp.getTimeStampResponse(DigestAlgorithm.SHA256, imprint);
        final var etsiU = (ArrayNode) sig.get("header").get("etsiU");
        for (int i = 0; i < etsiU.size(); i++) {
            final var component = (ObjectNode) mapper.readTree(Base64.getUrlDecoder().decode(etsiU.get(i).asString()));
            if (component.has("sigTst")) {
                ((ObjectNode) component.get("sigTst").get("tstTokens").get(0))
                        .put("val", Base64.getEncoder().encodeToString(token.getBytes()));
                etsiU.set(i, mapper.getNodeFactory().stringNode(b64u.encodeToString(mapper.writeValueAsBytes(component))));
            }
        }
        return mapper.writeValueAsString(root);
    }
}
