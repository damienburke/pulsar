package org.apache.pulsar.client.impl.auth;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.function.Supplier;
import javax.naming.AuthenticationException;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.pulsar.common.api.AuthData;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class AuthenticationDataTlsTest {

    BigInteger certificateSerialNumber;

    AuthenticationDataTls authenticationDataTls;

    @Test
    public void testInstantiate_withStreamProviders() {

        // Verify tls data
        final Certificate[] tlsCertificates = authenticationDataTls.getTlsCertificates();
        assertEquals(1, tlsCertificates.length);
        assertEquals(certificateSerialNumber, ((X509Certificate) tlsCertificates[0]).getSerialNumber());
        assertTrue(authenticationDataTls.hasDataForTls());
        assertNotNull(authenticationDataTls.getTlsPrivateKey());

        // Verify command data
        assertNotNull(authenticationDataTls.getCommandData());
        assertTrue(authenticationDataTls.hasDataFromCommand());
    }

    @Test
    public void testAuthenticate() throws CertificateException, AuthenticationException {

        final AuthData authData = mock(AuthData.class);

        final AuthData result = authenticationDataTls.authenticate(authData);

        byte[] derCertificate = authenticationDataTls.getTlsCertificates()[0].getEncoded();
        String pemEncoded = Base64.getEncoder().encodeToString(derCertificate);
        byte[] bytes = pemEncoded.getBytes(StandardCharsets.UTF_8);

        assertEquals(AuthData.of(bytes), result);
        verifyNoInteractions(authData);
    }

    @BeforeTest
    public void setup() throws CertificateException, IOException, OperatorCreationException, KeyManagementException {
        Pair<byte[], byte[]> privateKeyAndCertPair = generatePrivateKeyAndCert();

        final Supplier<ByteArrayInputStream> certStreamProvider =
                () -> new ByteArrayInputStream(privateKeyAndCertPair.getLeft());
        final Supplier<ByteArrayInputStream> keyStreamProvider =
                () -> new ByteArrayInputStream(privateKeyAndCertPair.getRight());

        authenticationDataTls =
                new AuthenticationDataTls(certStreamProvider, keyStreamProvider, null);

    }

    /**
     * To verify <code>AuthenticationDataTls</code> works as expected, a "real" private key and
     * certificates are provided - as opposed to mocks. One reason for this is the dependency of
     * <code>AuthenticationDataTls</code> on <code>SecurityUtility</code> static methods. While this interaction
     * <i>could</i> also be mocked, it is useful to have a unit test that exercises both
     * <code>AuthenticationDataTls</code> and <code>SecurityUtility</code>. Furthermore, this approach enables verifying
     * that the certs and private keys can be parsed (decoded, etc.) as expected.
     */
    private Pair<byte[], byte[]> generatePrivateKeyAndCert()
            throws CertificateException, IOException, OperatorCreationException {

        // Issuer and Subject DN
        final X500Name issuerName = new X500Name("CN=Self-Signed Certificate");
        final X500Name subjectName = new X500Name("CN=my-role");

        // Expires
        final long now = System.currentTimeMillis();
        final Date startDate = new Date(now);
        final Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // Valid for 1 year

        // Certificate serial number
        certificateSerialNumber = BigInteger.valueOf(new SecureRandom().nextInt());

        final KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerName, certificateSerialNumber, startDate, endDate, subjectName,
                        publicKeyInfo);

        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

        final Certificate certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(certificateBuilder.build(contentSigner));

        // Convert private key to PEM format
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.close();
        final String pemString = writer.toString();

        return Pair.of(certificate.getEncoded(), pemString.getBytes(StandardCharsets.UTF_8));
    }
}