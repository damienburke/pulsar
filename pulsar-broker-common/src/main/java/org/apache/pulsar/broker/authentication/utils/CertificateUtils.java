package org.apache.pulsar.broker.authentication.utils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateUtils.class);
    private static final Base64.Decoder decoder = Base64.getDecoder();

    private static final CertificateFactory certFactory;

    static {
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Converts the given String input
     *
     * @param input a Base64 encoded
     * @return a <code>X509Certificate</code> representing the given input.
     * @throws IllegalArgumentException if given bad data.
     */
    public static X509Certificate stringToCertificate(final String input) {
        try {
            byte[] decodedCert = decoder.decode(input);
            final X509Certificate cert =
                    (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCert));
            if (LOG.isDebugEnabled()) {
                LOG.info("Parsed the cert {}", cert);
            }
            return cert;
        } catch (Exception e) {
            LOG.warn("Failed to parse the given cert", e);
            throw new IllegalArgumentException(e);
        }
    }
}
