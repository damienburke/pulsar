/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pulsar.broker.authentication.utils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CertificateUtils {
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
     * Converts the given String input to an X509Certificate.
     *
     * @param input a Base64 encoded, String formatted X509Certificate.
     * @return a <code>X509Certificate</code> representing the given input.
     * @throws IllegalArgumentException if given bad data.
     */
    public static X509Certificate stringToCertificate(final String input) {
        try {
            byte[] decodedCert = decoder.decode(input);
            final X509Certificate cert =
                    (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCert));
            if (log.isDebugEnabled()) {
                log.info("Parsed the cert {}", cert);
            }
            return cert;
        } catch (Exception e) {
            log.warn("Failed to parse the given cert", e);
            throw new IllegalArgumentException(e);
        }
    }
}
