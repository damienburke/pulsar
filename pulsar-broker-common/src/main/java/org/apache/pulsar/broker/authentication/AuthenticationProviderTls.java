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
package org.apache.pulsar.broker.authentication;

import static org.apache.pulsar.broker.authentication.AuthenticationProviderTls.TLS_AUTH_NAME;
import static org.apache.pulsar.broker.authentication.utils.CertificateUtils.stringToCertificate;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.metrics.AuthenticationMetrics;
import org.apache.pulsar.common.api.AuthData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authentication Provider for TLS.
 */
public class AuthenticationProviderTls implements AuthenticationProvider {

    public static String TLS_AUTH_NAME = "tls";

    public enum ErrorCode {
        UNKNOWN,
        INVALID_CERTS,
        NOT_YET_VALID_CERT,
        EXPIRED_CERTS,
        INVALID_CN, // invalid common name
    }

    @Override
    public void close() throws IOException {
        // noop
    }

    @Override
    public void initialize(ServiceConfiguration config) throws IOException {
        // noop
    }

    @Override
    public String getAuthMethodName() {
        return TLS_AUTH_NAME;
    }

    @Override
    public AuthenticationState newAuthState(AuthData authData, SocketAddress remoteAddress, SSLSession sslSession)
            throws AuthenticationException {
        return new TlsAuthenticationState(this, authData, remoteAddress, sslSession);
    }

    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String commonName = null;
        ErrorCode errorCode = ErrorCode.UNKNOWN;
        try {
            if (authData.hasDataFromTls()) {
                /**
                 * Maybe authentication type should be checked if it is an HTTPS session. However this check fails
                 * actually because authType is null.
                 *
                 * This check is not necessarily needed, because an untrusted certificate is not passed to
                 * HttpServletRequest.
                 *
                 * <code>
                 * if (authData.hasDataFromHttp()) {
                 *     String authType = authData.getHttpAuthType();
                 *     if (!HttpServletRequest.CLIENT_CERT_AUTH.equals(authType)) {
                 *         throw new AuthenticationException(
                 *              String.format( "Authentication type mismatch, Expected: %s, Found: %s",
                 *                       HttpServletRequest.CLIENT_CERT_AUTH, authType));
                 *     }
                 * }
                 * </code>
                 */

                // Extract CommonName
                // The format is defined in RFC 2253.
                // Example:
                // CN=Steve Kille,O=Isode Limited,C=GB
                Certificate[] certs = authData.getTlsCertificates();
                if (null == certs) {
                    errorCode = ErrorCode.INVALID_CERTS;
                    throw new AuthenticationException("Failed to get TLS certificates from client");
                }
                String distinguishedName = ((X509Certificate) certs[0]).getSubjectX500Principal().getName();
                for (String keyValueStr : distinguishedName.split(",")) {
                    String[] keyValue = keyValueStr.split("=", 2);
                    if (keyValue.length == 2 && "CN".equals(keyValue[0]) && !keyValue[1].isEmpty()) {
                        commonName = keyValue[1];
                        break;
                    }
                }
            }

            if (commonName == null) {
                errorCode = ErrorCode.INVALID_CN;
                throw new AuthenticationException("Client unable to authenticate with TLS certificate");
            }
            AuthenticationMetrics.authenticateSuccess(getClass().getSimpleName(), getAuthMethodName());
        } catch (AuthenticationException exception) {
            incrementFailureMetric(errorCode);
            throw exception;
        }
        return commonName;
    }

}

/**
 * Class representing the mTLS authentication state of a single connection.
 * <p>
 * The authentication of certificates is always done in one single stage - but as we want to support challenging the
 * client to refresh expired credentials (in this case - client certificates) - we provide and configure this
 * <code>AuthenticationState</code> implementation. For more details, see
 * the PIP-55 documentation on refreshing authentication credentials:
 * <a href="https://github.com/apache/pulsar/wiki/PIP-55%3A-Refresh-Authentication-Credentials">
 * PIP-55: Refresh-Authentication-Credentials</a>.
 */
final class TlsAuthenticationState implements AuthenticationState {

    private static final Logger log = LoggerFactory.getLogger(TlsAuthenticationState.class.getName());
    private final AuthenticationProviderTls provider;
    private AuthenticationDataSource authenticationDataSource;
    private X509Certificate clientCertificate;
    private final SocketAddress remoteAddress;
    private final SSLSession sslSession;
    private long expiration;
    private String role;

    public TlsAuthenticationState(final AuthenticationProviderTls provider, final AuthData authData,
                                  final SocketAddress remoteAddress, final SSLSession sslSession)
            throws AuthenticationException {
        this.provider = provider;
        this.remoteAddress = remoteAddress;
        this.sslSession = sslSession;
        this.authenticate(authData);
    }

    @Override
    public String getAuthRole() {
        return this.role;
    }

    /**
     * Perform the authentication. Also sets the {@link #role}, which is used by upstream pulsar authorization checks.
     *
     * @param authData contains the bytes of the credential being used for authentication - which in this case is a
     *                 client certificate.
     * @return <code>null</code> (only authentication that is mutual would require a non-null value). For more details,
     * see the PIP-30 documentation on mutual authentication changes:
     * <a href="https://github.com/apache/pulsar/wiki/PIP-30%3A-change-authentication-provider-API-to-support-mutual
     * -authentication">PIP-30: Change Authentication Provider API to Support Mutual Authentication</a>.
     * @throws AuthenticationException if cert is not valid. If cert is just expired, no exception is thrown, and
     *                                 {@link #expiration} is just set.
     */
    public AuthData authenticate(final AuthData authData) throws AuthenticationException {

        final String cert = certificateFromAuthData(authData);
        this.authenticationDataSource = new AuthenticationDataCommand(cert, this.remoteAddress, this.sslSession);

        this.role = this.provider.authenticate(this.authenticationDataSource);

        this.clientCertificate = stringToCertificate(cert);

        try {
            // initial connection validated by sun.security.ssl types
            this.clientCertificate.checkValidity();
        } catch (CertificateExpiredException e) {
            incrementFailureMetric(AuthenticationProviderTls.ErrorCode.EXPIRED_CERTS);
            log.info("Expired client certificate", e);
            throw new AuthenticationException("Expired client certificate: " + e.getMessage());
        } catch (CertificateNotYetValidException e) {
            incrementFailureMetric(AuthenticationProviderTls.ErrorCode.NOT_YET_VALID_CERT);
            log.warn("Invalid client certificate", e);
            throw new AuthenticationException("Invalid client certificate: " + e.getMessage());
        } catch (Exception e) {
            incrementFailureMetric(AuthenticationProviderTls.ErrorCode.INVALID_CERTS);
            log.warn("Unexpected error parsing the client certificate", e);
            throw new AuthenticationException("Unexpected client certificate error: " + e.getMessage());
        }


        if (this.clientCertificate.getNotAfter() != null) {
            this.expiration = this.clientCertificate.getNotAfter().getTime();
        } else {
            // Disable expiration
            this.expiration = Long.MAX_VALUE;
        }

        return null;
    }

    public AuthenticationDataSource getAuthDataSource() {
        return this.authenticationDataSource;
    }

    public boolean isComplete() {
        // The authentication of certificates is always done in one single stage, so once certificate is set, it is
        // "complete"
        return clientCertificate != null;
    }

    public boolean isExpired() {
        return this.expiration < System.currentTimeMillis();
    }

    private static String certificateFromAuthData(final AuthData authData) {
        return new String(authData.getBytes(), StandardCharsets.UTF_8);
    }

    private void incrementFailureMetric(Enum<?> errorCode) {
        AuthenticationMetrics.authenticateFailure(getClass().getSimpleName(), TLS_AUTH_NAME, errorCode);
    }
}
