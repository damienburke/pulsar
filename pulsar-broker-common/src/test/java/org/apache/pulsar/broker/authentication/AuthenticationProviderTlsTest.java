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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import java.io.IOException;
import java.net.SocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.common.api.AuthData;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class AuthenticationProviderTlsTest {

    private final AuthenticationProviderTls tlsAuthProvider = new AuthenticationProviderTls();

    @AfterMethod(alwaysRun = true)
    public void tearDown() throws Exception {
        this.tlsAuthProvider.close();
    }

    @Test
    public void testInitialize() throws IOException {
        // initialize not implemented for tls, and this test just verifies initialize can be safely called.
        ServiceConfiguration serviceConfig = mock(ServiceConfiguration.class);
        this.tlsAuthProvider.initialize(serviceConfig);
        verifyNoInteractions(serviceConfig);
    }

    @Test
    public void testGetAuthMethodName() {
        assertEquals(tlsAuthProvider.getAuthMethodName(), "tls");
    }

    @Test
    public void testNewAuthState() throws AuthenticationException {

        AuthData authData = mock(AuthData.class);
        SocketAddress remoteAddress = mock(SocketAddress.class);
        SSLSession sslSession = mock(SSLSession.class);

        AuthenticationState result = tlsAuthProvider.newAuthState(authData, remoteAddress, sslSession);

        assertEquals(result.isExpired(), false);
    }

    @Test(dataProvider = "validPrincipals")
    public void testAuthenticate(final String x500PrincipalName, final String expectedRole)
            throws AuthenticationException {

        AuthenticationDataCommand authDataCommand = mock(AuthenticationDataCommand.class);
        X509Certificate clientCertificate = mock(X509Certificate.class);
        X500Principal x500Principal = mock(X500Principal.class);

        when(authDataCommand.hasDataFromTls()).thenReturn(true);
        when(authDataCommand.getTlsCertificates()).thenReturn(new Certificate[]{
                clientCertificate
        });
        when(clientCertificate.getSubjectX500Principal()).thenReturn(x500Principal);
        when(x500Principal.getName()).thenReturn(x500PrincipalName);

        assertEquals(tlsAuthProvider.authenticate(authDataCommand), expectedRole);
    }

    @Test(dataProvider = "invalidPrincipals")
    public void testAuthenticate_givenBadX500PrincipalName(final String x500PrincipalName) {

        AuthenticationDataCommand authDataCommand = mock(AuthenticationDataCommand.class);
        X509Certificate clientCertificate = mock(X509Certificate.class);
        X500Principal x500Principal = mock(X500Principal.class);

        when(authDataCommand.hasDataFromTls()).thenReturn(true);
        when(authDataCommand.getTlsCertificates()).thenReturn(new Certificate[]{
                clientCertificate
        });
        when(clientCertificate.getSubjectX500Principal()).thenReturn(x500Principal);
        when(x500Principal.getName()).thenReturn(x500PrincipalName);

        assertThrows(AuthenticationException.class, () -> tlsAuthProvider.authenticate(authDataCommand));
    }

    @Test
    public void testAuthenticate_givenNoTlsData() {

        AuthenticationDataCommand authDataCommand = mock(AuthenticationDataCommand.class);
        when(authDataCommand.hasDataFromTls()).thenReturn(false);

        assertThrows(AuthenticationException.class, () -> tlsAuthProvider.authenticate(authDataCommand));
    }

    @Test
    public void testAuthenticate_givenNoCertificates() {

        AuthenticationDataCommand authDataCommand = mock(AuthenticationDataCommand.class);
        when(authDataCommand.hasDataFromTls()).thenReturn(true);
        when(authDataCommand.getTlsCertificates()).thenReturn(null);

        assertThrows(AuthenticationException.class, () -> tlsAuthProvider.authenticate(authDataCommand));
    }

    @DataProvider
    public Object[][] validPrincipals() {
        return new Object[][]{
                {"CN=x500PrincipalName", "x500PrincipalName"},
                {"cn=not_expected,CN=x500PrincipalName2", "x500PrincipalName2"}
        };
    }

    @DataProvider
    public Object[][] invalidPrincipals() {
        return new Object[][]{
                {" CN=x500PrincipalName"}, // white-space before "cn"
                {"cn=x500PrincipalName"}, // lower-case "cn"
                {""}, // empty "cn"
                {"DN=x500PrincipalName"}, // missing a "cn"
        };
    }
}

