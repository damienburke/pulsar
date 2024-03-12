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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class CertificateUtilsTest {
    @DataProvider
    public Object[][] badCertInput() {
        return new Object[][]{
                {"bad m'ky"},
                {""},
                {null}
        };
    }

    @Test(dataProvider = "badCertInput")
    public void stringToCertificate_whenBadInput(String input) {
        assertThrows(IllegalArgumentException.class, () -> CertificateUtils.stringToCertificate(input));
    }

    @Test
    public void stringToCertificate() {

        final String input =
                "MIIDbDCCAlSgAwIBAgIUPt3hkiR6141syNLffdxm6d5fIVIwDQYJKoZIhvcNAQELBQAwRTEMMAoGA1UEBhMDSVJFMQ0wCwYDVQQKEwRBY21lMSYwJAYDVQQDEx1QdWxzYXIgSW50ZXJtZWRpYXRlIEF1dGhvcml0eTAeFw0yNDAzMTExNDI5MTNaFw0yNDAzMTExNDMwMTNaMBIxEDAOBgNVBAMTB215LXJvbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBhapFBUZ5uLpsni/31lRZtI2apcc/0fkYLXAZ1A3QEfEXnMvhGJZimkW3IPo+IPDOh+dpf5Cz2SN3CU/u47/rJfO0jTYRqh8UOLNcH4b6cQ3fzWUVauRab13IeYubPSfnIS0oLyRSfMfFHBx1ojr4kvV6fw4IYr1LJYkP+qYNIHIcKpmI/fk6wGJcrxPH4IaBRvr1Z3OaEBpp31TpqZ8uib+RmSJtWmprTzg9iBz5AhIY+h5nWctOsa1+8Bc6ybshBgcExbCvbBx3dbtBGrLmtDmXXAOrPMK3mhjJE3j+fVVIHGCn0BWZKnvXZbS9sFCtNHhcE0ZZ/iLGeM8iELmDAgMBAAGjgYYwgYMwDgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU0FnJeAsPwXWQ9iwsfFE3MiL7RwcwHwYDVR0jBBgwFoAUnXWIUbNovm8NlOe7W4vA6ETEozkwEgYDVR0RBAswCYIHbXktcm9sZTANBgkqhkiG9w0BAQsFAAOCAQEAWER2USD2iEW1ZlyiHnZiGii3iP7adD+kPSM2rCItmbiUmdRDFXu0+mIDVf1z5/JtDrHf5SYqyBQTIh6G3i32xn7MCnlTHQLUQ3iiDbAi5IQSvSfADCOxNG3czMGzk+m8NcjyFzdqRX6Uh5cxddun4naGMX2HIHwaeLQgYcD30zEZYpxvNoGZfk5Ui92w3GRxdN43glh02GOQumCKvGbbe9ILFc2dRIrQagM4WK5MOIHON50xR+kQlKRNW6LU2YnrUK4KGHfi715lFphQwDoQkDkttWGkR0izxHhNKjAEuzGGhE0tYVYLlUqJz9rEcBGamkvNK20PWS7wiKUC6v/mow==";

        X509Certificate x509Certificate = CertificateUtils.stringToCertificate(input);

        LocalDateTime localDateTime = LocalDateTime.of(2024, 3, 11, 14, 30, 13);
        ZoneId zoneId = ZoneId.of("GMT");
        ZonedDateTime zonedDateTime = localDateTime.atZone(zoneId);
        Date expectedDate = Date.from(zonedDateTime.toInstant());

        assertEquals(x509Certificate.getNotAfter(), expectedDate);
        assertEquals(x509Certificate.getIssuerX500Principal().getName(),
                "CN=Pulsar Intermediate Authority,O=Acme,C=IRE");
        assertEquals(x509Certificate.getSubjectX500Principal().getName(), "CN=my-role");
    }
}