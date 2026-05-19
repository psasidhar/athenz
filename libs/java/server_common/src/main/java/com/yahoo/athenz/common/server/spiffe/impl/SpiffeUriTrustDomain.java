/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.spiffe.impl;

import com.yahoo.athenz.common.server.spiffe.SpiffeUriValidator;
import org.eclipse.jetty.util.StringUtil;

/**
 * Trust Domain implementation of SpiffeUriValidator interface. This class validates the SPIFFE URI
 * with the following formats:
 * Service Cert URI: spiffe://<trustDomain>/ns/<namespace>/sa/<domainName>.<serviceName>
 *     Example: spiffe://athenz.io/ns/prod/sa/athenz.api
 * Role Cert URI: spiffe://<trustDomain>/ns/<domainName>/ra/<roleName>
 *     Example: spiffe://athenz.io/ns/athenz/ra/readers
 */
public class SpiffeUriTrustDomain implements SpiffeUriValidator {

    private static final String SPIFFE_DEFAULT_NAMESPACE = "default";

    private static final String SPIFFE_PROP_TRUST_DOMAIN = "athenz.zts.spiffe_trust_domain";
    private static final String SPIFFE_TRUST_DOMAIN = System.getProperty(SPIFFE_PROP_TRUST_DOMAIN, "athenz.io");

    /**
     * Service Cert URI: two accepted forms.
     *
     * Form 1 (Approach A — cluster infra, dotted SA):
     *   spiffe://<trustDomain>/ns/<namespace>/sa/<domainName>.<serviceName>
     *   Example: spiffe://athenz.io/ns/istio-system/sa/athenz.k8s.nonprod.istiod
     *
     * Form 2 (Approach C hybrid — application workloads, dot-free SA):
     *   spiffe://<trustDomain>/ns/<namespace>/sa/<serviceName>
     *   Example: spiffe://athenz.io/ns/calypso-nonprod/sa/curl
     *   Accepted only when namespace.replace("-", ".") equals domainName, ensuring the
     *   namespace round-trips to the claimed Athenz domain.
     */
    @Override
    public boolean validateServiceCertUri(String spiffeUri, String domainName, String serviceName, String namespace) {
        final String ns = StringUtil.isEmpty(namespace) ? SPIFFE_DEFAULT_NAMESPACE : namespace;

        // Form 1: spiffe://{trustDomain}/ns/{namespace}/sa/{domain}.{service}
        final String form1Uri = String.format("spiffe://%s/ns/%s/sa/%s.%s", SPIFFE_TRUST_DOMAIN,
                ns, domainName, serviceName);
        if (form1Uri.equalsIgnoreCase(spiffeUri)) {
            return true;
        }

        // Form 2: spiffe://{trustDomain}/ns/{namespace}/sa/{service}
        // Valid only when the namespace encodes the claimed domain (hyphen→dot round-trip).
        if (ns.replace("-", ".").equalsIgnoreCase(domainName)) {
            final String form2Uri = String.format("spiffe://%s/ns/%s/sa/%s", SPIFFE_TRUST_DOMAIN,
                    ns, serviceName);
            if (form2Uri.equalsIgnoreCase(spiffeUri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Role Cert URI: spiffe://<trustDomain>/ns/<domainName>/ra/<roleName>
     *     Example: spiffe://athenz.io/ns/athenz/ra/readers
     */
    @Override
    public boolean validateRoleCertUri(String spiffeUri, String domainName, String roleName) {
        final String reqUri = String.format("spiffe://%s/ns/%s/ra/%s", SPIFFE_TRUST_DOMAIN,
                domainName, roleName);
        return reqUri.equalsIgnoreCase(spiffeUri);
    }
}
