//
// This file generated by rdl 1.5.2. Do not modify!
//

package com.yahoo.athenz.msd;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.yahoo.rdl.*;

//
// KubernetesNetworkPolicyPort - Kubernetes network policy port range
//
@JsonIgnoreProperties(ignoreUnknown = true)
public class KubernetesNetworkPolicyPort {
    public int port;
    public int endPort;
    public TransportPolicyProtocol protocol;

    public KubernetesNetworkPolicyPort setPort(int port) {
        this.port = port;
        return this;
    }
    public int getPort() {
        return port;
    }
    public KubernetesNetworkPolicyPort setEndPort(int endPort) {
        this.endPort = endPort;
        return this;
    }
    public int getEndPort() {
        return endPort;
    }
    public KubernetesNetworkPolicyPort setProtocol(TransportPolicyProtocol protocol) {
        this.protocol = protocol;
        return this;
    }
    public TransportPolicyProtocol getProtocol() {
        return protocol;
    }

    @Override
    public boolean equals(Object another) {
        if (this != another) {
            if (another == null || another.getClass() != KubernetesNetworkPolicyPort.class) {
                return false;
            }
            KubernetesNetworkPolicyPort a = (KubernetesNetworkPolicyPort) another;
            if (port != a.port) {
                return false;
            }
            if (endPort != a.endPort) {
                return false;
            }
            if (protocol == null ? a.protocol != null : !protocol.equals(a.protocol)) {
                return false;
            }
        }
        return true;
    }
}
