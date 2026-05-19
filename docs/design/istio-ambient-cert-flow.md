# Istio Ambient Mode: Certificate Issuance Flow

Cluster: `gke_core-secplatcluster-s_us-east5_personal-mtcl-use5`
Trust domain: `athenz.cloud`

---

## Component Map

| Component | Namespace | Role |
|-----------|-----------|------|
| `istio-cni-node` DaemonSet | `istio-system` | Installs iptables rules in pod netns to redirect traffic to ztunnel |
| `ztunnel` DaemonSet | `istio-system` | L4 mTLS proxy; holds workload SVIDs in memory on behalf of pods |
| `istiod` Deployment | `istio-system` | xDS control plane; proxies workload SVID requests from ztunnel to istio-csr |
| `cert-manager-istio-csr` Deployment | `kube-addons` | gRPC CA bridge; turns SVID requests from istiod into cert-manager CertificateRequests |
| **cert-manager controller** | `kube-addons` | Framework that watches CertificateRequest objects and coordinates approval + signing |
| **approver-policy** | `kube-addons` | cert-manager plugin; auto-approves CertificateRequests matching the `allow-athenz-istio-issuer` policy |
| **athenz-issuer** | `kube-addons` | cert-manager external issuer; signs approved CertificateRequests by calling ZTS |
| `AthenzClusterIssuer` `athenz-istio-issuer` | cluster-scoped | Points athenz-issuer at the ZTS endpoint |
| `waypoint` Deployment | `msd-stage` | L7 Envoy proxy per namespace; enforces AuthorizationPolicy for traffic to services in that namespace |
| Athenz ZTS | external | Certificate authority; validates SA token + GCP OIDC issuer; signs and returns cert |

> **Where is cert-manager in `ztunnel → istiod → istio-csr → CertificateRequest → athenz-issuer → ZTS`?**
> cert-manager is the layer *around* `CertificateRequest`. It provides the CRD, watches for
> new requests, routes them to approver-policy (approval) and to athenz-issuer (signing).
> cert-manager does not touch cryptographic content — it orchestrates the lifecycle.
> approver-policy and athenz-issuer are separate pods, both cert-manager plugins.

---

## Certificate Landscape

| Certificate | Mechanism | Secret / location | Status |
|-------------|-----------|-------------------|--------|
| `istiod-tls` | cert-manager `Certificate` → athenz-issuer → ZTS | Secret `istiod-tls`, `istio-system` | ✅ READY |
| ztunnel node cert | cert-manager `Certificate` → athenz-issuer → ZTS | Secret `ztunnel-athenz-tls`, `istio-system` | ✅ READY |
| istio-csr serving cert | cert-manager `Certificate` → athenz-issuer → ZTS | Secret `cert-manager-istio-csr-athenz-tls`, `kube-addons` | ✅ READY |
| Workload SVIDs | ztunnel gRPC → istiod → istio-csr → CertificateRequest → athenz-issuer → ZTS | ztunnel in-memory, one per pod | ✅ READY |
| Waypoint SVID | waypoint gRPC → istio-csr → CertificateRequest → athenz-issuer → ZTS | waypoint in-memory | ✅ READY |

---

## Section 1: istiod and ztunnel Certificates

istiod and ztunnel each need their own X.509 certificate before the mesh can function.
These are **not** fetched via gRPC — they are provisioned by cert-manager `Certificate`
objects defined in `istio-infra/`. cert-manager controller reconciles them, athenz-issuer
signs them via ZTS, and the result lands in a Kubernetes Secret that the pod mounts.

### 1a. istiod TLS Serving Certificate

istiod exposes xDS on port 15012. ztunnel and istio-csr connect to this port over TLS;
both verify istiod's certificate against the mesh trust bundle. The cert is defined in
`istio-infra/istiod-cert.yaml`.

```
    cert-manager           approver-policy       athenz-issuer        Kubernetes API       Athenz ZTS          istiod
       (CM)                    (AP)                  (AI)                 (K8S)              (ZTS)              (ISO)
         │                      │                     │                     │                  │                  │
         │  [watches Certificate: istio-infra/istiod-cert.yaml              │                  │                  │
         │   issuerRef=athenz-istio-issuer  secretName=istiod-tls]          │                  │                  │
         │                      │                     │                     │                  │                  │
         │  1. Generate EC key pair and CSR           │                     │                  │                  │
         │     CN:      athenz.k8s.nonprod.istiod     │                     │                  │                  │
         │     URI SAN: spiffe://athenz.cloud/        │                     │                  │                  │
         │              ns/istio-system/sa/           │                     │                  │                  │
         │              athenz.k8s.nonprod.istiod     │                     │                  │                  │
         │     DNS SAN: istiod.istio-system.svc       │                     │                  │                  │
         │              istiod.istio-system.svc.cluster.local               │                  │                  │
         │                      │                     │                     │                  │                  │
         │  2. Create CertificateRequest istiod-1     │                     │                  │                  │
         ├──────────────────────────────────────────────────────────────── ►│                  │                  │
         │                      │                     │                     │                  │                  │
         │               3. Watch CertificateRequest istiod-1               │                  │                  │
         │               ◄───────────────────────────────────────────────── │                  │                  │
         │                      │                     │                     │                  │                  │
         │               4. Evaluate policy: issuerRef ok, URIs spiffe/* ok │                  │                  │
         │                      │                     │                     │                  │                  │
         │               5. Patch Approved=True        │                     │                  │                  │
         │               ─────────────────────────────────────────────────► │                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │              6. Watch CertificateRequest istiod-1 (Approved=True)               │
         │                      │              ◄───────────────────────────┤                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │              7. Parse SPIFFE URI from CSR │                  │                  │
         │                      │                     │  ns=istio-system sa=athenz.k8s.nonprod.istiod             │
         │                      │                     │  -> domain=athenz.k8s.nonprod service=istiod              │
         │                      │                     │                     │                  │                  │
         │                      │              8. TokenRequest for SA athenz.k8s.nonprod.istiod│                  │
         │                      │                     ├────────────────────►│                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │                     │◄────────────────────┤                  │                  │
         │                      │                     │  SA token           │                  │                  │
         │                      │                     │  sub: system:serviceaccount:           │                  │
         │                      │                     │       istio-system:athenz.k8s.nonprod.istiod              │
         │                      │                     │  iss: GKE OIDC endpoint                │                  │
         │                      │                     │  aud: ZTS URL       │                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │              9. POST /zts/v1/instance     │                  │                  │
         │                      │                     │  domain=athenz.k8s.nonprod service=istiod                 │
         │                      │                     │  provider=sys.k8s.gcp-us-east5         │                  │
         │                      │                     │  csr.CN:      athenz.k8s.nonprod.istiod│                  │
         │                      │                     │  csr.URI SAN: spiffe://athenz.cloud/   │                  │
         │                      │                     │               ns/istio-system/sa/      │                  │
         │                      │                     │               athenz.k8s.nonprod.istiod│                  │
         │                      │                     │  csr.DNS SAN: istiod.istio-system.svc(.cluster.local)     │
         │                      │                     │  identityToken: SA token above         │                  │
         │                      │                     ├─────────────────────────────────────── ►│                  │
         │                      │                     │                     │                  │                  │
         │                      │                     │                     │           10. Validate SA token      │
         │                      │                     │                     │               Validate GCP OIDC issuer
         │                      │                     │                     │               Validate CN == domain.service
         │                      │                     │                     │               Validate DNS SANs      │
         │                      │                     │                     │               Sign cert:             │
         │                      │                     │                     │                 Issuer:  Yahoo Athenz CA
         │                      │                     │                     │                 Subject: CN=athenz.k8s.nonprod.istiod
         │                      │                     │                     │                 URI SAN: spiffe://athenz.cloud/
         │                      │                     │                     │                          ns/istio-system/sa/
         │                      │                     │                     │                          athenz.k8s.nonprod.istiod
         │                      │                     │                     │                 DNS SAN: istiod.istio-system.svc(.cluster.local)
         │                      │                     │                     │                  │                  │
         │                      │                     │◄──────────────────────────────────────┤                  │
         │                      │                     │  11. signed cert + chain               │                  │
         │                      │                     │                     │                  │                  │
         │                      │              12. Patch CertificateRequest.status.certificate │                  │
         │                      │                     ├────────────────────►│                  │                  │
         │                      │                     │                     │                  │                  │
         │                      │                     │              13. cert-manager writes Secret istiod-tls    │
         │                      │                     │                     │  tls.crt / tls.key / ca.crt         │
         │                      │                     │                     │                  │                  │
         │                      │                     │                     │          14. istiod mounts Secret istiod-tls
         │                      │                     │                     │◄──────────────────────────────────── │
         │                      │                     │                     │               serves xDS on port 15012
```

### 1b. ztunnel Node Certificate

ztunnel needs its own identity cert to authenticate to istiod (xDS connection) and to
other ztunnel nodes (HBONE tunnel setup). Defined in `istio-infra/ztunnel-cert.yaml`.
The flow is identical to istiod's — cert-manager Certificate → athenz-issuer → ZTS.

```
    cert-manager           approver-policy       athenz-issuer        Kubernetes API       Athenz ZTS           ztunnel
       (CM)                    (AP)                  (AI)                 (K8S)              (ZTS)               (ZT)
         │                      │                     │                     │                  │                   │
         │  [watches Certificate: istio-infra/ztunnel-cert.yaml             │                  │                   │
         │   issuerRef=athenz-istio-issuer  secretName=ztunnel-athenz-tls]  │                  │                   │
         │                      │                     │                     │                  │                   │
         │  1. Generate EC key pair and CSR           │                     │                  │                   │
         │     CN:      athenz.k8s.nonprod.ztunnel    │                     │                  │                   │
         │     URI SAN: spiffe://athenz.cloud/ns/istio-system/sa/athenz.k8s.nonprod.ztunnel    │                   │
         │     DNS SAN: ztunnel.istio-system.svc.cluster.local (+ instanceId SAN)              │                   │
         │                      │                     │                     │                  │                   │
         │  2. Create CertificateRequest ztunnel-1    │                     │                  │                   │
         ├──────────────────────────────────────────────────────────────── ►│                  │                   │
         │                      │                     │                     │                  │                   │
         │               3. Watch and approve ztunnel-1                     │                  │                   │
         │               ◄───────────────────────────────────────────────── │                  │                   │
         │               ─────────────────────────────────────────────────► │                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              4. Watch CertificateRequest ztunnel-1 (Approved=True)               │
         │                      │              ◄───────────────────────────┤                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              5. TokenRequest for SA athenz.k8s.nonprod.ztunnel                   │
         │                      │                     ├────────────────────►│                  │                   │
         │                      │                     │◄────────────────────┤                  │                   │
         │                      │                     │  SA token: sub=system:serviceaccount:istio-system:athenz.k8s.nonprod.ztunnel
         │                      │                     │                     │                  │                   │
         │                      │              6. POST /zts/v1/instance     │                  │                   │
         │                      │                     │  domain=athenz.k8s.nonprod  service=ztunnel                │
         │                      │                     │  csr.CN:      athenz.k8s.nonprod.ztunnel                   │
         │                      │                     │  csr.URI SAN: spiffe://athenz.cloud/ns/istio-system/sa/athenz.k8s.nonprod.ztunnel
         │                      │                     │  csr.DNS SAN: ztunnel.istio-system.svc.cluster.local + instanceId SAN
         │                      │                     │  identityToken: SA token               │                   │
         │                      │                     ├─────────────────────────────────────── ►│                   │
         │                      │                     │                     │                  │                   │
         │                      │                     │                     │           7. Validate and sign cert   │
         │                      │                     │                     │               Issuer:  Yahoo Athenz CA│
         │                      │                     │                     │               Subject: CN=athenz.k8s.nonprod.ztunnel
         │                      │                     │                     │               URI SAN: spiffe://athenz.cloud/ns/istio-system/sa/athenz.k8s.nonprod.ztunnel
         │                      │                     │                     │               DNS SAN: ztunnel.istio-system.svc.cluster.local
         │                      │                     │◄──────────────────────────────────────┤                   │
         │                      │                     │  8. signed cert + chain                │                   │
         │                      │                     │                     │                  │                   │
         │                      │              9. Write Secret ztunnel-athenz-tls              │                   │
         │                      │                     ├────────────────────►│                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │                     │             10. ztunnel mounts Secret ztunnel-athenz-tls   │
         │                      │                     │                     │◄──────────────────────────────────── │
         │                      │                     │                     │               connects to istiod:15012 (xDS)
         │                      │                     │                     │               HBONE tunnel mTLS to peer ztunnel nodes
```

> **Note:** ztunnel's cert in Secret `ztunnel-athenz-tls` is its **node agent identity**.
> This is separate from the **workload SVIDs** ztunnel fetches per-pod via gRPC to istiod
> (covered in Section 3).

---

## Section 2: istio-csr Serving Certificate

istio-csr is the gRPC CA bridge that istiod forwards workload SVID requests to. It exposes
port 6443 (gRPC TLS). istiod connects to it and verifies its certificate.

### Why this required code changes to istio-csr

istio-csr v0.16 generates its own serving CSR internally using `pkiutil.GenCSR()`, which
produces a **DNS-only CSR** — no SPIFFE URI SAN. athenz-issuer requires a SPIFFE URI to
identify the Athenz domain and service and call ZTS. Without a URI SAN, signing fails with
`"failed to get service account or in namespace : resource name may not be empty"`.

The fix: two new flags that tell istio-csr to **skip generating its own CSR** and instead
load its serving cert from a pre-provisioned cert-manager Certificate Secret.

#### Code changes (`csi-driver-athenz/istio-csr/`)

**`pkg/tls/tls.go`** — core change
```
Added:
  Options.ServingCertificateSecretName   string
  Options.ServingCertificateSecretNamespace string
  Provider.k8sClient                     kubernetes.Interface

New method loadFromSecret():
  reads tls.crt / tls.key / ca.crt from the named Secret
  parses and returns the tls.Certificate directly

Modified fetchCertificate():
  if ServingCertificateSecretName != "":
      return loadFromSecret()   // ← new path
  else:
      // original GenCSR() path (unchanged)
```

**`cmd/app/options/options.go`** — two new CLI flags
```
--serving-certificate-secret-name       string
--serving-certificate-secret-namespace  string

Also: relaxed the DNS-names validation check — previously it rejected
startup if --serving-dns-names was empty, which conflicts with Secret mode
where DNS SANs are embedded in the pre-provisioned cert.
```

**`cmd/app/app.go`** — wire k8s client into tls.Provider
```
Passes the existing k8s client (cl) into tls.NewProvider() so that
loadFromSecret() can call the Secrets API.
```

**`pkg/certmanager/certmanager.go`** — mutex deadlock fix
```
HasIssuerConfig() was acquiring Lock() (write lock) while only reading
activeIssuerRef. Sign() holds RLock() for the full duration of certificate
signing. Under concurrent workload SVID load, HasIssuerConfig() (called
on every readiness probe) blocked on the write lock held by Sign() →
readiness probe timeout → pod NotReady.

Fix: Lock()/Unlock() → RLock()/RUnlock() in HasIssuerConfig().
```

### Sequence Diagram: istio-csr Serving Certificate

```
    cert-manager           approver-policy       athenz-issuer        Kubernetes API       Athenz ZTS          istio-csr
       (CM)                    (AP)                  (AI)                 (K8S)              (ZTS)              (ICSR)
         │                      │                     │                     │                  │                   │
         │  [watches Certificate: istio-infra/istio-csr-cert.yaml           │                  │                   │
         │   issuerRef=athenz-istio-issuer  secretName=cert-manager-istio-csr-athenz-tls]      │                   │
         │                      │                     │                     │                  │                   │
         │  1. Generate EC key pair and CSR           │                     │                  │                   │
         │     CN:      athenz.k8s.nonprod.cert-manager-istio-csr           │                  │                   │
         │     URI SAN: spiffe://athenz.cloud/ns/kube-addons/sa/athenz.k8s.nonprod.cert-manager-istio-csr         │
         │     DNS SAN: cert-manager-istio-csr.kube-addons.svc              │                  │                   │
         │              cert-manager-istio-csr.kube-addons.svc.cluster.local│                  │                   │
         │              (+ instanceId SAN)            │                     │                  │                   │
         │                      │                     │                     │                  │                   │
         │  2. Create CertificateRequest istio-csr-cert-1                   │                  │                   │
         ├──────────────────────────────────────────────────────────────── ►│                  │                   │
         │                      │                     │                     │                  │                   │
         │               3. Watch and approve istio-csr-cert-1              │                  │                   │
         │               ◄───────────────────────────────────────────────── │                  │                   │
         │               ─────────────────────────────────────────────────► │                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              4. Watch CertificateRequest istio-csr-cert-1 (Approved=True)        │
         │                      │              ◄───────────────────────────┤                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              5. Parse SPIFFE URI: ns=kube-addons sa=athenz.k8s.nonprod.cert-manager-istio-csr
         │                      │                     │  -> domain=athenz.k8s.nonprod service=cert-manager-istio-csr
         │                      │                     │                     │                  │                   │
         │                      │              6. TokenRequest for SA athenz.k8s.nonprod.cert-manager-istio-csr    │
         │                      │                     ├────────────────────►│                  │                   │
         │                      │                     │◄────────────────────┤                  │                   │
         │                      │                     │  SA token           │                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │              7. POST /zts/v1/instance     │                  │                   │
         │                      │                     │  domain=athenz.k8s.nonprod  service=cert-manager-istio-csr │
         │                      │                     │  csr.CN:      athenz.k8s.nonprod.cert-manager-istio-csr    │
         │                      │                     │  csr.URI SAN: spiffe://athenz.cloud/ns/kube-addons/sa/athenz.k8s.nonprod.cert-manager-istio-csr
         │                      │                     │  csr.DNS SAN: cert-manager-istio-csr.kube-addons.svc(.cluster.local)
         │                      │                     │  identityToken: SA token               │                   │
         │                      │                     ├─────────────────────────────────────── ►│                   │
         │                      │                     │                     │                  │                   │
         │                      │                     │                     │           8. Validate and sign cert   │
         │                      │                     │                     │               Issuer:  Yahoo Athenz CA│
         │                      │                     │                     │               Subject: CN=athenz.k8s.nonprod.cert-manager-istio-csr
         │                      │                     │                     │               URI SAN: spiffe://athenz.cloud/ns/kube-addons/sa/athenz.k8s.nonprod.cert-manager-istio-csr
         │                      │                     │                     │               DNS SAN: cert-manager-istio-csr.kube-addons.svc(.cluster.local)
         │                      │                     │◄──────────────────────────────────────┤                   │
         │                      │                     │  9. signed cert + chain                │                   │
         │                      │                     │                     │                  │                   │
         │                      │             10. Write Secret cert-manager-istio-csr-athenz-tls                   │
         │                      │                     ├────────────────────►│                  │                   │
         │                      │                     │                     │                  │                   │
         │                      │                     │             11. istio-csr starts with flags:               │
         │                      │                     │                     │  serving-certificate-secret-name=cert-manager-istio-csr-athenz-tls
         │                      │                     │                     │  serving-certificate-secret-namespace=kube-addons
         │                      │                     │                     │  (loadFromSecret() instead of GenCSR())
         │                      │                     │                     │◄──────────────────────────────────── │
         │                      │                     │                     │                  │  tls.crt / tls.key / ca.crt
         │                      │                     │                     │                  │                   │
         │                      │                     │                     │                  │  12. Serve gRPC on port 6443
         │                      │                     │                     │                  │      using Athenz-signed cert
         │                      │                     │                     │                  │      istiod connects and verifies
         │                      │                     │                     │                  │      against Athenz CA trust bundle
```

---

## Section 3: Workload SVIDs

Once the control plane is up (istiod cert + ztunnel node cert + istio-csr serving cert all
ready), ztunnel can request per-pod SVIDs for workloads in the ambient mesh. This path goes
through gRPC, not cert-manager `Certificate` objects — the requests are ephemeral and
generated on demand by ztunnel as pods join the mesh.

### SA Naming: Approach A

Workload SAs use fully-qualified names: `{athenz-domain}.{athenz-service}`.
signer.go splits on the last dot to extract domain and service:
- SA `calypso.nonprod.curl` → domain=`calypso.nonprod`, service=`curl`
- SA `msd.stage.httpbin` → domain=`msd.stage`, service=`httpbin`

```
  Workload Pod      ztunnel          istiod         istio-csr      cert-manager    athenz-issuer   Kubernetes API    Athenz ZTS
    (POD)            (ZT)            (ISO)           (ICSR)          (CM/AP)           (AI)            (K8S)            (ZTS)
       │               │               │               │               │                 │               │                │
       │  [Pod scheduled on node       │               │               │                 │               │                │
       │   NS label: istio.io/dataplane-mode=ambient   │               │                 │               │                │
       │   SA: calypso.nonprod.curl]   │               │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │  1. pod joins ambient mesh (istio-cni iptables redirect)       │                 │               │                │
       ├──────────────►│               │               │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │  2. Generate EC P-256 key pair on behalf of pod│                 │               │                │
       │               │     CSR Subject: (empty - SPIFFE spec)         │                 │               │                │
       │               │     CSR URI SAN: spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl│               │
       │               │     CSR DNS SAN: (none)        │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │  3. gRPC IstioCertificateService.CreateCertificate               │               │                │
       │               │     Bearer: ztunnel SA token (SA=athenz.k8s.nonprod.ztunnel, aud=istio-ca)       │                │
       │               │     ImpersonatedIdentity: spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl
       │               ├──────────────►│               │               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │        4. TokenReview: validate ztunnel Bearer token             │               │                │
       │               │               ├───────────────────────────────────────────────── ►│               │                │
       │               │               │◄───────────────────────────────────────────────── │               │                │
       │               │               │  ok: authenticated as athenz.k8s.nonprod.ztunnel  │               │                │
       │               │               │               │               │                 │               │                │
       │               │        5. ClusterNodeAuthorizer: ztunnel is trusted node agent, workload pod on same node ok
       │               │               │               │               │                 │               │                │
       │               │        6. gRPC CreateCertificate forwarded (ImpersonatedIdentity preserved, no token)
       │               │               ├──────────────►│               │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │               │        7. ClusterNodeAuthorizer: node-workload co-location ok   │                │
       │               │               │               │               │                 │               │                │
       │               │               │        8. Create CertificateRequest istio-csr-xxxx               │                │
       │               │               │               │  spec.request: CSR (Subject empty, URI SAN only, no DNS SANs)    │
       │               │               │               │  spec.issuerRef: athenz-istio-issuer              │                │
       │               │               │               │  annotation istio.cert-manager.io/identities:     │                │
       │               │               │               │    spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl
       │               │               │               │  (no SA token - trust fully consumed above)       │                │
       │               │               │               ├──────────────►│                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │               │               │        9. approver-policy: policy match ok, Approved=True         │
       │               │               │               │               │                 │               │                │
       │               │               │               │              10. Read SPIFFE URI from annotation  │                │
       │               │               │               │               │  ns=calypso-nonprod  sa=calypso.nonprod.curl
       │               │               │               │               │  SA has dots -> split on last dot │                │
       │               │               │               │               │  -> domain=calypso.nonprod  service=curl          │
       │               │               │               │               │                 │               │                │
       │               │               │               │              11. TokenRequest for SA calypso.nonprod.curl         │
       │               │               │               │               │                 ├──────────────►│                │
       │               │               │               │               │                 │◄──────────────┤                │
       │               │               │               │               │                 │  SA token (GCP OIDC-signed, 1h TTL)
       │               │               │               │               │                 │  sub: system:serviceaccount:calypso-nonprod:calypso.nonprod.curl
       │               │               │               │               │                 │  iss: GKE OIDC endpoint         │
       │               │               │               │               │                 │  aud: ZTS URL  │                │
       │               │               │               │               │                 │  (SA-bound, no pod claim)       │
       │               │               │               │               │                 │               │                │
       │               │               │               │              12. POST /zts/v1/instance            │                │
       │               │               │               │               │  domain=calypso.nonprod  service=curl             │
       │               │               │               │               │  provider=sys.k8s.gcp-us-east5  namespace=calypso-nonprod
       │               │               │               │               │  csr: Subject empty, URI SAN only, no DNS SANs    │
       │               │               │               │               │  identityToken: SA token          │                │
       │               │               │               │               │                 ├───────────────────────────────► │
       │               │               │               │               │                 │               │                │
       │               │               │               │               │                 │        13. Validate SA token: sub, aud, iss ok
       │               │               │               │               │                 │            GCP OIDC issuer check ok
       │               │               │               │               │                 │            CSR CN empty - skip (patch 1)
       │               │               │               │               │                 │            DNS SANs none + URI SAN is spiffe - bypass DNS validation (patch 2)
       │               │               │               │               │                 │            Sign cert:
       │               │               │               │               │                 │              Issuer:  Yahoo Athenz CA
       │               │               │               │               │                 │              Subject: (empty)
       │               │               │               │               │                 │              URI SAN: spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl
       │               │               │               │               │                 │              Validity: 7 days
       │               │               │               │               │                 │◄─────────────────────────────── │
       │               │               │               │               │                 │  14. signed cert + chain        │
       │               │               │               │               │                 │               │                │
       │               │               │               │              15. Patch CertificateRequest.status.certificate      │
       │               │               │               │               │◄────────────────┤               │                │
       │               │               │               │               │  Ready=True     │               │                │
       │               │               │◄──────────────┤               │                 │               │                │
       │               │◄──────────────┤               │               │                 │               │                │
       │               │  16. gRPC response: signed cert chain          │                 │               │                │
       │               │               │               │               │                 │               │                │
       │               │  17. Store SPIFFE cert in memory keyed by pod identity           │               │                │
       │               │      Used for HBONE mTLS on behalf of the pod  │                 │               │                │
```

---

## Section 4: Waypoint Proxy Certificate

The waypoint is an Envoy-based L7 proxy deployed as a Kubernetes Deployment in the
application namespace. It enforces `AuthorizationPolicy` for all traffic destined to services
in that namespace. Like ztunnel, the waypoint calls istio-csr **directly** (via `CA_ADDRESS`)
for its own SPIFFE SVID — bypassing the ztunnel → istiod hop that workload SVIDs use.

### Gateway naming constraint and SA annotation

Istio's gateway controller derives **both** the Kubernetes Service name and the SA name from
the Gateway name. SA names allow dots (Kubernetes allows RFC 1123 subdomain format), but
Kubernetes Service names must be DNS-1035 compliant (no dots). A Gateway named
`msd.stage.waypoint` causes Service creation to fail silently, leaving the Gateway
`Programmed=False` and ztunnel never routing through it.

**Why the namespace cannot encode the domain:** Teams may choose any namespace name
(`payments-frontend`, `team-a`, etc.). Requiring the namespace to be a hyphenated form of
the Athenz domain breaks namespace naming freedom and creates ambiguity when domain
component names already contain hyphens.

**Solution** (`istio-infra/waypoint.yaml`):
- Gateway named `waypoint` (DNS-1035 valid) → Istio creates Service `waypoint` and
  Deployment SA `waypoint` — all match, no post-creation patch needed ✓
- SA `waypoint` carries annotation `athenz.io/domain: msd.stage` — the authoritative
  domain binding, set by the application team alongside their SA
- athenz-issuer reads the annotation: SA has no dots → GET the ServiceAccount →
  read `athenz.io/domain` → `domain=msd.stage`, `service=waypoint`
- Namespace naming is completely free; ZTS validates domain via the annotation path

**Trust model:** The annotation is set in Kubernetes alongside the SA object. Only users
with RBAC write access to ServiceAccounts in that namespace can set it — the same users
who register services in the Athenz domain. athenz-issuer is the trusted bridge that reads
and forwards the annotation to ZTS; ZTS validates the SA token cryptographically (proves
the pod is the claimed SA in the claimed namespace) and trusts athenz-issuer's domain
assertion from the annotation.

### Sequence Diagram

```
      waypoint           istio-csr       cert-manager      athenz-issuer     Kubernetes API      Athenz ZTS
       (WP)               (ICSR)           (CM/AP)              (AI)             (K8S)              (ZTS)
         │                  │                 │                   │                 │                  │
         │  [SA=waypoint     │                 │                   │                 │                  │
         │   annotation athenz.io/domain=msd.stage                │                 │                  │
         │   CA_ADDR=cert-manager-istio-csr.kube-addons.svc:443]  │                 │                  │
         │                  │                 │                   │                 │                  │
         │  1. Generate EC P-256 key pair and CSR                  │                 │                  │
         │     Subject: O= (empty string - Istio bug in GenCSRTemplate)             │                  │
         │     URI SAN: spiffe://athenz.cloud/ns/msd-stage/sa/waypoint              │                  │
         │     DNS SAN: (none)              │                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │  2. gRPC CreateCertificate       │                   │                 │                  │
         │     csr (Subject O=, URI SAN only)│                   │                 │                  │
         │     identities: spiffe://athenz.cloud/ns/msd-stage/sa/waypoint          │                  │
         ├─────────────────►│                 │                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │           3. Create CertificateRequest istio-csr-xxxx  │                 │                  │
         │                  │  spec.request: CSR (Subject O=, URI SAN only, no DNS SANs)              │
         │                  │  spec.issuerRef: athenz-istio-issuer │                 │                  │
         │                  │  annotation istio.cert-manager.io/identities:         │                  │
         │                  │    spiffe://athenz.cloud/ns/msd-stage/sa/waypoint     │                  │
         │                  ├────────────────►│                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │                  │          4. approver-policy: policy match ok, Approved=True              │
         │                  │                 │                   │                 │                  │
         │                  │                 │            5. Read SPIFFE URI from annotation          │
         │                  │                 │               ns=msd-stage  sa=waypoint                │
         │                  │                 │               SA has no dots -> GET ServiceAccount     │
         │                  │                 │                   │                 │                  │
         │                  │                 │            6. GET ServiceAccount waypoint in msd-stage │
         │                  │                 │                   ├────────────────►│                  │
         │                  │                 │                   │◄────────────────┤                  │
         │                  │                 │                   │  SA object: annotations.athenz.io/domain = msd.stage
         │                  │                 │                   │                 │                  │
         │                  │                 │               -> domain=msd.stage (from annotation)    │
         │                  │                 │                  service=waypoint (SA name)            │
         │                  │                 │                   │                 │                  │
         │                  │                 │            7. TokenRequest for SA waypoint in msd-stage│
         │                  │                 │                   ├────────────────►│                  │
         │                  │                 │                   │◄────────────────┤                  │
         │                  │                 │                   │  SA token       │                  │
         │                  │                 │                   │  sub: system:serviceaccount:msd-stage:waypoint
         │                  │                 │                   │  iss: GKE OIDC endpoint             │
         │                  │                 │                   │  aud: ZTS URL   │                  │
         │                  │                 │                   │                 │                  │
         │                  │                 │            8. POST /zts/v1/instance │                  │
         │                  │                 │               domain=msd.stage  service=waypoint       │
         │                  │                 │               provider=sys.k8s.gcp-us-east5  namespace=msd-stage
         │                  │                 │               csr: Subject O= (empty), URI SAN only, no DNS SANs
         │                  │                 │               identityToken: SA token                  │
         │                  │                 │                   ├─────────────────────────────────── ►│
         │                  │                 │                   │                 │                  │
         │                  │                 │                   │                 │          9. Validate SA token ok
         │                  │                 │                   │                 │             GCP OIDC issuer check ok
         │                  │                 │                   │                 │             CSR CN empty - skip (patch 1)
         │                  │                 │                   │                 │             DNS SANs none + spiffe URI - bypass DNS validation (patch 2)
         │                  │                 │                   │                 │             Subject O= empty string - treat as absent (patch 3)
         │                  │                 │                   │                 │             SA name has no dots - accept Form 2 SPIFFE URI (patch 4)
         │                  │                 │                   │                 │             Sign cert:
         │                  │                 │                   │                 │               Issuer:  Yahoo Athenz CA
         │                  │                 │                   │                 │               Subject: O= (preserved from CSR)
         │                  │                 │                   │                 │               URI SAN: spiffe://athenz.cloud/ns/msd-stage/sa/waypoint
         │                  │                 │                   │                 │               Validity: 7 days
         │                  │                 │                   │◄───────────────────────────────── │
         │                  │                 │                   │  10. signed cert + chain           │
         │                  │                 │                   │                 │                  │
         │                  │                 │            11. Patch CertificateRequest.status.certificate
         │                  │                 │◄──────────────────┤                 │                  │
         │                  │◄────────────────┤  CR Ready=True    │                 │                  │
         │◄─────────────────┤                 │                   │                 │                  │
         │  12. gRPC response: signed cert chain                   │                 │                  │
         │                  │                 │                   │                 │                  │
         │  13. Hold cert in memory           │                   │                 │                  │
         │      Serve HBONE port 15008        │                   │                 │                  │
         │      ztunnel routes L7 traffic here│                   │                 │                  │
```

### How the waypoint differs from the workload SVID path

| Aspect | Workload SVID (Section 3) | Waypoint cert (Section 4) |
|--------|--------------------------|--------------------------|
| CSR generator | ztunnel (on behalf of pod) | waypoint pilot-agent (for itself) |
| First gRPC hop | ztunnel → istiod → istio-csr | waypoint → istio-csr (direct) |
| SA naming | Approach A: `{domain}.{service}` (dots) | Dot-free SA name; Athenz domain from `athenz.io/domain` annotation |
| Domain derivation | Split SA on last dot | Read `athenz.io/domain` annotation; error if absent |
| Namespace naming | Free choice | Free choice — namespace does not encode the domain |
| Subject DN | Completely empty (SPIFFE spec) | `O=` (empty Organization — Istio bug) |
| DNS SANs | None | None |
| ZTS patches needed | #1 (CN) and #2 (DNS bypass) | #1 (CN) and #2 (DNS bypass) and #3 (empty O=) and #4 (Form 2 SPIFFE URI) |
| Cert held by | ztunnel in-memory (per pod) | waypoint in-memory (for itself) |
| Used for | HBONE mTLS between ztunnel nodes | HBONE mTLS to/from ztunnel + L7 policy enforcement |

### L7 Data Plane Flow (with Waypoint)

ztunnel is involved at **both ends**. The waypoint sits between the source and destination
ztunnels — it does not replace them. istiod's xDS pushes waypoint routing rules to ztunnel:
when ztunnel sees traffic destined for the `httpbin` Service it routes to the waypoint first
instead of directly to the destination ztunnel. The waypoint evaluates L7 policy, then
opens a second HBONE hop to the destination ztunnel, which delivers plaintext to the pod.

```
   curl pod          ztunnel           waypoint          ztunnel          httpbin pod
 (calypso-nonprod)  (curl node)    (msd-stage/waypoint) (httpbin node)   (msd-stage)
       │                │                  │                  │                │
       │  1. plain TCP to httpbin:80 (intercepted by eBPF/iptables)            │
       ├───────────────►│                  │                  │                │
       │                │                  │                  │                │
       │                │  [xDS from istiod: httpbin Service has waypoint annotation
       │                │   route to waypoint instead of direct]               │
       │                │                  │                  │                │
       │                │  2. HBONE CONNECT port 15008         │                │
       │                │     mTLS: src=curl SVID, dst=waypoint SVID           │
       │                │     inner dst: httpbin pod IP:80     │                │
       │                ├─────────────────►│                  │                │
       │                │                  │                  │                │
       │                │                  │  [terminates mTLS                 │
       │                │                  │   source principal:               │
       │                │                  │   spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl
       │                │                  │   evaluates AuthorizationPolicy httpbin-get-only
       │                │                  │   method GET  -> ALLOW            │
       │                │                  │   method POST -> DENY 403]        │
       │                │                  │                  │                │
       │                │                  │  3. HBONE CONNECT port 15008      │
       │                │                  │     mTLS: src=waypoint SVID, dst=httpbin SVID
       │                │                  │     inner dst: httpbin pod IP:80  │
       │                │                  ├─────────────────►│                │
       │                │                  │                  │                │
       │                │                  │                  │  4. plain TCP to httpbin:80
       │                │                  │                  ├───────────────►│
       │                │                  │                  │◄───────────────┤
       │                │                  │◄─────────────────┤  HTTP response │
       │                │◄─────────────────┤  HBONE response  │                │
       ◄────────────────┤  plain TCP response                  │                │
```

Two HBONE hops are always used when a waypoint is present — one from source ztunnel to
waypoint and one from waypoint to destination ztunnel. L4-only paths (no waypoint) use a
single ztunnel-to-ztunnel hop (see Section 5).

---

## Section 5: mTLS — How the Cert Is Used in Traffic (L4, no waypoint)

```
  curl pod          ztunnel-A          ztunnel-B         httpbin pod
(calypso-nonprod,  (Node A)           (Node B)          (msd-stage,
  Node A)                                                 Node B)
     │                 │                  │                  │
     │  1. plaintext TCP (iptables intercept to port 15001)  │
     ├────────────────►│                  │                  │
     │                 │                  │                  │
     │                 │  2. HBONE/mTLS tunnel on port 15008 │
     │                 │     Client cert (ztunnel-A, on behalf of curl):
     │                 │       Subject: (empty)              │
     │                 │       URI SAN: spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl
     │                 │       Issuer:  Yahoo Athenz CA      │
     │                 │     Server cert (ztunnel-B, on behalf of httpbin):
     │                 │       Subject: (empty)              │
     │                 │       URI SAN: spiffe://athenz.cloud/ns/msd-stage/sa/msd.stage.httpbin
     │                 │       Issuer:  Yahoo Athenz CA      │
     │                 ├─────────────────►│                  │
     │                 │                  │                  │
     │                 │          3. Verify client cert URI SAN
     │                 │             Evaluate AuthorizationPolicy
     │                 │                  │                  │
     │                 │          4. plaintext TCP into pod netns
     │                 │                  ├─────────────────►│
     │                 │                  │◄─────────────────┤
     │                 │                  │  response        │
     │                 │◄─────────────────┤  HBONE/mTLS      │
     │◄────────────────┤  plaintext response                  │
```

**Application pods send and receive plaintext. mTLS is entirely within ztunnel.**

---

## Certificate Fields by Component

| Certificate | CN | URI SAN | DNS SANs | Subject | Issuer |
|-------------|----|---------|-----------|---------|----|
| istiod-tls | `athenz.k8s.nonprod.istiod` | `spiffe://athenz.cloud/ns/istio-system/sa/athenz.k8s.nonprod.istiod` | `istiod.istio-system.svc[.cluster.local]` | = CN | Yahoo Athenz CA |
| ztunnel node cert | `athenz.k8s.nonprod.ztunnel` | `spiffe://athenz.cloud/ns/istio-system/sa/athenz.k8s.nonprod.ztunnel` | `ztunnel.istio-system.svc.cluster.local` | = CN | Yahoo Athenz CA |
| istio-csr serving cert | `athenz.k8s.nonprod.cert-manager-istio-csr` | `spiffe://athenz.cloud/ns/kube-addons/sa/athenz.k8s.nonprod.cert-manager-istio-csr` | `cert-manager-istio-csr.kube-addons.svc[.cluster.local]` | = CN | Yahoo Athenz CA |
| Workload SVID (curl) | *(empty)* | `spiffe://athenz.cloud/ns/calypso-nonprod/sa/calypso.nonprod.curl` | *(none)* | *(empty)* | Yahoo Athenz CA |
| Workload SVID (httpbin) | *(empty)* | `spiffe://athenz.cloud/ns/msd-stage/sa/msd.stage.httpbin` | *(none)* | *(empty)* | Yahoo Athenz CA |
| Waypoint SVID | *(empty)* | `spiffe://athenz.cloud/ns/msd-stage/sa/waypoint` | *(none)* | `O=` (empty — Istio bug) | Yahoo Athenz CA |

> Control-plane certs have a CN and DNS SANs because components connect to them by hostname.
> Workload and waypoint SVIDs carry identity purely in the SPIFFE URI SAN. The waypoint's
> `Subject: O=` (empty Organization field present but blank) is an Istio bug in
> `GenCSRTemplate` — it unconditionally writes `Organization: []string{options.Org}` even when
> `Org` is unset (Go zero value `""`), producing an empty field rather than omitting it.
> See `docs/project_istio_csr_empty_org_bug.md`.

---

## SA Token Flow Per Hop (Workload SVID Path)

| Hop | Token | Identity | Purpose |
|-----|-------|----------|---------|
| ztunnel → istiod | ztunnel's own SA token (Bearer) | `athenz.k8s.nonprod.ztunnel`, aud: `istio-ca` | Prove ztunnel is a trusted node agent |
| istiod → istio-csr | none | — | Trust consumed; istiod enforces node-workload co-location |
| istio-csr → CertificateRequest | none | — | CertificateRequest carries only CSR + SPIFFE URI annotation |
| athenz-issuer → K8s TokenRequest | fetches fresh token | `calypso.nonprod.curl`, aud: ZTS URL | Obtain proof of workload identity for ZTS |
| athenz-issuer → ZTS | workload SA token | `sub: system:serviceaccount:calypso-nonprod:calypso.nonprod.curl`<br>`iss`: GKE OIDC endpoint<br>`aud`: ZTS URL<br>no pod claim — SA-bound | ZTS validates against GCP OIDC JWKS; confirms sub matches domain.service |

---

## ZTS Patches for Workload SVIDs

Both patches are in the `servers/zts` module (loaded from WAR via `deploy_zts_war.sh`).

> **Classloading constraint:** `athenz-instance-provider` JAR is on ZTS's ext-classpath.
> Jetty parent-first classloading means changes to that JAR inside the WAR are silently
> ignored. Only `servers/zts` changes reliably take effect.

### Patch 1 — Skip CN validation for empty Subject (`X509ServiceCertRequest.java`)
SPIFFE SVIDs have no Subject DN by spec. ZTS required CN == `domain.service`. The patch
skips the CN check when the CSR CN is empty, relying instead on the URI SAN validation.
Affects: workload SVIDs and waypoint SVID.

### Patch 2 — Bypass DNS hostname validation for SPIFFE-only SVIDs (`ZTSImpl.java`)
Workload SVIDs carry no DNS SANs. The GCP K8s provider fails immediately on an empty DNS
SAN list. The patch in `validateConfirmationData()`: when `sanDns` is empty and `sanUri`
starts with `spiffe://`, bypass `confirmInstance()` entirely and set `ZTS_CERT_REFRESH=false`.
Affects: workload SVIDs and waypoint SVID.

### Patch 3 — Accept empty Subject O field (`X509CertRequest.java`)
The waypoint's Envoy generates a CSR with `Subject: O=` — the Organization field is present
but set to empty string. `Crypto.extractX509CSRSubjectOField()` returns `""` (not `null`).
The old check `if (value == null)` did not treat `""` as absent, causing the empty string to
be validated against the allowed-values set and fail. The patch changes the guard to
`if (StringUtils.isEmpty(value))`, treating an empty O field the same as an absent one.
Affects: waypoint SVID only. Root cause is an Istio bug — see note in Certificate Fields table.

### Patch 4 — Accept Form 2 SPIFFE URI for annotation-driven dot-free SAs (`X509ServiceCertRequest.java`)
The waypoint SA is dot-free (`waypoint`) — Kubernetes Gateway API requires the Gateway and
its backing Service to share the same DNS-1035 compliant name, so the SA cannot encode the
Athenz domain via dots. The Athenz domain is carried instead via the `athenz.io/domain`
annotation on the ServiceAccount, read by athenz-issuer. The resulting SPIFFE URI
`spiffe://athenz.cloud/ns/{namespace}/sa/{service}` is Form 2 (no domain prefix in the SA
component). ZTS's default validator expects Form 1
(`spiffe://{trustDomain}/ns/{ns}/sa/{domain}.{service}`). The patch in `validateSpiffeURI()`:
when `serviceName` contains no dots (confirming this is a dot-free SA case), construct the
Form 2 URI and accept it if it matches. The namespace is whatever the application team chose
— the `!serviceName.contains(".")` guard is the only requirement. This replaces the earlier
`namespace.replace("-",".")  == domainName` check, which broke when namespace names did not
encode the Athenz domain.
Affects: waypoint SVID only (dot-free SA with `athenz.io/domain` annotation).

---

## Key Source Files

| File | Purpose |
|------|---------|
| `istio-infra/istiod-cert.yaml` | cert-manager Certificate for istiod TLS cert |
| `istio-infra/ztunnel-cert.yaml` | cert-manager Certificate for ztunnel node cert |
| `istio-infra/istio-csr-cert.yaml` | cert-manager Certificate for istio-csr serving cert |
| `istio-infra/curl.yaml` | Namespace, SA (`calypso.nonprod.curl`), and Deployment for curl workload |
| `istio-infra/httpbin.yaml` | Namespace, SA (`msd.stage.httpbin`), Deployment, Service, and AuthorizationPolicy for httpbin |
| `istio-infra/waypoint.yaml` | SA (`waypoint` with `athenz.io/domain: msd.stage` annotation) and Gateway for the msd-stage waypoint |
| `istio-infra/terraform/control-plane/main.tf` | Registers control-plane services in `athenz.k8s.nonprod` domain |
| `istio-infra/terraform/curl/main.tf` | Registers `curl` service in `calypso.nonprod` domain |
| `istio-infra/terraform/httpbin/main.tf` | Registers `httpbin` and `waypoint` services in `msd.stage` domain |
| `istio-csr/pkg/tls/tls.go` | `loadFromSecret()` — load serving cert from pre-provisioned Secret |
| `istio-csr/cmd/app/options/options.go` | `--serving-certificate-secret-name/namespace` flags |
| `istio-csr/cmd/app/app.go` | Wires k8s client into tls.Provider |
| `istio-csr/pkg/certmanager/certmanager.go` | `HasIssuerConfig()` mutex fix (Lock → RLock) |
| `athenz/servers/zts/.../ZTSImpl.java` | SPIFFE bypass in `validateConfirmationData`; full logging |
| `athenz/servers/zts/.../X509ServiceCertRequest.java` | Skip CN check (Patch #1); Form 2 SPIFFE URI (Patch #4) |
| `athenz/servers/zts/.../X509CertRequest.java` | Accept empty Subject O field (Patch #3) |
| `drivers/deploy_zts_war.sh` | Deploys patched ZTS WAR to dev instance |
| `drivers/push_istio_csr_to_gar.sh` | Builds and pushes patched istio-csr image to GAR |
