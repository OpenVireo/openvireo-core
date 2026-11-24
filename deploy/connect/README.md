# Deploying `ov connect`

`ov connect` is a small REST server inside `ov` that holds one service account token and serves the
vaults it can open to other programs, with its own scoped bearer tokens. The API, the environment
variables and the token format are documented in openvireo-sdk's
[docs/connect.md](https://github.com/openvireo/openvireo-sdk/blob/develop/docs/connect.md), also on
[developer.openvireo.com/cli/connect/](https://developer.openvireo.com/cli/connect/).

This directory runs it on Kubernetes and plugs it into the
[External Secrets Operator](https://external-secrets.io) (ESO) through ESO's built-in webhook provider;
there is no custom operator.

| Path | |
|---|---|
| `Dockerfile` | the release image: the static musl `ov` from the release on distroless |
| `helm/openvireo-connect/` | Helm chart: Deployment, Service, NetworkPolicy, the config Secret, two `ClusterSecretStore`s |
| `helm/external-secrets-values.yaml` | values for the upstream ESO chart |
| `kubernetes/` | the same as plain `kubectl apply -k` manifests; `external-secret.example.yaml` shows the consumer side |

These files moved here from openvireo-sdk `packages/connect/deploy/` at commit `6926a1d` (SDK 1.1.0),
when `ov connect` was ported to Rust. The environment, the Secret keys (`sa-token`, `tokens.json`), the
probes (`/health` liveness, `/ready` readiness) and the values are unchanged, so an existing
`values.yaml` keeps working; only the image changed (now published, entrypoint `ov`). One exception:
the manifests now set `command: ["ov"]`, so a values file that pins `image.tag` (or `image.repository`)
to a self-built image of the old Bun `openvireo-connect` must drop that override and use the published
image.

## The image

Every openvireo-core release publishes `ghcr.io/openvireo/openvireo-connect:<core version>` (and
`:latest` for a stable release) for linux/amd64 and linux/arm64. It is `gcr.io/distroless/static-debian12:nonroot`
with the release's static `ov` at `/usr/local/bin/ov`: entrypoint `ov`, default command `connect serve`,
user 65532, listening on `0.0.0.0:8080`. The manifests run it with `command: ["ov"]` and
`args: ["connect", "serve"]`.

```sh
docker run --rm ghcr.io/openvireo/openvireo-connect:1.2.0 version
docker run --rm ghcr.io/openvireo/openvireo-connect:1.2.0 connect token --name eso
```

The chart's `appVersion` and the tag in `kubernetes/openvireo-connect.yaml` are the core version
(1.2.0 now). The release bumps them together with `version` in the workspace `Cargo.toml`.

To build the image yourself, put a static Linux `ov` per architecture in a context directory as
`linux-<arch>/ov` (`amd64`, `arm64`; from the release archives or `cargo xtask release --only ov` on
Linux) and run, from the repository root:

```sh
mkdir -p ctx/linux-amd64 && cp ov-1.2.0-linux-x64/ov ctx/linux-amd64/
docker buildx build -f deploy/connect/Dockerfile --platform linux/amd64 \
  --build-arg VERSION=1.2.0 -t openvireo-connect:dev --load ctx
```

## Install with Helm and ESO

```sh
# 1. ESO, from its own chart
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace \
  -f deploy/connect/helm/external-secrets-values.yaml

# 2. a connect token for ESO: the token on stdout, its config entry (hash only) as the last line of stderr
ov connect token --name eso > eso.token 2> entry.txt

# 3. ov connect, with the service account token in sa.token
helm install openvireo deploy/connect/helm/openvireo-connect -n openvireo-connect --create-namespace \
  --set-file serviceAccountToken=sa.token --set-json "connectTokens=[$(tail -1 entry.txt)]" \
  --set-file externalSecrets.token=eso.token
```

Values (see `values.yaml`):

- `existingSecret`, or `serviceAccountToken` + `connectTokens`: an existing Secret with the keys
  `sa-token` and `tokens.json`, or the chart creates one. One of the two is required.
- `externalSecrets.token`: the plain connect token ESO presents; the chart puts it in the Secret
  `externalSecrets.tokenSecret` (default `openvireo-connect-eso`, key `token`). Leave it empty to create
  that Secret yourself. `externalSecrets.enabled: false` leaves the stores out.
- `networkPolicy.allowedNamespaces`: who may call ov connect (default `[external-secrets]`). Egress is
  limited to DNS and HTTPS (the auth and sync servers).
- `image.tag`: defaults to the chart's `appVersion`; `image.repository` for a mirror.
- `cacheTtlSeconds`, `replicaCount`, `resources`, `service.port`, `imagePullSecrets`.

## Install with kustomize

`kubernetes/` creates the namespace `openvireo-connect`, the two Secrets as placeholders
(`secrets.example.yaml`), the Deployment (non-root, read-only root filesystem), Service, NetworkPolicy
and the two `ClusterSecretStore`s. Install ESO as in step 1 above, then either fill in
`secrets.example.yaml` or remove it from `kustomization.yaml` and create the Secrets yourself:

```sh
ov connect token --name eso > eso.token 2> entry.txt
kubectl create namespace openvireo-connect
kubectl -n openvireo-connect create secret generic openvireo-connect \
  --from-file=sa-token=sa.token --from-literal=tokens.json="[$(tail -1 entry.txt)]"
kubectl -n openvireo-connect create secret generic openvireo-connect-eso --from-file=token=eso.token
kubectl apply -k deploy/connect/kubernetes
```

To pin another image version, add an overlay with
`images: [{name: ghcr.io/openvireo/openvireo-connect, newTag: <version>}]`.

## Using the stores

Both stores use `apiVersion: external-secrets.io/v1` (ESO 0.17 or later; use `v1beta1` on older
releases):

- `openvireo`: one field per `remoteRef`, with `key: "Team%20Infra/items/Deploy/Database"` (vault, then
  `items/`, then the group path and the entry, percent-encoded) and `property: password`. It calls
  `…/items/…?field=password` and reads `$.value`. `property` is required.
- `openvireo-items`: `dataFrom: [{extract: {key: "Team%20Infra/items/GitHub"}}]` makes every field of
  the item a key of the Secret (`$.fields`).

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: app-db
spec:
  refreshInterval: 15m
  secretStoreRef: { kind: ClusterSecretStore, name: openvireo }
  target: { name: app-db }
  data:
    - secretKey: password
      remoteRef: { key: "Team%20Infra/items/Deploy/Database", property: password }
```

## Checks

```sh
helm lint deploy/connect/helm/openvireo-connect --set serviceAccountToken=x \
  --set 'connectTokens[0].name=a' --set "connectTokens[0].sha256=$(printf 'a%.0s' {1..64})"
kubectl kustomize deploy/connect/kubernetes
```

CI runs both (`.github/workflows/ci.yml`, job `deploy`).
