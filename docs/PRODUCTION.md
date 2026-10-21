# Production checklist

Use this before the first real deployment, and again when you move a data directory to a new host.

## Identity and network

- [ ] Set `MAXIO_ACCESS_KEY` and `MAXIO_SECRET_KEY` yourself. MaxIO refuses to start with the built-in `maxioadmin` / `maxioadmin` pair. Do not pass `--allow-insecure-dev` or `MAXIO_ALLOW_INSECURE_DEV` on a shared machine.
- [ ] Generate the secret on the host and store it in your secret manager. Do not commit it.

```bash
export MAXIO_ACCESS_KEY="operator"
export MAXIO_SECRET_KEY="$(openssl rand -hex 32)"
```

- [ ] Put TLS in front of MaxIO. The server speaks HTTP. A reverse proxy should terminate TLS and forward `X-Forwarded-Proto: https` so the console session cookie is marked `Secure`.

Caddy:

```
storage.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 0;
}
```

`client_max_body_size 0` lets large uploads through. Also raise the proxy read timeout for big multipart parts.

Console login limits count failed attempts: 10 per 5 minutes for one access key, and 50 per 5 minutes for one client IP across every access key. Behind this proxy, set `MAXIO_TRUSTED_PROXY` to the proxy's address (for example `127.0.0.1`) so MaxIO reads `X-Forwarded-For`. Without that setting every login is attributed to the proxy itself, so one client can lock the console for everyone until the window expires. Do not list a network that clients can connect from directly: a trusted proxy is allowed to choose the client address.

- [ ] Leave port 9000 bound to localhost when a proxy is on the same machine (`MAXIO_ADDRESS=127.0.0.1`). If clients reach MaxIO directly, allow that port only from the networks that should use it.
- [ ] Keep clocks in sync (for example chrony). Signature V4 requests outside the clock skew window are rejected.

## Data you must be able to restore

- [ ] The data directory, `<data-dir>/.maxio-keys.json`, and `<data-dir>/iam.json` (IAM users and sealed access-key secrets) are backed up together, and the backup is not only on the same disk.
- [ ] You have restored that pair onto a spare host once, or you have a written restore command you have actually run.
- [ ] `MAXIO_MASTER_KEY`, if you set it, is in the same backup plan as the data directory. An override key that is not backed up is the same as losing the keyring.
- [ ] The volume is large enough for the objects you will store. Erasure coding uses extra space for parity shards when you enable it.

A backup is a copy of the data directory while MaxIO is stopped, or a filesystem snapshot that is consistent. Copying the live directory during writes can capture a torn object.

## Capacity

Start small and raise the limits when the workload needs it. These are starting points for a single small server, not a sizing formula.

- [ ] Memory limit of at least 512MiB. A host with room for the page cache (a few GiB) will serve reads faster.
- [ ] Open-file limit of at least 65535 for the MaxIO process (`LimitNOFILE` in systemd, or `ulimits` in Docker).
- [ ] A pid limit high enough for the worker threads (Docker `--pids-limit` of a few hundred is enough to start; raise it if the process is killed for pid exhaustion).
- [ ] Disk monitoring on the data volume. MaxIO does not enforce a quota.

Docker example:

```bash
docker run -d --name maxio \
  --memory=1g --pids-limit=512 \
  --ulimit nofile=65535:65535 \
  -p 127.0.0.1:9000:9000 \
  -v /var/lib/maxio:/data \
  -e MAXIO_ACCESS_KEY -e MAXIO_SECRET_KEY \
  ghcr.io/coollabsio/maxio:1.0.0
```

systemd:

```
MemoryMax=1G
LimitNOFILE=65535
```

## Health

- [ ] The process supervisor uses `GET /maxio/health/live` or `maxio healthcheck`. A 200 body looks like `{"status":"ok"}` and does not include the version.
- [ ] `/maxio/health/ready` is the readiness probe (`503` when the data directory cannot be read). `/maxio/health/live` and `/maxio/health/ready` are the only health URLs.
- [ ] The image tag or binary version is pinned. `latest` is for experiments.
- [ ] You know which version is installed (`maxio --version`) and which format the data directory is on (the startup log, or `.maxio-format`).

## Still single node

Replication and distributed mode are not in this release. One data directory must have one writer. Do not mount the same directory on two MaxIO processes.
