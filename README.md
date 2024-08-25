## minikube-client

Generates client certificates and keys signed by Minikube's CA for quick authn/z setups.

#### Usage

```
minikube-client -cn myuser -o mygroup
```

Note that `-o` accepts a comma-delimited string (e.g. `a,b`) for multiple groups.

Your kubeconfig will be updated with an embedded client certificate and key:

```yaml
apiVersion: v1
kind: Config
# other fields...
users:
# other users...
- name: myuser
  user:
    client-certificate-data: ...
    client-key-data: ...
```

Now run `kubectl`:

```shell script
kubectl --user myuser ...
```

#### Advanced Usage

The location of your kubeconfig is resolved following rules similar to `kubectl`. In order of priority, these are:

1. The value of the  `-kubeconfig` flag, if provided.
2. The first valid path in `$KUBECONFIG`, if present.
3. `~/.kube/config`

You can also generate a standalone certificate and key instead, using the `-cert` and `-key` flags:

```shell script
minikube-client -cn mymuser -o mygroup -cert /path/to/cert.pem -key /path/to/key.pem
```

These can be used by any system that needs to access your Minikube instance.
