## minikube-client

Generates client certificates and keys signed by Minikube's CA for quick authn/z setups.

#### Installation

```
make
sudo make install
```

Or, just `go build` it and stick it somewhere in your path.

#### Usage

```
minikube-client -cn mymuser -o mygroup
```

Note that `-o` accepts a comma-delimited string e.g. `a,b` for multiple groups.

Your `~/.kube/config` will be updated with an embedded client certificate and key:

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

```
kubectl --user myuser ...
```

#### Advanced Usage

You can also generate a standalone certificate and key with the `-cert` and `-key` flags:

```
minikube-client -cn mymuser -o mygroup -cert /path/to/cert.pem -key /path/to/key.pem
```

These can be used by any system that needs to access your Minikube instance.
