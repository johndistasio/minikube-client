## minikube-client

Generates client certificates and keys signed by Minikube's CA for easy authn/z configuration.

Example usage (`-o` accepts a comma-delimited string e.g. `a,b` for multiple groups):

```
% minikube-client -cert cert.pem -key key.pem -cn mymuser -o mygroup
```

Update your kubeconfig to match:

```yaml
apiVersion: v`
kind: Config
# other fields...
users:
# other users...
- name: myuser
  user:
    client-certificate: /path/to/cert.pem
    client-key: /path/to/key.pem
```
Now use `kubectl`:
```
% kubectl --user myuser ...
```
Run:
```
% minkube-client -h
```
for extended usage information.