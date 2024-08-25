## minikube-client

Generates client certificates and keys signed by Minikube's CA for quick authn/z setups.

Example usage :

```
% minikube-client -cert cert.pem -key key.pem -cn mymuser -o mygroup
```
Note that `-o` accepts a comma-delimited string e.g. `a,b` for multiple groups.

Update your kubeconfig to match:

```yaml
apiVersion: v1
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
