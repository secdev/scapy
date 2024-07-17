# Notes on how to generate the PKI

```
openssl genpkey -algorithm ED25519 -out srv_key_ed25519.pem
openssl req -new -key srv_key_ed25519.pem -out srv_cert_ed25519.csr -addext basicConstraints=critical,CA:FALSE,pathlen:1 -addext "extendedKeyUsage = serverAuth" -subj "/C=MN/L=Ulaanbaatar/OU=Scapy Test PKI/CN=Scapy Test Server"
openssl x509 -req -days 3653 -in srv_cert_ed25519.csr -CA ca_cert.pem -CAkey ca_key.pem -out srv_cert_ed25519.pem -copy_extensions copyall
rm srv_cert_ed25519.csr
openssl x509 -in srv_cert_ed25519.pem -text -noout
```
