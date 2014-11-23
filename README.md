yoca
====

just a simple script to issue a self-signed certificate.

```
# setup script
./certs.sh setup
# create a root certificate
./certs.sh root create
# create a intermediate certificate
./create.sh intermediate create
By default the intermediate function will be looking for a different ssl.cnf located in ./intermediate/openssl.cnf It will need to be created before running the script.

# create a client certificate
./create.sh client create
# ...
./create.sh client create
```

### credits:
https://jamielinux.com
