## To Build

To build this package, do the following steps:

```sh
    1. meson build
    2. ninja -C build
```

#### LDAP Configuration

#### Configure LDAP

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/json" -X POST -d '{"data":[false,"ldap://<ldap://<LDAP server ip/hostname>/", "<bindDN>", "<baseDN>","<bindDNPassword>","<searchScope>","<serverType>"]}''  https://$BMC_IP/xyz/openbmc_project/user/ldap/action/CreateConfig

```

#### NOTE

If the configured ldap server is secure then we need to upload the client
certificate and the CA certificate in following cases.

- First time LDAP configuration.
- Change the already configured Client/CA certificate

#### Upload LDAP Client Certificate

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream"
     -X PUT -T <FILE> https://<BMC_IP>/xyz/openbmc_project/certs/client/ldap
```

#### Upload CA Certificate

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/octet-stream"
     -X PUT -T <FILE> https://<BMC_IP>/xyz/openbmc_project/certs/authority/truststore
```

#### Clear LDAP Config

```sh
curl -b cjar -k -H "Content-Type: application/json" -X POST -d '{"data":[]}' https://$BMC_IP/xyz/openbmc_project/user/ldap/config/action/delete
```

#### Get LDAP Config

```sh
curl -b cjar -k https://$BMC_IP/xyz/openbmc_project/user/ldap/enumerate
```
