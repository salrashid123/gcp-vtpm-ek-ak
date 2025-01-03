## Sign, Verify and decode using Google Cloud vTPM Attestation Key and Certificate


This repo covers how to use a GCE Confidential VM's [TPM module](https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext) to sign some data that can be verified later by a Google signed public certificate in such a way that act of signing must have been done only on that VM.

Meaning, you can sign data and someone else can verify that the target GCP vm's TPM did that signing only.

The `x509 cert` issued to each vm is unique but is signed by google.  The certificate encodes that VM's `instanceID`, `project`, `region` directly into that certificate which a verifier can use to check the signature and then know that signature was done on that same instanceID, project, region.

Meaning, you can assert _this `vm_id=1234`, running in `region=us-central1-a` in `project=abcd` must have signed this data_

So how does this work:   Each VM's `Endorsement Key` (encryption) and `Attestation Key` (signing) is encoded into `x509` certificates issued by Google's private root CA and a per-project subordinate CA.  The subordinate CA is unique to your project but you can derive trust to the roots:

Eg root CA:

```bash
$ cat ek_root.pem
-----BEGIN CERTIFICATE-----
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
av16U4E=
-----END CERTIFICATE-----

$ openssl x509 -in ek_root.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a6:5d:a4:f9:e3:28:f3:80:35:c3:a7:3d:4f:72:43:2b:df:15:dc
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Root
        Validity
            Not Before: Jul  8 00:40:34 2022 GMT
            Not After : Jul  8 05:57:23 2122 GMT
        Subject: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Root
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:9d:25:f5:50:a8:c8:96:4b:4a:89:7c:2b:28:4d:
                    a5:b4:bb:a4:19:ee:89:c1:3a:a6:da:dd:b7:10:16:
                    21:1d:93:9c:bc:52:83:13:45:89:1e:dd:ae:da:1f:
                    c4:8d:2b:b9:c7:a8:08:8a:6c:6b:d3:47:20:aa:f3:
                    de:c3:3f:37:f1:3c:98:53:47:88:90:2e:c9:57:f7:
                    a4:fa:66:0e:92:c9:65:0d:6a:7b:cc:87:92:91:92:
                    b3:72:a3:de:ce:58:61:6b:44:79:c0:95:7f:33:6c:
                    e0:cb:4a:bc:67:c0:f9:62:81:e3:d0:3a:36:88:bc:
                    47:d4:75:1a:89:cb:20:de:b0:49:75:f7:90:fd:62:
                    6d:19:f4:34:68:1d:aa:07:e0:45:ee:47:0b:79:0a:
                    02:18:d9:ea:c7:13:f0:46:f5:48:69:5a:07:21:b3:
                    13:95:a8:19:39:cd:6f:28:9f:93:2c:7d:a1:46:71:
                    5d:52:6c:aa:fd:aa:eb:5d:56:dd:aa:5b:3f:17:20:
                    7a:ff:33:e4:95:d0:51:ba:eb:43:b1:1b:3b:44:ad:
                    2b:50:ec:29:1b:0a:2e:e0:fe:60:bc:63:ac:14:50:
                    e1:47:88:37:95:87:a7:a1:b4:be:06:22:3a:9b:47:
                    9b:a6:0a:67:14:1e:98:ef:e4:54:c2:d1:ce:c9:b5:
                    01:81:fb:78:d3:85:7a:47:01:20:a4:63:4a:aa:64:
                    e6:6e:2e:77:4e:2a:ba:6e:9f:d2:10:63:de:21:3f:
                    3d:ef:83:bc:86:d5:84:b8:7d:22:d0:2e:9c:84:86:
                    40:f0:3d:75:81:20:7c:0f:ea:5a:2a:fe:a5:4e:cb:
                    57:7a:61:a4:b7:86:86:e9:65:f0:6f:f3:62:64:21:
                    17:78:5e:83:46:ee:21:1e:f4:69:ab:f3:4f:c8:8b:
                    01:0a:f1:54:c3:51:64:91:06:33:02:0d:fe:da:bc:
                    62:24:f7:fb:71:19:21:c4:aa:ab:a1:80:1a:38:ae:
                    57:0d:cd:22:c5:c2:df:e0:ae:48:91:90:e4:66:c3:
                    a7:8f:4b:73:a5:56:3c:77:96:78:5b:f0:49:41:a0:
                    c4:a5:ea:e6:bd:7e:3d:1b:28:62:02:ba:4b:88:61:
                    79:c8:17:11:7e:5c:ed:1b:5a:e9:37:05:94:41:5b:
                    d1:72:bd:7e:9c:b5:76:bf:3d:2d:e1:46:c5:40:69:
                    74:3b:ca:c4:34:4b:32:6d:c5:41:e9:fc:ae:64:7f:
                    3d:24:5e:11:c2:6c:6a:a6:d4:3f:fa:bb:3d:ce:e4:
                    d1:17:c5:f4:c6:fa:01:f3:d9:7e:7a:a0:a5:82:50:
                    f8:81:52:af:d1:23:45:25:b5:c0:f7:0b:d3:7c:e8:
                    4c:fe:3b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                2.23.133.8.1
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                49:E7:4A:5B:56:29:F5:9D:79:B7:A6:30:3C:03:B2:8F:E7:14:DD:4C
            X509v3 Authority Key Identifier: 
                49:E7:4A:5B:56:29:F5:9D:79:B7:A6:30:3C:03:B2:8F:E7:14:DD:4C
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        95:f1:d1:bc:e0:77:08:9a:0b:4e:5d:58:1b:f0:2f:8c:6a:19:
        92:93:4c:ca:9e:57:e6:37:b5:20:20:90:eb:c6:f6:f7:a1:27:
        f6:12:14:95:c6:18:ff:e9:ee:10:f4:8f:52:30:c0:de:2c:f0:
        27:c0:c0:7d:5e:11:12:0a:50:ce:aa:21:e9:78:51:dd:38:32:
        7c:75:e3:27:a0:c2:ee:9b:b3:12:0b:73:17:5f:b0:1d:28:54:
        a4:1a:1e:dc:72:ae:2f:85:a1:07:7a:ef:c2:4d:92:12:cb:9d:
        06:ef:76:a3:d0:6e:06:37:03:27:f1:96:e4:64:6d:a4:3f:c7:
        ef:51:c0:13:ca:c8:f6:32:78:d6:74:b4:16:f9:24:8d:a5:f4:
        82:5b:27:b4:c5:54:5e:2c:1c:b5:af:06:23:44:0e:13:68:a3:
        b0:90:70:93:8d:6e:40:6b:74:60:e8:f6:48:69:44:c0:d0:02:
        e4:30:53:07:99:19:ef:ee:97:f7:11:84:eb:f7:3e:33:74:c0:
        03:43:8d:a1:7d:7c:ac:d7:e2:7f:de:1c:0b:1f:e6:3d:83:ac:
        f2:95:24:00:d4:40:43:86:93:44:1b:e9:06:ba:f2:19:3f:11:
        d5:a8:53:06:43:1e:45:01:b7:b5:db:0b:1d:14:fc:7c:90:85:
        50:03:5d:e5:62:d6:b2:2f:37:d3:4e:72:fd:6b:8c:cf:cf:e0:
        14:a7:34:3c:bf:85:f8:cb:9b:0a:c2:75:38:33:d3:46:c7:07:
        f7:74:25:4b:8c:c4:32:0e:61:0c:02:24:b3:e7:c3:a1:12:76:
        42:24:4e:aa:8e:c6:02:a6:d3:73:b4:93:29:f1:9c:af:df:a9:
        6b:ad:e7:6b:b7:f7:a3:2d:6c:64:f5:8f:77:10:7c:b7:1e:73:
        de:58:21:88:f3:f7:92:d4:31:ff:22:bf:d4:5c:1f:d6:18:31:
        24:71:72:ff:65:1c:68:6b:8e:5d:14:51:4c:fc:84:9e:9a:59:
        a7:cd:8a:8a:0b:3d:68:f1:d6:b5:a5:66:db:f2:eb:5d:7d:9f:
        bd:3f:62:33:f9:34:0a:8b:cd:02:3f:2b:ce:d1:f1:b1:41:28:
        03:4c:49:9d:23:89:34:fa:5e:f4:f4:5d:8e:c4:e3:ef:fb:b7:
        5e:ee:a1:40:b3:4d:89:d0:47:80:8d:c7:72:68:bb:d3:81:cc:
        31:df:f7:c9:9e:36:e0:e3:ab:4b:7d:b2:96:97:94:d6:87:90:
        1c:5a:cb:13:a8:58:5f:8f:ed:b4:c1:13:6e:61:12:20:a7:76:
        ad:38:2c:b4:fa:2d:4a:f9:2e:07:94:e5:8d:b2:98:3d:1f:a5:
        ab:b8:50:6a:fd:7a:53:81
```

The subordinate CA will ofcourse reference back to this cert:

```text
            X509v3 Authority Key Identifier: 
                49:E7:4A:5B:56:29:F5:9D:79:B7:A6:30:3C:03:B2:8F:E7:14:DD:4C
            Authority Information Access: 
                CA Issuers - URI:http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt
```


These x509 certificates are embedded that VMs in non-volatile memory and is also surfaced via GCE compute API API (see   [Retrieving endorsement keys](https://cloud.google.com/compute/shielded-vm/docs/retrieving-endorsement-key).


You can use the vTPm to encrypt data with the EK and separately sign data using the AK using just standard TPM function or helper library functions.  Once the AK signed the data, you can give that and the x509 to someone to verify later...and they can trust that it happened on a specific VM by verifying the signature using the certificate and verifying the CA chain...*critically*, the certificate includes encoded data about the specific vmID instance id and project.  You can use this to correlate the signature to a specific instnace's tpm

What this tutorial will do is 

1. create a GCP confidential-VM which includes a vTPM
2. on your laptop, acquire its AK cert
3. on your laptop, parse the AK cert and show its encoded value
4. ssh to the shielded vm and use its tpm to sign some data
5. on your laptop, verify the signature on the laptop using the attestation certificate

---

### Create VM and acquire AK/EK certificate

First create a VM

```bash
gcloud compute instances create instance-1 \
    --zone=us-central1-a \
    --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan" \
    --shielded-secure-boot --no-service-account --no-scopes \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --confidential-compute


$  gcloud compute instances get-shielded-identity  instance-1

encryptionKey:
  ekCert: |
    -----BEGIN CERTIFICATE-----
    MIIF3zCCA8egAwIBAgIUAM2PxgjR+nu3w0OfrdyQRD2ntM0wDQYJKoZIhvcNAQEL
    BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
    Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
    b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
    NDA1MDcxMTI0NDRaGA8yMDU0MDQzMDExMjQ0M1owaTEWMBQGA1UEBxMNdXMtY2Vu
    dHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQL
    Ewhjb3JlLWVzbzEcMBoGA1UEAxMTNjUyNDY5Nzk0MzAyMjc0Mzk0MTCCASIwDQYJ
    KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKuXJzxjL/P51Ft/lO2zY8ghCjXsVwOT
    a6ItODmVbeBO/zK8/seuqEmZ+PJ/Gup8p8ruk1ef6xyBA7W3XWO86JguGpJZKYU0
    zwCWUBlpGJEa4k6XElKvEv3Xhn8x+I/kT4HWV1xrbmEwJp6H+7HaNHZUugKtd1sn
    oH05TwTXNluKcjIlQqsAB57VMpUzrlBfSGBP/xuoDoVO/v5QMpH5OTNby2Y27OpE
    FGj1sE75c6h64BQNt8I5NaUfv0vQH3QLR87tWqQPtv7QxQg6+lRn9RONThrzHd+d
    WiJjzDHPUe89O55kbgVaV+/+m8JzLPZ7jWQXQz5Zrm+fv3QkcmJMruECAwEAAaOC
    AV0wggFZMA4GA1UdDwEB/wQEAwIFIDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRw
    wMZ0yA4csRve2+sn8ffRhCmqsjAfBgNVHSMEGDAWgBQEbnNYMsSlysI5BP4ze1lA
    YGjItDCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZh
    dGVjYS1jb250ZW50LTY1ZDcwM2M0LTAwMDAtMmJiNS04YzYwLTI0MDU4ODcyN2E3
    OC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzE0MTI4NGMxMThlZWRhZWMwOWY5L2Nh
    LmNydDBpBgorBgEEAdZ5AgEVBFswWQwNdXMtY2VudHJhbDEtYQIGAOevc16cDAhj
    b3JlLWVzbwIIWoxiNbiXsYUMCmluc3RhbmNlLTGgIDAeoAMCAQChAwEB/6IDAQH/
    owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQCVP4UdKTi7PNQGGDH/
    fWIw8XryYzqAWZ8ldx5bnWy6jrsCFrti3wSRGtoGuQWMCuncEYf52lvaeVr4NgzK
    FukaAjU9ptfVexF4L9cEKAdYSLctIzbNU0BhyfbN4rZIsXhCsjECc9vvZw9qdoI3
    EqrFJSyiKhnNwDXN9nkX2Pj8DAj21G5tQxXT8ucbB+8O5Y7btkqANNdV8LKE6z84
    Fh6f2/4kVYXL5/CYeXls6aLK9DAzCXNocGTXKshL6IFjJfD97wr4pW3syrgwQv5Q
    Ze5nzorGDPSiRgoLyckwjqH5/Sle4KKF49+4QPp1Qk1VjN2KAkY9RXDwM/5iE0O7
    +KCFxAwDuUX7/7xpnqTjOovyIsQnqH/V2DC5UkwD9KYibu537iadxRVzd8HQC0zJ
    ldS8W79dtUlfV/HQUR9gTkrXzsaeHrRQ/yM4OoIbowWHD8NwmPU76/EBa0M7+Pq9
    NIXYbKw29CIQQGFFZMCRq7nMwe7zMwTaetWqfmzN4qbxasLHQVcjv6ktlUu5nn1u
    Fs3B7AGgaae7E7IGafN0zX4wGDU4KDYnoMovY6sgw+8G+UutpsCICXkJ5roND22M
    +tduDHEziCxyf3IC+XpAxMjOYqVM41StPZE24gCwVNz32NNq2+rIkfehxGEK57LA
    PeIjTVLIBfNMwE570KIC+Ae/EA==
    -----END CERTIFICATE-----
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq5cnPGMv8/nUW3+U7bNj
    yCEKNexXA5Nroi04OZVt4E7/Mrz+x66oSZn48n8a6nynyu6TV5/rHIEDtbddY7zo
    mC4aklkphTTPAJZQGWkYkRriTpcSUq8S/deGfzH4j+RPgdZXXGtuYTAmnof7sdo0
    dlS6Aq13WyegfTlPBNc2W4pyMiVCqwAHntUylTOuUF9IYE//G6gOhU7+/lAykfk5
    M1vLZjbs6kQUaPWwTvlzqHrgFA23wjk1pR+/S9AfdAtHzu1apA+2/tDFCDr6VGf1
    E41OGvMd351aImPMMc9R7z07nmRuBVpX7/6bwnMs9nuNZBdDPlmub5+/dCRyYkyu
    4QIDAQAB
    -----END PUBLIC KEY-----
kind: compute#shieldedInstanceIdentity
signingKey:
  ekCert: |
    -----BEGIN CERTIFICATE-----
    MIIF3zCCA8egAwIBAgIUAO5uKOo6RYLl3C2J905G44VhK64wDQYJKoZIhvcNAQEL
    BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
    Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
    b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
    NDA1MDcxMTI0NDRaGA8yMDU0MDQzMDExMjQ0M1owaTEWMBQGA1UEBxMNdXMtY2Vu
    dHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQL
    Ewhjb3JlLWVzbzEcMBoGA1UEAxMTNjUyNDY5Nzk0MzAyMjc0Mzk0MTCCASIwDQYJ
    KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPHklrn4z7GBIWjA06vpHh/zqExRo2i
    zPLQ/d5RKr+jI5X5YVT2h9Q6NSnLyDgE9BFWonuldKzGwVPTJp0BLkeLtWt5kD1K
    0xFawF+yweoOlY9HfLuHKri4Yk0C3jWLU7oBS5f0O4Nk/CaDv+tVLx2boWVOaMtq
    //NFyq+NVjMLAVs+DTwUWp+LW2oFTZ+LzNHg7J2ZDWrnb7jLLkK2GvIHSf9kLpT0
    4781eUNuJseJQ8sb6GMF7QhGCnt4NbbarvqB8TUjtgYyyM35iO/k1ZGSkxNo0hVv
    dqEzyX750emNRw5pd6dItMUWA4fF/pt7g6lAADeh17gwwfIkjpewLFECAwEAAaOC
    AV0wggFZMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRR
    UxLX2O/6vCeNb2yGiiUfy9LbYDAfBgNVHSMEGDAWgBTpZnNUZ2Yb791lv+XoXOOR
    C5sFUjCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZh
    dGVjYS1jb250ZW50LTYzM2JlYjk0LTAwMDAtMjVjMS1hOWQ3LTAwMWExMTRiYTZl
    OC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2M1OWEyMjU4OWFiNDNhNTdlM2E0L2Nh
    LmNydDBpBgorBgEEAdZ5AgEVBFswWQwNdXMtY2VudHJhbDEtYQIGAOevc16cDAhj
    b3JlLWVzbwIIWoxiNbiXsYUMCmluc3RhbmNlLTGgIDAeoAMCAQChAwEB/6IDAQH/
    owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQBWi8Z0cOpjo4dEPAHM
    eyoryiOVcYdwc2ovLgF1eBdEvx5MA1L+m0MYJGyEMo31vGU5s068ZGiZrLTNzbsM
    kz0ZrQUF/SQfJmCUFFpWpycctJoUysXyWg5Qvtfd1eSZTJ0eIP2YAAIxvsDySE3j
    blsQJsLv7ASQbbUspNPhzni+cEGXNj3efk5qkagr2NU9Ah9xyXbSU0lwzRy5YC58
    ONvMK7GCGAMN2AMgVbV/vmwx1ja5L8tY65IG0qf8ftg+47fx6Y6IP58MJ156ny1E
    RktmC0aUW3tDQwB6jwnwvlGcjum/EnyETYYXi+IIhxuVfnP67Vgp87eeS+NOr/Tz
    Oy1FnByW8TcYvpu+1zd2nUe5dhRvjMPfShKo7guRx3WcsvfSHZFxVYFcx7pT5gp7
    70oFyM2yta0X1lv0scP54C/DjHflqJXOFLb354p//L9RaKdyK6jjkQAF+aYoPgzc
    6XfWK8DIizA6KvwePBlCbTbl+p+oztbMt5H5k5khg/5HymueztgwWqJW9JIJ+u/n
    3ijVCeC1oTPmoc40OoWdwXvBBmn1zRvwsY0DzSWPWg4ia2FIM22oQBHYJetLrsYV
    IpIXWO6C19crtyJP2yrRIix3oQ4TREBJ4UABnt38t2AU1SChrW8uY6eVPE3lKMSg
    JEAtkWH8xN4KNLyQi+HqIrOuVQ==
    -----END CERTIFICATE-----
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8eSWufjPsYEhaMDTq+k
    eH/OoTFGjaLM8tD93lEqv6MjlflhVPaH1Do1KcvIOAT0EVaie6V0rMbBU9MmnQEu
    R4u1a3mQPUrTEVrAX7LB6g6Vj0d8u4cquLhiTQLeNYtTugFLl/Q7g2T8JoO/61Uv
    HZuhZU5oy2r/80XKr41WMwsBWz4NPBRan4tbagVNn4vM0eDsnZkNaudvuMsuQrYa
    8gdJ/2QulPTjvzV5Q24mx4lDyxvoYwXtCEYKe3g1ttqu+oHxNSO2BjLIzfmI7+TV
    kZKTE2jSFW92oTPJfvnR6Y1HDml3p0i0xRYDh8X+m3uDqUAAN6HXuDDB8iSOl7As
    UQIDAQAB
    -----END PUBLIC KEY-----


# get its EK and AK
$ gcloud compute instances get-shielded-identity instance-1 --format=json | jq -r '.encryptionKey.ekCert' > ekcert.pem
$ gcloud compute instances get-shielded-identity instance-1 --format=json | jq -r '.signingKey.ekCert' > akcert.pem
```

If you decode the cert, you'll see all sorts of stuff including the `Issuer` field and several other things we'll look at later

for EK:

```bash
$ openssl x509 -in ekcert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            cd:8f:c6:08:d1:fa:7b:b7:c3:43:9f:ad:dc:90:44:3d:a7:b4:cd
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Intermediate
        Validity
            Not Before: May  7 11:24:44 2024 GMT
            Not After : Apr 30 11:24:43 2054 GMT
        Subject: L=us-central1-a, O=Google Compute Engine, OU=core-eso, CN=6524697943022743941
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ab:97
                    ae:e1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Key Encipherment
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                70:C0:C6:74:C8:0E:1C:B1:1B:DE:DB:EB:27:F1:F7:D1:84:29:AA:B2
            X509v3 Authority Key Identifier: 
                04:6E:73:58:32:C4:A5:CA:C2:39:04:FE:33:7B:59:40:60:68:C8:B4
            Authority Information Access: 
                CA Issuers - URI:http://privateca-content-65d703c4-0000-2bb5-8c60-240588727a78.storage.googleapis.com/141284c118eedaec09f9/ca.crt
            1.3.6.1.4.1.11129.2.1.21: 
us-central1-a.....s^...core-eso..Z.b5.....
instance-1. 0...............................
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        95:3f:85:1d:29:38:
```

for AK

```bash
$ openssl x509 -in akcert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ee:6e:28:ea:3a:45:82:e5:dc:2d:89:f7:4e:46:e3:85:61:2b:ae
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Intermediate
        Validity
            Not Before: May  7 11:24:44 2024 GMT
            Not After : Apr 30 11:24:43 2054 GMT
        Subject: L=us-central1-a, O=Google Compute Engine, OU=core-eso, CN=6524697943022743941
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a3:c7:92:5a:
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                51:53:12:D7:D8:EF:FA:BC:27:8D:6F:6C:86:8A:25:1F:CB:D2:DB:60
            X509v3 Authority Key Identifier: 
                E9:66:73:54:67:66:1B:EF:DD:65:BF:E5:E8:5C:E3:91:0B:9B:05:52
            Authority Information Access: 
                CA Issuers - URI:http://privateca-content-633beb94-0000-25c1-a9d7-001a114ba6e8.storage.googleapis.com/c59a22589ab43a57e3a4/ca.crt
            1.3.6.1.4.1.11129.2.1.21: 
us-central1-a.....s^...core-eso..Z.b5.....
instance-1. 0...............................
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        56:8b:c6:74:70:ea        
```

to get the ek on the device itself, you can use `tpm2_tools`:

```bash
# https://tpm2-tools.readthedocs.io/en/stable/INSTALL/
# https://github.com/salrashid123/tpm2?tab=readme-ov-file#installing-tpm2_tools-golang

# get ekcert from tpm nvram
$ tpm2_getekcertificate -X -o ECcert.bin
$ openssl x509 -in ECcert.bin -inform DER -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            cd:8f:c6:08:d1:fa:7b:b7:c3:43:9f:ad:dc:90:44:3d:a7:b4:cd
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = California, L = Mountain View, O = Google LLC, OU = Google Cloud, CN = EK/AK CA Intermediate
        Validity
            Not Before: May  7 11:24:44 2024 GMT
            Not After : Apr 30 11:24:43 2054 GMT
        Subject: L = us-central1-a, O = Google Compute Engine, OU = core-eso, CN = 6524697943022743941
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ab:97:27:
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Key Encipherment
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                70:C0:C6:74:C8:0E:1C:B1:1B:DE:DB:EB:27:F1:F7:D1:84:29:AA:B2
            X509v3 Authority Key Identifier: 
                04:6E:73:58:32:C4:A5:CA:C2:39:04:FE:33:7B:59:40:60:68:C8:B4
            Authority Information Access: 
                CA Issuers - URI:http://privateca-content-65d703c4-0000-2bb5-8c60-240588727a78.storage.googleapis.com/141284c118eedaec09f9/ca.crt
            1.3.6.1.4.1.11129.2.1.21: 
us-central1-a.....s^...core-eso..Z.b5.....
instance-1. 0...............................
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        95:3f:85:1d:29:38:

$ tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
$ tpm2_readpublic -c primary.ctx -o ek.pem -f PEM -Q

$ cat ek.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq5cnPGMv8/nUW3+U7bNj
yCEKNexXA5Nroi04OZVt4E7/Mrz+x66oSZn48n8a6nynyu6TV5/rHIEDtbddY7zo
mC4aklkphTTPAJZQGWkYkRriTpcSUq8S/deGfzH4j+RPgdZXXGtuYTAmnof7sdo0
dlS6Aq13WyegfTlPBNc2W4pyMiVCqwAHntUylTOuUF9IYE//G6gOhU7+/lAykfk5
M1vLZjbs6kQUaPWwTvlzqHrgFA23wjk1pR+/S9AfdAtHzu1apA+2/tDFCDr6VGf1
E41OGvMd351aImPMMc9R7z07nmRuBVpX7/6bwnMs9nuNZBdDPlmub5+/dCRyYkyu
4QIDAQAB
-----END PUBLIC KEY-----
```

#### Verify EK Certificate with Roots

We're going to cross check the issued certificate with google roots.


```bash
## get the EK
gcloud compute instances get-shielded-identity attestor --format=json --zone=us-central1-a | jq -r '.encryptionKey.ekCert' > ekcert.pem
## get the intermediate from the ek
curl -s $(openssl x509 -in ekcert.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out ek_intermediate.pem
curl -s $(openssl x509 -in ek_intermediate.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out ek_root.pem

### the following subordinate is for my project; your's will be different

### EK 
## Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Root
wget http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt -O ek_root.crt 

# Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Root
wget http://privateca-content-65d703c4-0000-2bb5-8c60-240588727a78.storage.googleapis.com/141284c118eedaec09f9/ca.crt -O ek_intermediate.crt

openssl x509 -in ek_intermediate.crt -text -noout

openssl x509 -inform der -in ek_intermediate.crt -out ek_intermediate.pem
openssl x509 -inform der -in ek_root.crt -out ek_root.pem
cat ek_root.pem ek_intermediate.pem > ek_chain.pem
rm ek_root.pem ek_intermediate.pem
openssl verify -verbose -CAfile ek_chain.pem  ekcert.pem 
  ekcert.pem: OK

### AK

gcloud compute instances get-shielded-identity instance-1 --format=json | jq -r '.signingKey.ekCert' > akcert.pem
curl -s $(openssl x509 -in akcert.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out ak_intermediate.pem
curl -s $(openssl x509 -in ak_intermediate.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out ak_root.pem

#### again, the subordinate will be different for you
# Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Root
wget http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt -O ak_root.crt 

# Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Intermediate
wget http://privateca-content-633beb94-0000-25c1-a9d7-001a114ba6e8.storage.googleapis.com/c59a22589ab43a57e3a4/ca.crt -O ak_intermediate.crt

openssl x509 -in ak_intermediate.crt -text -noout

### optional CRL
#  wget "http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/crl.crl" -O intermediate.crl
#  openssl crl -inform DER -text -noout -in intermediate.crl


openssl x509 -inform der -in ak_intermediate.crt -out ak_intermediate.pem
openssl x509 -inform der -in ak_root.crt -out ak_root.pem
cat ak_root.pem ak_intermediate.pem > ak_chain.pem
rm ak_root.pem ak_intermediate.pem
openssl verify -verbose -CAfile ak_chain.pem  akcert.pem 
  akcert.pem: OK
```

done!,  what that'll allow us to do is have an attested root authority that we can use later to confirm some data was infact signed by a vTPM in a GCE VM.

But...what it doesn't tell us is _which_ VM nor specifications of the TPM

..but now what is this stuff:

```bash
            1.3.6.1.4.1.11129.2.1.21: 
us-central1-a.....s^...core-eso..Z.b5.....
instance-1. 0...............................
```

well, `1.3.6.1.4.1.11129.2.1.21` is a custom OID from google that isn't registered 

so lets look the EK at it using an [asn1 parser](https://lapo.it/asn1js/#MIIF3zCCA8egAwIBAgIUAM2PxgjR-nu3w0OfrdyQRD2ntM0wDQYJKoZIhvcNAQELBQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxHb29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0yNDA1MDcxMTI0NDRaGA8yMDU0MDQzMDExMjQ0M1owaTEWMBQGA1UEBxMNdXMtY2VudHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQLEwhjb3JlLWVzbzEcMBoGA1UEAxMTNjUyNDY5Nzk0MzAyMjc0Mzk0MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKuXJzxjL_P51Ft_lO2zY8ghCjXsVwOTa6ItODmVbeBO_zK8_seuqEmZ-PJ_Gup8p8ruk1ef6xyBA7W3XWO86JguGpJZKYU0zwCWUBlpGJEa4k6XElKvEv3Xhn8x-I_kT4HWV1xrbmEwJp6H-7HaNHZUugKtd1snoH05TwTXNluKcjIlQqsAB57VMpUzrlBfSGBP_xuoDoVO_v5QMpH5OTNby2Y27OpEFGj1sE75c6h64BQNt8I5NaUfv0vQH3QLR87tWqQPtv7QxQg6-lRn9RONThrzHd-dWiJjzDHPUe89O55kbgVaV-_-m8JzLPZ7jWQXQz5Zrm-fv3QkcmJMruECAwEAAaOCAV0wggFZMA4GA1UdDwEB_wQEAwIFIDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRwwMZ0yA4csRve2-sn8ffRhCmqsjAfBgNVHSMEGDAWgBQEbnNYMsSlysI5BP4ze1lAYGjItDCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY1ZDcwM2M0LTAwMDAtMmJiNS04YzYwLTI0MDU4ODcyN2E3OC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzE0MTI4NGMxMThlZWRhZWMwOWY5L2NhLmNydDBpBgorBgEEAdZ5AgEVBFswWQwNdXMtY2VudHJhbDEtYQIGAOevc16cDAhjb3JlLWVzbwIIWoxiNbiXsYUMCmluc3RhbmNlLTGgIDAeoAMCAQChAwEB_6IDAQH_owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQCVP4UdKTi7PNQGGDH_fWIw8XryYzqAWZ8ldx5bnWy6jrsCFrti3wSRGtoGuQWMCuncEYf52lvaeVr4NgzKFukaAjU9ptfVexF4L9cEKAdYSLctIzbNU0BhyfbN4rZIsXhCsjECc9vvZw9qdoI3EqrFJSyiKhnNwDXN9nkX2Pj8DAj21G5tQxXT8ucbB-8O5Y7btkqANNdV8LKE6z84Fh6f2_4kVYXL5_CYeXls6aLK9DAzCXNocGTXKshL6IFjJfD97wr4pW3syrgwQv5QZe5nzorGDPSiRgoLyckwjqH5_Sle4KKF49-4QPp1Qk1VjN2KAkY9RXDwM_5iE0O7-KCFxAwDuUX7_7xpnqTjOovyIsQnqH_V2DC5UkwD9KYibu537iadxRVzd8HQC0zJldS8W79dtUlfV_HQUR9gTkrXzsaeHrRQ_yM4OoIbowWHD8NwmPU76_EBa0M7-Pq9NIXYbKw29CIQQGFFZMCRq7nMwe7zMwTaetWqfmzN4qbxasLHQVcjv6ktlUu5nn1uFs3B7AGgaae7E7IGafN0zX4wGDU4KDYnoMovY6sgw-8G-UutpsCICXkJ5roND22M-tduDHEziCxyf3IC-XpAxMjOYqVM41StPZE24gCwVNz32NNq2-rIkfehxGEK57LAPeIjTVLIBfNMwE570KIC-Ae_EA)


and the AK:  [as1 parser](https://lapo.it/asn1js/#MIIF3zCCA8egAwIBAgIUAO5uKOo6RYLl3C2J905G44VhK64wDQYJKoZIhvcNAQELBQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxHb29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0yNDA1MDcxMTI0NDRaGA8yMDU0MDQzMDExMjQ0M1owaTEWMBQGA1UEBxMNdXMtY2VudHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQLEwhjb3JlLWVzbzEcMBoGA1UEAxMTNjUyNDY5Nzk0MzAyMjc0Mzk0MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPHklrn4z7GBIWjA06vpHh_zqExRo2izPLQ_d5RKr-jI5X5YVT2h9Q6NSnLyDgE9BFWonuldKzGwVPTJp0BLkeLtWt5kD1K0xFawF-yweoOlY9HfLuHKri4Yk0C3jWLU7oBS5f0O4Nk_CaDv-tVLx2boWVOaMtq__NFyq-NVjMLAVs-DTwUWp-LW2oFTZ-LzNHg7J2ZDWrnb7jLLkK2GvIHSf9kLpT04781eUNuJseJQ8sb6GMF7QhGCnt4NbbarvqB8TUjtgYyyM35iO_k1ZGSkxNo0hVvdqEzyX750emNRw5pd6dItMUWA4fF_pt7g6lAADeh17gwwfIkjpewLFECAwEAAaOCAV0wggFZMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRRUxLX2O_6vCeNb2yGiiUfy9LbYDAfBgNVHSMEGDAWgBTpZnNUZ2Yb791lv-XoXOORC5sFUjCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTYzM2JlYjk0LTAwMDAtMjVjMS1hOWQ3LTAwMWExMTRiYTZlOC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2M1OWEyMjU4OWFiNDNhNTdlM2E0L2NhLmNydDBpBgorBgEEAdZ5AgEVBFswWQwNdXMtY2VudHJhbDEtYQIGAOevc16cDAhjb3JlLWVzbwIIWoxiNbiXsYUMCmluc3RhbmNlLTGgIDAeoAMCAQChAwEB_6IDAQH_owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQBWi8Z0cOpjo4dEPAHMeyoryiOVcYdwc2ovLgF1eBdEvx5MA1L-m0MYJGyEMo31vGU5s068ZGiZrLTNzbsMkz0ZrQUF_SQfJmCUFFpWpycctJoUysXyWg5Qvtfd1eSZTJ0eIP2YAAIxvsDySE3jblsQJsLv7ASQbbUspNPhzni-cEGXNj3efk5qkagr2NU9Ah9xyXbSU0lwzRy5YC58ONvMK7GCGAMN2AMgVbV_vmwx1ja5L8tY65IG0qf8ftg-47fx6Y6IP58MJ156ny1ERktmC0aUW3tDQwB6jwnwvlGcjum_EnyETYYXi-IIhxuVfnP67Vgp87eeS-NOr_TzOy1FnByW8TcYvpu-1zd2nUe5dhRvjMPfShKo7guRx3WcsvfSHZFxVYFcx7pT5gp770oFyM2yta0X1lv0scP54C_DjHflqJXOFLb354p__L9RaKdyK6jjkQAF-aYoPgzc6XfWK8DIizA6KvwePBlCbTbl-p-oztbMt5H5k5khg_5HymueztgwWqJW9JIJ-u_n3ijVCeC1oTPmoc40OoWdwXvBBmn1zRvwsY0DzSWPWg4ia2FIM22oQBHYJetLrsYVIpIXWO6C19crtyJP2yrRIix3oQ4TREBJ4UABnt38t2AU1SChrW8uY6eVPE3lKMSgJEAtkWH8xN4KNLyQi-HqIrOuVQ)


(you can also parse the certs using openssl)
```bash
$ openssl asn1parse -inform pem -in akcert.pem
```

![images/asn.png](images/asn.png)


The decoded structure shows some interesting stuff:

```bash
          extnID OBJECT IDENTIFIER 1.3.6.1.4.1.11129.2.1.21
          extnValue OCTET STRING (91 byte) 30590C0D75732D63656E7472616C312D61020600E7AF735E9C0C08636F72652D65736F…
            SEQUENCE (6 elem)
              UTF8String us-central1-a
              INTEGER (40 bit) 995081019036
              UTF8String core-eso
              INTEGER (63 bit) 6524697943022743941
              UTF8String instance-1
              [0] (1 elem)
                SEQUENCE (6 elem)
                  [0] (1 elem)
                    INTEGER 0
                  [1] (1 elem)
                    BOOLEAN true
                  [2] (1 elem)
                    BOOLEAN true
                  [3] (1 elem)
                    BOOLEAN false
                  [4] (1 elem)
                    BOOLEAN false
                  [5] (1 elem)
                    BOOLEAN false
```


Remember we created an instance called `instance-1` ...that seems to be right there in encoded form as the extension...and you're right; Google EK certs encodes the `instanceName`, `instanceID`, `projectName` and `projectNumber` _into the cert_....

The encoding allows you to verify that "this specific instance on GCP in this project and zone signed some data with its vTPM"

To note, the `SAN` extension is *NOT* present in the EK or AK contradictory to section [3.2.9 Subject Alternative Name](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf)


### Sign with vTPM AK Cert

To do the real test, we need to sign something on the VM using its TPM:

On the shielded VM, install `golang`, then run `example/sign/main.go`

```bash
$ cd sign/
$ go run main.go 


      2024/05/07 12:54:11 ======= Init  ========
      2024/05/07 12:54:11 0 handles flushed
      2024/05/07 12:54:11      Load SigningKey and Certifcate 
      2024/05/07 12:54:11      Signing PEM 
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8eSWufjPsYEhaMDTq+k
      eH/OoTFGjaLM8tD93lEqv6MjlflhVPaH1Do1KcvIOAT0EVaie6V0rMbBU9MmnQEu
      R4u1a3mQPUrTEVrAX7LB6g6Vj0d8u4cquLhiTQLeNYtTugFLl/Q7g2T8JoO/61Uv
      HZuhZU5oy2r/80XKr41WMwsBWz4NPBRan4tbagVNn4vM0eDsnZkNaudvuMsuQrYa
      8gdJ/2QulPTjvzV5Q24mx4lDyxvoYwXtCEYKe3g1ttqu+oHxNSO2BjLIzfmI7+TV
      kZKTE2jSFW92oTPJfvnR6Y1HDml3p0i0xRYDh8X+m3uDqUAAN6HXuDDB8iSOl7As
      UQIDAQAB
      -----END PUBLIC KEY-----
      2024/05/07 12:54:11      Signing Certificate 
      -----BEGIN CERTIFICATE-----
      MIIF3zCCA8egAwIBAgIUAO5uKOo6RYLl3C2J905G44VhK64wDQYJKoZIhvcNAQEL
      BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
      Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
      b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
      NDA1MDcxMTI0NDRaGA8yMDU0MDQzMDExMjQ0M1owaTEWMBQGA1UEBxMNdXMtY2Vu
      dHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQL
      Ewhjb3JlLWVzbzEcMBoGA1UEAxMTNjUyNDY5Nzk0MzAyMjc0Mzk0MTCCASIwDQYJ
      KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPHklrn4z7GBIWjA06vpHh/zqExRo2i
      zPLQ/d5RKr+jI5X5YVT2h9Q6NSnLyDgE9BFWonuldKzGwVPTJp0BLkeLtWt5kD1K
      0xFawF+yweoOlY9HfLuHKri4Yk0C3jWLU7oBS5f0O4Nk/CaDv+tVLx2boWVOaMtq
      //NFyq+NVjMLAVs+DTwUWp+LW2oFTZ+LzNHg7J2ZDWrnb7jLLkK2GvIHSf9kLpT0
      4781eUNuJseJQ8sb6GMF7QhGCnt4NbbarvqB8TUjtgYyyM35iO/k1ZGSkxNo0hVv
      dqEzyX750emNRw5pd6dItMUWA4fF/pt7g6lAADeh17gwwfIkjpewLFECAwEAAaOC
      AV0wggFZMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRR
      UxLX2O/6vCeNb2yGiiUfy9LbYDAfBgNVHSMEGDAWgBTpZnNUZ2Yb791lv+XoXOOR
      C5sFUjCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZh
      dGVjYS1jb250ZW50LTYzM2JlYjk0LTAwMDAtMjVjMS1hOWQ3LTAwMWExMTRiYTZl
      OC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2M1OWEyMjU4OWFiNDNhNTdlM2E0L2Nh
      LmNydDBpBgorBgEEAdZ5AgEVBFswWQwNdXMtY2VudHJhbDEtYQIGAOevc16cDAhj
      b3JlLWVzbwIIWoxiNbiXsYUMCmluc3RhbmNlLTGgIDAeoAMCAQChAwEB/6IDAQH/
      owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQBWi8Z0cOpjo4dEPAHM
      eyoryiOVcYdwc2ovLgF1eBdEvx5MA1L+m0MYJGyEMo31vGU5s068ZGiZrLTNzbsM
      kz0ZrQUF/SQfJmCUFFpWpycctJoUysXyWg5Qvtfd1eSZTJ0eIP2YAAIxvsDySE3j
      blsQJsLv7ASQbbUspNPhzni+cEGXNj3efk5qkagr2NU9Ah9xyXbSU0lwzRy5YC58
      ONvMK7GCGAMN2AMgVbV/vmwx1ja5L8tY65IG0qf8ftg+47fx6Y6IP58MJ156ny1E
      RktmC0aUW3tDQwB6jwnwvlGcjum/EnyETYYXi+IIhxuVfnP67Vgp87eeS+NOr/Tz
      Oy1FnByW8TcYvpu+1zd2nUe5dhRvjMPfShKo7guRx3WcsvfSHZFxVYFcx7pT5gp7
      70oFyM2yta0X1lv0scP54C/DjHflqJXOFLb354p//L9RaKdyK6jjkQAF+aYoPgzc
      6XfWK8DIizA6KvwePBlCbTbl+p+oztbMt5H5k5khg/5HymueztgwWqJW9JIJ+u/n
      3ijVCeC1oTPmoc40OoWdwXvBBmn1zRvwsY0DzSWPWg4ia2FIM22oQBHYJetLrsYV
      IpIXWO6C19crtyJP2yrRIix3oQ4TREBJ4UABnt38t2AU1SChrW8uY6eVPE3lKMSg
      JEAtkWH8xN4KNLyQi+HqIrOuVQ==
      -----END CERTIFICATE-----
      2024/05/07 12:54:11      AK Signed Data using go-tpm-tools BNrf0I+fqazvHpU1DroT+Sroi+b+Ebf891Kh6WXtPC9V566/IEQQJjaeL/0etIMt+gBpHo7upC1cPwiJFxGLZ4pp1ncJOY2PaMfBbVl7da6QvTVYLOuc0u3MFrE7DQh358bWzgH5YnL892HPrPInUrtM1DujcwaYEjgmulzMrgIXbQV7rnCRuqgR6JZl0s3sgVXiJFj1XKJLNs/wgGi5WJu9DTpEgstWSaxXzpMh9gvA2C73uxUtTuHGVFI1FMryu9QRcjIgWG+SxRfhSnhh8MS596U6aSx54F6fI2gWTWhgZf6KQBWVDm70TP1+aEr5Q4C6uLK3rxBj9H2ODISl/g
      2024/05/07 12:54:11      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
      2024/05/07 12:54:11      AK Signed Data BNrf0I+fqazvHpU1DroT+Sroi+b+Ebf891Kh6WXtPC9V566/IEQQJjaeL/0etIMt+gBpHo7upC1cPwiJFxGLZ4pp1ncJOY2PaMfBbVl7da6QvTVYLOuc0u3MFrE7DQh358bWzgH5YnL892HPrPInUrtM1DujcwaYEjgmulzMrgIXbQV7rnCRuqgR6JZl0s3sgVXiJFj1XKJLNs/wgGi5WJu9DTpEgstWSaxXzpMh9gvA2C73uxUtTuHGVFI1FMryu9QRcjIgWG+SxRfhSnhh8MS596U6aSx54F6fI2gWTWhgZf6KQBWVDm70TP1+aEr5Q4C6uLK3rxBj9H2ODISl/g
      2024/05/07 12:54:11      Signature Verified

```

Copy the `AK Signed Data` field (they should be the same) to your laptop


### Verify with AK Cert 

You can take the signed data and verify it anywhere if you have the certificate alone (`akcert.pem`)


```bash
$ go run main.go \
   --akCert=../certs/akcert.pem \
   --dataSigned=foobar \
   --signature="BNrf0I+fqazvHpU1DroT+Sroi+b+Ebf891Kh6WXtPC9V566/IEQQJjaeL/0etIMt+gBpHo7upC1cPwiJFxGLZ4pp1ncJOY2PaMfBbVl7da6QvTVYLOuc0u3MFrE7DQh358bWzgH5YnL892HPrPInUrtM1DujcwaYEjgmulzMrgIXbQV7rnCRuqgR6JZl0s3sgVXiJFj1XKJLNs/wgGi5WJu9DTpEgstWSaxXzpMh9gvA2C73uxUtTuHGVFI1FMryu9QRcjIgWG+SxRfhSnhh8MS596U6aSx54F6fI2gWTWhgZf6KQBWVDm70TP1+aEr5Q4C6uLK3rxBj9H2ODISl/g" 


    2024/05/07 08:55:17 VM InstanceName from AK cert:  instance-1
    2024/05/07 08:55:17 Verify with EKcert with chain
    2024/05/07 08:55:17 Verified Certificate Chain
    2024/05/07 08:55:17 Verifying signature BNrf0I+fqazvHpU1DroT+Sroi+b+Ebf891Kh6WXtPC9V566/IEQQJjaeL/0etIMt+gBpHo7upC1cPwiJFxGLZ4pp1ncJOY2PaMfBbVl7da6QvTVYLOuc0u3MFrE7DQh358bWzgH5YnL892HPrPInUrtM1DujcwaYEjgmulzMrgIXbQV7rnCRuqgR6JZl0s3sgVXiJFj1XKJLNs/wgGi5WJu9DTpEgstWSaxXzpMh9gvA2C73uxUtTuHGVFI1FMryu9QRcjIgWG+SxRfhSnhh8MS596U6aSx54F6fI2gWTWhgZf6KQBWVDm70TP1+aEr5Q4C6uLK3rxBj9H2ODISl/g
    2024/05/07 08:55:17      Signature Verified

```

Notice we used the certificate where we have the encoded runtime instance data visible and that we could cryptographically verify a given VM did sign our data.

### Sign JWT with TPM

You can also sign a JWT using the AK Key and `github.com/salrashid123/golang-jwt-tpm`

[golang-jwt for Trusted Platform Module (TPM) - Sign/Verify with GCP builtin AKCert ](https://github.com/salrashid123/golang-jwt-tpm?tab=readme-ov-file#signverify-with-gcp-builtin-akcert)

```bash
cd example/jwt
$ go run main.go 

    2024/05/07 13:06:36 ======= Init  ========
    2024/05/07 13:06:36 0 handles flushed
    2024/05/07 13:06:36      Load SigningKey and Certifcate 
    2024/05/07 13:06:36      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8eSWufjPsYEhaMDTq+k
    eH/OoTFGjaLM8tD93lEqv6MjlflhVPaH1Do1KcvIOAT0EVaie6V0rMbBU9MmnQEu
    R4u1a3mQPUrTEVrAX7LB6g6Vj0d8u4cquLhiTQLeNYtTugFLl/Q7g2T8JoO/61Uv
    HZuhZU5oy2r/80XKr41WMwsBWz4NPBRan4tbagVNn4vM0eDsnZkNaudvuMsuQrYa
    8gdJ/2QulPTjvzV5Q24mx4lDyxvoYwXtCEYKe3g1ttqu+oHxNSO2BjLIzfmI7+TV
    kZKTE2jSFW92oTPJfvnR6Y1HDml3p0i0xRYDh8X+m3uDqUAAN6HXuDDB8iSOl7As
    UQIDAQAB
    -----END PUBLIC KEY-----
    2024/05/07 13:06:36      Signing Certificate 
    -----BEGIN CERTIFICATE-----
    MIIF3zCCA8egAwIBAgIUAO5uKOo6RYLl3C2J905G44VhK64wDQYJKoZIhvcNAQEL
    BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
    Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
    b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
    NDA1MDcxMTI0NDRaGA8yMDU0MDQzMDExMjQ0M1owaTEWMBQGA1UEBxMNdXMtY2Vu
    dHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQL
    Ewhjb3JlLWVzbzEcMBoGA1UEAxMTNjUyNDY5Nzk0MzAyMjc0Mzk0MTCCASIwDQYJ
    KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPHklrn4z7GBIWjA06vpHh/zqExRo2i
    zPLQ/d5RKr+jI5X5YVT2h9Q6NSnLyDgE9BFWonuldKzGwVPTJp0BLkeLtWt5kD1K
    0xFawF+yweoOlY9HfLuHKri4Yk0C3jWLU7oBS5f0O4Nk/CaDv+tVLx2boWVOaMtq
    //NFyq+NVjMLAVs+DTwUWp+LW2oFTZ+LzNHg7J2ZDWrnb7jLLkK2GvIHSf9kLpT0
    4781eUNuJseJQ8sb6GMF7QhGCnt4NbbarvqB8TUjtgYyyM35iO/k1ZGSkxNo0hVv
    dqEzyX750emNRw5pd6dItMUWA4fF/pt7g6lAADeh17gwwfIkjpewLFECAwEAAaOC
    AV0wggFZMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRR
    UxLX2O/6vCeNb2yGiiUfy9LbYDAfBgNVHSMEGDAWgBTpZnNUZ2Yb791lv+XoXOOR
    C5sFUjCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZh
    dGVjYS1jb250ZW50LTYzM2JlYjk0LTAwMDAtMjVjMS1hOWQ3LTAwMWExMTRiYTZl
    OC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2M1OWEyMjU4OWFiNDNhNTdlM2E0L2Nh
    LmNydDBpBgorBgEEAdZ5AgEVBFswWQwNdXMtY2VudHJhbDEtYQIGAOevc16cDAhj
    b3JlLWVzbwIIWoxiNbiXsYUMCmluc3RhbmNlLTGgIDAeoAMCAQChAwEB/6IDAQH/
    owMBAQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQBWi8Z0cOpjo4dEPAHM
    eyoryiOVcYdwc2ovLgF1eBdEvx5MA1L+m0MYJGyEMo31vGU5s068ZGiZrLTNzbsM
    kz0ZrQUF/SQfJmCUFFpWpycctJoUysXyWg5Qvtfd1eSZTJ0eIP2YAAIxvsDySE3j
    blsQJsLv7ASQbbUspNPhzni+cEGXNj3efk5qkagr2NU9Ah9xyXbSU0lwzRy5YC58
    ONvMK7GCGAMN2AMgVbV/vmwx1ja5L8tY65IG0qf8ftg+47fx6Y6IP58MJ156ny1E
    RktmC0aUW3tDQwB6jwnwvlGcjum/EnyETYYXi+IIhxuVfnP67Vgp87eeS+NOr/Tz
    Oy1FnByW8TcYvpu+1zd2nUe5dhRvjMPfShKo7guRx3WcsvfSHZFxVYFcx7pT5gp7
    70oFyM2yta0X1lv0scP54C/DjHflqJXOFLb354p//L9RaKdyK6jjkQAF+aYoPgzc
    6XfWK8DIizA6KvwePBlCbTbl+p+oztbMt5H5k5khg/5HymueztgwWqJW9JIJ+u/n
    3ijVCeC1oTPmoc40OoWdwXvBBmn1zRvwsY0DzSWPWg4ia2FIM22oQBHYJetLrsYV
    IpIXWO6C19crtyJP2yrRIix3oQ4TREBJ4UABnt38t2AU1SChrW8uY6eVPE3lKMSg
    JEAtkWH8xN4KNLyQi+HqIrOuVQ==
    -----END CERTIFICATE-----
    TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6IkpwMG5vOHM0RHAwa3c1OEx5Zklpem9TVC9jQmtpMS9LTnFCeERLeEM1c1E9IiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE1MDg3Nzk2fQ.hQ1n5hNeb-NzLOPYtquVQDTHfa6rRO-sZOoMz3CXzexxOqETmjBz331IfbtpcqoCZkNfXT3f4Xr41iF0_KRQet1_BolJQsRiUp9-g2MPijmY99ACkXet4ajRBAlvBaJrWXLDfSnd_GclpBT7n1a5kRuvSDT7w-UwKlIfbIQ6vQoS-KzuOdAi9klQ3ERpo1MDi6yF2iha5HrVqNRBHHrjr6dXNV2KeCNzzmck41NyIPXZ3BoGIWb2y8FkxsbX3hMylk8i8B-H_D8HyA2FXkXacBjMXzLg8w8Gv2HOh3zOVg08Ub9r0HnoX_PFnt74eMgN2cIxMLJ58VWv8CKTdDccvA
    2024/05/07 13:06:36      verified with Signer PublicKey
    2024/05/07 13:06:36      verified with exported PubicKey

```

the JWT value decodes to:

```json
{
  "alg": "RS256",
  "kid": "Jp0no8s4Dp0kw58LyfIizoST/cBki1/KNqBxDKxC5sQ=",
  "typ": "JWT"
}
{
  "iss": "test",
  "exp": 1715087796
}
```

Where just by convention i'm using,  the keyID is the base64 encoded sha556 value of the DER public key (eg, key fingerprint)

```bash
$ gcloud compute instances get-shielded-identity instance-1 --format=json | jq -r '.signingKey.ekPub' > akpub.pem
$ openssl rsa -pubin -in akpub.pem -outform DER | openssl sha256
    writing RSA key
    SHA256(stdin)= 269d27a3cb380e9d24c39f0bc9f222ce8493fdc0648b5fca36a0710cac42e6c4

# base64 of hex SHA256(stdin)= 269d27a3cb380e9d24c39f0bc9f222ce8493fdc0648b5fca36a0710cac42e6c4 --> Jp0no8s4Dp0kw58LyfIizoST/cBki1/KNqBxDKxC5sQ=
```

---

#### References

- [Sealing RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys)

  This allows you to use the EK to securely transfer some data such that it can only get decrypted by that target VM

- [Read EK from NV](https://github.com/salrashid123/tpm2/tree/master/gcp_ek_ak)

  The AK/EK templates are sealed to non-volatile area of GCP vms.  If you wanted to acquire them directly on the VM, use this

- [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)

  This allows you to securely connect to a Confidential VM after attestation

- [Kubernetes Trusted Platform Module (TPM) using Device Plugin and Gatekeeper](https://github.com/salrashid123/tpm_kubernetes)

  Access the vTPM from GKE using a device plugin

- [Kubernetes Trusted Platform Module (TPM) DaemonSet](https://github.com/salrashid123/tpm_daemonset)

  Access the vTPM from GKE indirectly from a daemonset
  
- [Go-TPM-Wrapping - Go library for encrypting values through Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)

  Envelope encryption using go-tpm-wrapping library adapted to use vTPM's EK key

- [TPM and PKCS-11 backed crypto/rand Reader](https://github.com/salrashid123/tpmrand)

  Just get real random stuff in go

- [Sign with AK saved to NV (gce only)](https://github.com/salrashid123/tpm2/tree/master/ak_sign_nv)

  Sign data with GCE's AK saved to NVRAM

- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)

  Generic samples using go-tpm and tpm2_tools

- [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)

  If you wanted to create and verify a JWT signed by a TPM.  see [Sign/Verify with GCP builtin AKCert](https://github.com/salrashid123/golang-jwt-tpm/blob/main/README.md#signverify-with-gcp-builtin-akcert)

- [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)

  Access GCP resources where the private key is saved inside a vTPM

- [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)

  gRPC implementation of Remote Attestation from scratch.  THis is the long form way to acquire an AK.  In GCP, the AK is already provided to you.
- [OCICrypt provider for Trusted Platform Modules (TPM)](https://github.com/salrashid123/ocicrypt-tpm-keyprovider)

  If you wanted to encrypt an OCI container image such that it can only get decrypted on a target VM (the vm need not be on gcp)

- [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)

- [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)

---
