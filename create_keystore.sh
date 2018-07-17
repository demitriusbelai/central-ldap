#!/bin/bash

SSLCertificateFile=/etc/ssl/certs/ssl-cert-snakeoil.pem
SSLCertificateKeyFile=/etc/ssl/private/ssl-cert-snakeoil.key
#SSLCACertificateFile=/etc/apache2/ssl.crt/ca-bundle.crt

#openssl pkcs12 -export -in "$SSLCertificateFile" -inkey "$SSLCertificateKeyFile" -CAfile "$SSLCACertificateFile" -caname ca -out keystore.p12 -name server -passout pass:changeit
openssl pkcs12 -export -in "$SSLCertificateFile" -inkey "$SSLCertificateKeyFile" -out keystore.p12 -name server -passout pass:changeit
