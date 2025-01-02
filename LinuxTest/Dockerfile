#Dockerfile that will deploy a linux container that will have a certificate installed on it and will execute multiple curl commands
#to test the certificate installation.

#Pulling the base image
FROM ubuntu:latest

USER root

#Installing curl
RUN apt-get update && apt-get install -y curl

#Copying the certificate to the container
#COPY mitmproxy-ca-cert.cer /usr/local/share/ca-certificates/mitmproxy-ca-cert.cer
COPY mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.pem

#Updating the certificate store
RUN openssl x509 -in /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.pem -inform PEM -out /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.crt
RUN rm /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.pem
RUN update-ca-certificates

# Running curl commands to test the certificate installation
CMD curl -v --proxy http://172.17.0.2:8080 http://example.com && curl -v --proxy http://172.17.0.2:8080 https://example.com