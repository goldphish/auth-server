# Envoy Client TLS Auth Server

A barebones hacky server which reads a directory full of client x509
certificates and fingerprints them. This implements the Envoy client_ssl_auth
API and serves said fingerprints.
