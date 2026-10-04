# Vault: enterprise SPIRE issuing CA (pki_spire) + dynamic database credentials for agents.
ui            = true
disable_mlock = true
api_addr      = "https://vault:8200"

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/pki/tls/vault-fullchain.crt"
  tls_key_file  = "/pki/tls/vault.key"
  # SVIDs chain to the enterprise root, so Vault could also authenticate agents by cert.
  tls_client_ca_file                 = "/pki/tls/trust-anchor.pem"
  tls_require_and_verify_client_cert = false
}
