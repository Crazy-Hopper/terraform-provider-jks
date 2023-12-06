terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "~> 3.1.0"
    }
    jks = {
      source  = "hashicorp.com/Crazy-Hopper/jks"
      version = "= 0.8.1"
    }
  }
}

provider "tls" {
}

provider "jks" {
}

resource "tls_private_key" "ca" {
  algorithm = "ECDSA"
}

resource "tls_self_signed_cert" "ca" {
  key_algorithm   = tls_private_key.ca.algorithm
  private_key_pem = tls_private_key.ca.private_key_pem

  validity_period_hours = 12
  early_renewal_hours   = 3

  is_ca_certificate = true
  allowed_uses      = [
    "cert_signing",
    "crl_signing",
  ]

  subject {
    common_name  = "Cluster TLS Root CA"
    organization = "YourOrg, Inc."
  }

  set_subject_key_id = true
}

resource "jks_trust_store" "this" {
  certificates = [
    tls_self_signed_cert.ca.cert_pem
  ]
}

resource "jks_key_store" "this" {
  certificate_chain = [
    tls_self_signed_cert.ca.cert_pem
  ]
  ca          = tls_self_signed_cert.ca.cert_pem
  private_key = tls_private_key.ca.private_key_pem
  password    = "none"
}

output "ca_trust_store_jks" {
  value = jks_trust_store.this.jks
}

output "ca_key_store_jks" {
  value = jks_key_store.this.jks
}

output "ca_pem" {
  value = tls_self_signed_cert.ca.cert_pem
}
