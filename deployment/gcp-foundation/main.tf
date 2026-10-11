# REVIEW ONLY. No terraform apply, billing link or cloud plan has been run.
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
provider "google" {
  project = var.project_id
  region  = var.region
}
variable "project_id" {
  type        = string
  description = "Explicit owner-approved project; no personal account or project identifier is shipped."
}
variable "region" {
  type        = string
  description = "Owner-approved region; no default chosen."
}
resource "google_project_service" "apis" {
  for_each           = toset(["run.googleapis.com", "artifactregistry.googleapis.com", "cloudkms.googleapis.com", "secretmanager.googleapis.com", "compute.googleapis.com"])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
resource "google_service_account" "owner" {
  account_id   = "signet-owner"
  display_name = "Signet protected owner service"
}
resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "signet"
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}
resource "google_kms_key_ring" "owner" {
  name       = "signet-owner"
  location   = var.region
  depends_on = [google_project_service.apis]
}
resource "google_kms_crypto_key" "owner" {
  name     = "owner-approval"
  key_ring = google_kms_key_ring.owner.id
  purpose  = "ASYMMETRIC_SIGN"
  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = "SOFTWARE"
  }
  lifecycle { prevent_destroy = true }
}
# Deliberately no signing IAM grant yet: decide the isolated signer identity,
# exact pinned version and complete authenticated KMS transport before granting.
# No billing link, bucket credentials, Cloud Run service, ingress or DNS here.
