#!/bin/bash
# Deploys ReportIT.ai to Google Cloud Run.
# Run this from the repo root, where .env already lives.
#
# Prereqs (one-time, do these first if you haven't):
#   gcloud auth login
#   gcloud config set project exalted-pattern-502023-i8
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh

set -e

PROJECT_ID="exalted-pattern-502023-i8"
REGION="us-central1"
BUCKET="${PROJECT_ID}-reportit-data"

echo "==> Using project: $PROJECT_ID"
gcloud config set project "$PROJECT_ID" >/dev/null

# Load secrets from .env without printing them anywhere
if [ ! -f .env ]; then
  echo "ERROR: .env not found. Run this from the repo root."
  exit 1
fi
set -a
source .env
set +a

# --- 0. Enable required APIs (avoids interactive y/N prompts later) --------
echo "==> Enabling required APIs (first run only, takes ~1 min)"
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  storage.googleapis.com \
  --project="$PROJECT_ID"

# Newly enabled APIs (especially Secret Manager) can take a minute to
# actually propagate even after the enable command reports success.
echo "==> Waiting 30s for API enablement to propagate"
sleep 30

# --- 1. Storage bucket for the SQLite file (idempotent) --------------------
echo "==> Ensuring bucket gs://$BUCKET exists"
gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1 || \
  gcloud storage buckets create "gs://$BUCKET" --location="$REGION"

# --- 2. Secrets (create if missing, add a new version if they exist) -------
create_or_update_secret () {
  local name="$1"
  local value="$2"
  if [ -z "$value" ]; then
    echo "==> Skipping $name (no value in .env)"
    return
  fi
  local attempt=1
  while [ "$attempt" -le 3 ]; do
    if gcloud secrets describe "$name" >/dev/null 2>&1; then
      echo "==> Updating secret $name"
      printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- && return
    else
      echo "==> Creating secret $name (attempt $attempt)"
      printf '%s' "$value" | gcloud secrets create "$name" --data-file=- && return
    fi
    echo "    ...API may still be propagating, retrying in 15s"
    sleep 15
    attempt=$((attempt + 1))
  done
  echo "ERROR: could not create/update secret $name after 3 attempts"
  exit 1
}

create_or_update_secret reportit-google-client-id     "$GOOGLE_CLIENT_ID"
create_or_update_secret reportit-google-client-secret  "$GOOGLE_CLIENT_SECRET"
create_or_update_secret reportit-anthropic-key         "$ANTHROPIC_API_KEY"
create_or_update_secret reportit-vt-key                "$VT_API_KEY"
create_or_update_secret reportit-abuseipdb-key         "$ABUSEIPDB_API_KEY"
create_or_update_secret reportit-urlhaus-key           "$URLHAUS_API_KEY"

# Build the --set-secrets list, only including keys that actually exist
SECRETS="GOOGLE_CLIENT_ID=reportit-google-client-id:latest,GOOGLE_CLIENT_SECRET=reportit-google-client-secret:latest"
[ -n "$ANTHROPIC_API_KEY" ] && SECRETS="$SECRETS,ANTHROPIC_API_KEY=reportit-anthropic-key:latest"
[ -n "$VT_API_KEY" ] && SECRETS="$SECRETS,VT_API_KEY=reportit-vt-key:latest"
[ -n "$ABUSEIPDB_API_KEY" ] && SECRETS="$SECRETS,ABUSEIPDB_API_KEY=reportit-abuseipdb-key:latest"
[ -n "$URLHAUS_API_KEY" ] && SECRETS="$SECRETS,URLHAUS_API_KEY=reportit-urlhaus-key:latest"

# --- 2b. Let Cloud Run's service account read the secrets ------------------
# Creating a secret doesn't automatically grant access to it -- Cloud Run's
# default compute service account needs Secret Manager Secret Accessor
# explicitly, or the revision fails at startup with "Permission denied".
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
echo "==> Granting Secret Manager access to $COMPUTE_SA"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$COMPUTE_SA" \
  --role="roles/secretmanager.secretAccessor" \
  --condition=None \
  >/dev/null

# --- 3. Deploy ---------------------------------------------------------------
# --add-volume contains "/data", which Git Bash on Windows would otherwise
# rewrite into a Windows path before gcloud sees it. MSYS_NO_PATHCONV=1
# disables that GLOBALLY, which also breaks gcloud's own internal Python
# bootstrap (it relies on that same conversion for its own paths) -- that's
# what caused the "can't open file C:\c\Program Files..." error. Excluding
# just the --add-volume flag by name avoids touching anything else.
echo "==> Deploying to Cloud Run"
MSYS2_ARG_CONV_EXCL="--add-volume" gcloud run deploy reportit \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=1 \
  --add-volume=mount-path=/data,type=cloud-storage,bucket="$BUCKET",readonly=false \
  --set-secrets="$SECRETS"

echo ""
echo "==> Done. Copy the service URL printed above and add:"
echo "    <that-url>/auth/google/callback"
echo "    as an authorized redirect URI at:"
echo "    https://console.cloud.google.com/apis/credentials"
