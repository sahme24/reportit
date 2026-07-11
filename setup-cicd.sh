#!/bin/bash
# One-time setup: grants Cloud Build's service account permission to deploy
# to Cloud Run. Run this once, after connecting the GitHub repo and creating
# the trigger in the Cloud Build console (see README.md's "Auto-deploy on
# push" section) but before the first automatic deploy fires.
#
# Usage:
#   chmod +x setup-cicd.sh
#   ./setup-cicd.sh

set -e

PROJECT_ID="exalted-pattern-502023-i8"

echo "==> Using project: $PROJECT_ID"
gcloud config set project "$PROJECT_ID" >/dev/null

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
CLOUDBUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

echo "==> Granting Cloud Build ($CLOUDBUILD_SA) permission to deploy to Cloud Run"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$CLOUDBUILD_SA" \
  --role="roles/run.admin" \
  --condition=None \
  >/dev/null

echo "==> Granting Cloud Build permission to push built images to Artifact Registry"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$CLOUDBUILD_SA" \
  --role="roles/artifactregistry.writer" \
  --condition=None \
  >/dev/null

echo "==> Granting Cloud Build permission to act as the Cloud Run runtime service account"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$CLOUDBUILD_SA" \
  --role="roles/iam.serviceAccountUser" \
  --condition=None \
  >/dev/null

echo ""
echo "==> Done. Push to main and check the build at:"
echo "    https://console.cloud.google.com/cloud-build/builds?project=$PROJECT_ID"
