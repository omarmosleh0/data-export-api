#!/bin/bash
# Deploy Data Export Api to Cloud Run

# Configuration
PROJECT_ID="wileyconnect"
REGION="us-west1"
SERVICE_NAME="data-export-api"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"
CLOUD_SQL_INSTANCE="${PROJECT_ID}:${REGION}:postgres"

echo "🚀 Deploying Query Engine to Cloud Run..."
echo "Project: ${PROJECT_ID}"
echo "Region: ${REGION}"
echo "Service: ${SERVICE_NAME}"
echo ""

# Deploy
gcloud run deploy ${SERVICE_NAME} \
  --image=${IMAGE} \
  --region=${REGION} \
  --platform=managed \
  --allow-unauthenticated \
  --add-cloudsql-instances=${CLOUD_SQL_INSTANCE} \
  --set-env-vars="DB_SOCKET_PATH=/cloudsql/${CLOUD_SQL_INSTANCE},DB_NAME=postgres,DB_USER=postgres,GCS_EXPORT_BUCKET=wiley-data-exports,DB_POOL_SIZE=10,DB_MAX_OVERFLOW=5" \
  --set-secrets="DB_PASS=db-password:latest,JWT_ISSUER=jwt-issuer:latest,JWT_AUDIENCE=jwt-audience:latest" \
  --memory=2Gi \
  --cpu=2 \
  --timeout=3600 \
  --max-instances=10 \
  --min-instances=0 \
  --concurrency=80

# Check deployment status
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Deployment successful!"
    echo ""
    echo "Getting service URL..."
    SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
      --region=${REGION} \
      --format='value(status.url)')
    
    echo ""
    echo "🌐 Service URL: ${SERVICE_URL}"
    echo ""
    echo "Test with:"
    echo "curl ${SERVICE_URL}/"
else
    echo ""
    echo "❌ Deployment failed!"
    exit 1
fi