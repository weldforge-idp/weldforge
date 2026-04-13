# Infrastructure - intelli-sso

AWS EKS deployment for the intelli-sso project with TeamCity CI/CD.

## Architecture

- **CI/CD Cluster** (`intelli-cicd`): TeamCity Server + PostgreSQL + auto-scaling agents
- **SSO Cluster** (`intelli-sso`): Spring Boot API + Angular Frontend + PostgreSQL

Both clusters run in `af-south-1` (Cape Town).

## Prerequisites

### 1. Install Tools

```bash
# AWS CLI v2
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /

# Terraform
brew install terraform

# kubectl
brew install kubectl

# aws-iam-authenticator (for EKS auth)
brew install aws-iam-authenticator
```

### 2. Configure AWS

```bash
aws configure
# AWS Access Key ID: <your-key>
# AWS Secret Access Key: <your-secret>
# Default region: af-south-1
# Output format: json
```

> **Note:** The `af-south-1` region must be enabled in your AWS account. Go to AWS Console > Account > Regions and enable "Africa (Cape Town)" if not already active.

### 3. Create Terraform State Backend

```bash
# Create S3 bucket for state
aws s3api create-bucket \
  --bucket intelli-terraform-state \
  --region af-south-1 \
  --create-bucket-configuration LocationConstraint=af-south-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket intelli-terraform-state \
  --versioning-configuration Status=Enabled

# Create DynamoDB table for locking
aws dynamodb create-table \
  --table-name terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region af-south-1
```

After creating the backend, uncomment the `backend "s3"` block in both `cicd-cluster/backend.tf` and `sso-cluster/backend.tf`.

### 4. Create ECR Repositories

```bash
aws ecr create-repository --repository-name intelli-sso-auth --region af-south-1
aws ecr create-repository --repository-name intelli-sso-admin-portal --region af-south-1
```

## Deployment

### Step 1: Deploy CI/CD Cluster

```bash
cd terraform/cicd-cluster
terraform init
terraform plan
terraform apply
```

Configure kubectl:
```bash
aws eks update-kubeconfig --region af-south-1 --name intelli-cicd
```

Deploy TeamCity stack:
```bash
cd ../../kubernetes/cicd
kubectl apply -f namespace.yaml
kubectl apply -f postgres/
kubectl apply -f teamcity/
```

Wait for TeamCity to start (~3-5 minutes):
```bash
kubectl get pods -n cicd -w
```

Get TeamCity URL:
```bash
kubectl get svc teamcity-server -n cicd -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

Access TeamCity at `http://<hostname>:8111` and complete the setup wizard.

### Step 2: Deploy SSO Cluster

```bash
cd terraform/sso-cluster
terraform init
terraform plan
terraform apply
```

Configure kubectl:
```bash
aws eks update-kubeconfig --region af-south-1 --name intelli-sso
```

### Step 3: Build & Push Docker Images (first time)

```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=af-south-1

# Login to ECR
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build and push API
cd intelli-sso-auth
docker build -t $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-auth:latest .
docker push $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-auth:latest
cd ..

# Build and push Frontend
cd intelli-sso-admin-portal
docker build -t $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-admin-portal:latest .
docker push $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-admin-portal:latest
cd ..
```

### Step 4: Deploy SSO Application

**Important:** Before deploying, update these files with your actual values:
- `kubernetes/sso/postgres/secret.yaml` — database password
- `kubernetes/sso/api/secret.yaml` — all secrets (JWT, OAuth2 providers, Twilio, DB password)
- `kubernetes/sso/api/deployment.yaml` — replace `<AWS_ACCOUNT_ID>` with your account ID
- `kubernetes/sso/frontend/deployment.yaml` — replace `<AWS_ACCOUNT_ID>` with your account ID

```bash
cd kubernetes/sso
kubectl apply -f namespace.yaml
kubectl apply -f frontend/nginx-configmap.yaml
kubectl apply -f postgres/
kubectl apply -f api/
kubectl apply -f frontend/
```

Wait for pods to be ready:
```bash
kubectl get pods -n sso -w
```

Get the frontend URL:
```bash
kubectl get svc sso-frontend -n sso -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

### Step 5: Configure TeamCity Pipelines

See [teamcity/build-configs.md](teamcity/build-configs.md) for detailed pipeline setup instructions.

## Verification

```bash
# CI/CD cluster
kubectl get pods -n cicd
# Expected: teamcity-server, teamcity-agent, teamcity-postgres

# SSO cluster
kubectl get pods -n sso
# Expected: sso-api (x2), sso-frontend (x2), sso-postgres

# Check services
kubectl get svc -n cicd
kubectl get svc -n sso
```

## Cost Estimate (af-south-1)

| Resource | Monthly Cost (approx) |
|----------|----------------------|
| 2x EKS clusters | ~$146 ($73 each) |
| 4x t3.medium nodes (2 per cluster) | ~$180 |
| NAT Gateways (2) | ~$90 |
| EBS volumes | ~$10 |
| Load Balancers (3) | ~$60 |
| **Total** | **~$486/month** |

## Teardown

```bash
# Delete K8s resources first
kubectl delete -f kubernetes/sso/ --recursive
kubectl delete -f kubernetes/cicd/ --recursive

# Destroy SSO cluster
cd terraform/sso-cluster
terraform destroy

# Destroy CI/CD cluster
cd ../cicd-cluster
terraform destroy
```
