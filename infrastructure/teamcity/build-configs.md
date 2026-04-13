# TeamCity CI/CD Pipeline Configuration

## Prerequisites

After TeamCity server is running, complete the initial setup wizard via the LoadBalancer IP on port 8111. Then configure the following:

## 1. Create a Project

- **Name:** intelli-sso
- **VCS Root:** Your Git repository URL (HTTPS or SSH)
- **Branch:** main

## 2. Build Configuration: SSO Auth API

**Name:** Build & Deploy API

### Build Steps

**Step 1: Maven Build**
- Runner: Maven
- Goals: `clean package -DskipTests`
- JDK: Java 21
- Working directory: `intelli-sso-auth`

**Step 2: Docker Build & Push to ECR**
- Runner: Command Line
- Script:
```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=af-south-1
REPO=$AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-auth
TAG=%build.number%

aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

cd intelli-sso-auth
docker build -t $REPO:$TAG -t $REPO:latest .
docker push $REPO:$TAG
docker push $REPO:latest
```

**Step 3: Deploy to Kubernetes**
- Runner: Command Line
- Script:
```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=af-south-1
REPO=$AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-auth
TAG=%build.number%

aws eks update-kubeconfig --region $REGION --name intelli-sso
kubectl set image deployment/sso-api sso-api=$REPO:$TAG -n sso
kubectl rollout status deployment/sso-api -n sso --timeout=300s
```

### Triggers
- VCS Trigger: on changes to `intelli-sso-auth/**`

---

## 3. Build Configuration: Admin Portal (Frontend)

**Name:** Build & Deploy Frontend

### Build Steps

**Step 1: npm Build**
- Runner: Command Line
- Script:
```bash
cd intelli-sso-admin-portal
npm ci
npm run build
```

**Step 2: Docker Build & Push to ECR**
- Runner: Command Line
- Script:
```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=af-south-1
REPO=$AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-admin-portal
TAG=%build.number%

aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

cd intelli-sso-admin-portal
docker build -t $REPO:$TAG -t $REPO:latest .
docker push $REPO:$TAG
docker push $REPO:latest
```

**Step 3: Deploy to Kubernetes**
- Runner: Command Line
- Script:
```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=af-south-1
REPO=$AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/intelli-sso-admin-portal
TAG=%build.number%

aws eks update-kubeconfig --region $REGION --name intelli-sso
kubectl set image deployment/sso-frontend sso-frontend=$REPO:$TAG -n sso
kubectl rollout status deployment/sso-frontend -n sso --timeout=300s
```

### Triggers
- VCS Trigger: on changes to `intelli-sso-admin-portal/**`

---

## 4. Agent Configuration

TeamCity agents auto-scale via the HorizontalPodAutoscaler. The agent Docker image includes:
- Docker (Docker-in-Docker mode)
- Basic build tools

For Java and Node.js builds, the agents need additional tools. You can either:

**Option A: Custom Agent Image (Recommended)**
Build a custom agent image with Java 21, Node.js 20, Maven, AWS CLI, and kubectl pre-installed. Update the `agent-deployment.yaml` image reference.

**Option B: Use Docker Build Steps**
Run builds inside Docker containers within the agent. TeamCity agents with Docker support can use Docker wrappers for build steps.

## 5. AWS Credentials for Agents

Create an IAM user or role with permissions for:
- ECR: Push/pull images
- EKS: Describe cluster, update kubeconfig
- STS: Get caller identity

Configure credentials as TeamCity parameters:
- `env.AWS_ACCESS_KEY_ID`
- `env.AWS_SECRET_ACCESS_KEY`
- `env.AWS_DEFAULT_REGION` = `af-south-1`

Or use IAM Roles for Service Accounts (IRSA) for a more secure approach.
