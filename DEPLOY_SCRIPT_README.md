# Deployment Script Details

The `deploy.sh` script provides automated packaging and deployment capabilities with the following features:

**Key Features:**
- **Automatic Dependency Management**: Installs Python dependencies from `requirements.txt` files for each Lambda function
- **S3 Integration**: Uploads packaged functions and CloudFormation templates to S3
- **CloudFormation Deployment**: Complete stack deployment automation

**Script Usage:**
```bash
# Display help and usage information
./deploy.sh --help

# Package Functions Locally
./deploy.sh

# Package and Upload to S3
./deploy.sh your-s3-bucket-name

# Package functions and Deploy CloudFormation
./deploy.sh your-s3-bucket-name --deploy your-stack-name --params-file my-params.json

# Only Deploy CloudFormation (assumes Lambda packages are already in S3)
./deploy.sh --deploy-only your-stack-name --params-file my-params.json
```
