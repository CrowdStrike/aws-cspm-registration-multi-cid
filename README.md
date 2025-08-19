![CrowdStrike](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png#gh-light-mode-only)
![CrowdStrike](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-red.png#gh-dark-mode-only)

## CrowdStrike AWS Registration with Multiple Falcon CIDs

This repository provides CloudFormation templates to onboard AWS Organizations with two CrowdStrike Falcon CIDs.  

## Table of Contents
- [Parameter File Details](./PARAMS_JSON_README.md)
- [Deploy Script Details](./DEPLOY_SCRIPT_README.md)
- [Update Instructions](./UPDATE_INSTRUCTIONS.md)
- [Cleanup Instructions](./CLEANUP_INSTRUCTIONS.md)
- [Quick Start](#quick-start)
- [Troubleshooting](#troubleshooting)

## Purpose
To easily onboard accounts within a single AWS Organization to multiple Falcon CIDs, this solution automates the Single Account Registration workflow.  This workaround solves the issue with the Organization Registration locking all child accounts to a single CID.

## Prerequisites

### Create Falcon API Client and Secret for each CID
1. In CrowdStrike Console, Navigate to API Clients and Keys page.
2. Click on "Add new API client".
3. Within the "Add new API client" modal, create a new client name and click on the Read and Write checkboxes next to **CSPM registration** and **Cloud security AWS registration** under API Scopes..
4. Add new API Client
5. Save the CLIENT ID and SECRET displayed for your records. The SECRET will not be visible after this step.

### Ensure the Organization is not currently registered
1. In CrowdStrike Console, Navigate to Cloud Accounts Registration page.
2. Verify the AWS Organization and child accounts are not listed.
3. If they are listed, deregister and remove CrowdStrike resources from those accounts before proceeding.

## Quick Start

### Option 1: Automated Deployment with Package Script (Recommended)

1. Download the contents of this repository.
2. Log in to the Management Account of your AWS Organization.
3. Use the automated packaging and deployment script:
4. Verify prerequisites:
  - Ensure you have Python 3.x and pip3 installed
  - AWS CLI configured with appropriate permissions
  - An S3 bucket for storing Lambda functions and CloudFormation templates
5. Setup Parameter File
  - Copy `params.json` to create your own parameter file eg. `my-params.json`
  - Fill in your actual CrowdStrike API credentials and AWS Organization details
6. Run the `deploy.sh` script to package, upload and deploy using your parameter file

```bash
./deploy.sh your-s3-bucket-name --deploy your-stack-name --params-file my-params.json
```

### Option 2: Manual Deployment (required for resource tags)

If you prefer manual deployment, follow these steps:

1. Run the `deploy.sh` script to create Lambda deployment packages from the source code:
```bash
# Only package functions locally
# This will not upload to S3 or deploy CloudFormation
./deploy.sh
```
2. Upload `init_lambda_function.zip` and `update_lambda_function.zip` to the root of an S3 Bucket
3. In the CloudFormation console select create stack.
4. Choose Specify Template and upload `init_crowdstrike_multiple_cid.yml`
5. Fill out the parameters, click next.
6. Optional: adding tags during the `Configure Stack Options` step will be applied to all resources created by this solution (excluding EventBridge Rules)
7. Optional: change Stack Failure Options to Preserve successfully provisioned resources. This option will allow you to maintain the stack and update parameters in the event of a mistake.
8. Enable the capabilities in the blue box and click submit.

## Post Deployment Steps

### Option 1: Initial Registration with CLI
1. Open CloudShell in your AWS Account and run the following:

```bash
aws lambda invoke \
    --function-name crowdstrike-multi-cid-registration  \
    --payload '{}' \
    response.json
```
### Option 2: Initial Registration in AWS Console
1. Navigate to Lambda and open the crowdstrike-cloud-registration function.
2. Create and save an empty test event. eg. {}
3. Click test.

This will execute the Lambda to retrieve your API Credentials from Secrets Manager and register each account to the CID mapped to its Parent OU.  Upon a successful registration, Lambda will trigger the StackSets required to onboard the Account.

### Validate Registration
1. Each account will have a correspondiong stackset named CrowdStrike-Cloud-Security-Stackset-{accountID}.  You can open these stacksets and review the status of stack instances to confirm the account has been onboarded.
2. Each account will appear in Falcon>Cloud Security>Cloud Accounts Registration.  Be sure to refresh the list to get the most up-to-date status of each account.

## How New Accounts are Registered
The solution supports automatic account registration in two scenarios:
1. **Account Creation**: When a new AWS Account is created within the Organization, and moved into an OU (MoveAccount event), EventBridge will trigger the crowdstrike-cloud-registration function.
2. **Account Movement**: When an existing AWS Account is moved to a different OU (MoveAccount event), the function will automatically detect this and re-register the account with the appropriate CID.

In both cases, the Lambda function will retrieve your API Credentials from Secrets Manager and register the account to the CID mapped to its Parent OU. Upon successful registration, Lambda will trigger the StackSets required to onboard the Account.

### Troubleshooting
If an account either does not appear in Falcon or shows as inactive more than an hour after registration, review the logs for each Lambda function in cloudwatch logs and review the StackSet for that account to ensure no errors occured during stack deployment.

## Questions or concerns?

If you encounter any issues or have questions about this repository, please open an [issue](https://github.com/CrowdStrike/cloud-aws-registration-cloudformation/issues/new/choose).

## Statement of Support

CrowdStrike AWS Registration is a community-driven, open source project designed to provide options for onboarding AWS with CrowdStrike Cloud Security. While not a formal CrowdStrike product, this repo is maintained by CrowdStrike and supported in partnership with the open source community.
