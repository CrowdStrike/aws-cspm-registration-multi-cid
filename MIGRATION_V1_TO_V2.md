# Migration Guide: v1.0 to v2.0.0

This guide helps customers migrate from v1.0  to v2.0.0+.

## Breaking Changes in v2.0.0

v2.0.0 introduces several breaking changes that prevent a simple CloudFormation stack update:

1. **Removed Parameter**: `CSPMTemplateURL` parameter removed from CloudFormation template
2. **Lambda Consolidation**: Two Lambda functions merged into one
   - Old: `crowdstrike-cloud-initial-registration` + `crowdstrike-cloud-new-registration`
   - New: `crowdstrike-multi-cid-registration`
3. **Function Renames**: Update function renamed to `crowdstrike-multi-cid-update-stacksets`
4. **StackSet Tagging**: v2.0.0 requires stacksets to have a `template_url` tag

## Migration Path

### In-Place Migration (This Will Preserve Existing StackSets)

If you want to preserve your existing stacksets and registrations, follow these steps:

#### Step 1: Tag Existing StackSets

The v2.0.0 update function requires all base CSPM stacksets to have a `template_url` tag to apply the latest changes to the CSPM Reader Role. Use the provided script tag_existing_stacksets.py to add this tag to your existing stacksets.

**Note**: The script only tags base CSPM stacksets. EB and IOA stacksets are excluded.

```bash
# Install dependencies
pip3 install boto3

# Dry run to see what will be tagged
python3 tag_existing_stacksets.py --dry-run

# For GovCloud deployments
python3 tag_existing_stacksets.py --region us-gov-west-1 --dry-run

# For delegated admin deployments
python3 tag_existing_stacksets.py --call-as DELEGATED_ADMIN --dry-run

# Tag stacksets (will prompt for confirmation)
python3 tag_existing_stacksets.py

# Use custom template URL (for air-gapped/private deployments)
python3 tag_existing_stacksets.py \
  --template-url https://my-bucket.s3.us-east-1.amazonaws.com/crowdstrike_aws_cspm.json
```

**Script Options:**
- `--region`: AWS region (default: us-east-1)
- `--template-url`: Custom template URL for all stacksets
- `--call-as`: Use DELEGATED_ADMIN for delegated admin deployments
- `--dry-run`: Preview changes without applying them
- `--log-level`: Set logging verbosity (DEBUG, INFO, WARNING, ERROR)

#### Step 2: Delete Old Stack

After tagging stacksets, delete the old v1.0 CloudFormation stack:

```bash
# Delete the stack but preserve stacksets
aws cloudformation delete-stack --stack-name <old-stack-name>
```

**IMPORTANT**: Do NOT use the cleanup script in this scenario. The cleanup script deletes stacksets, which you want to preserve.

#### Step 3: Deploy v2.0.0 Stack

Deploy the new v2.0.0 stack:

```bash
aws cloudformation create-stack \
  --stack-name crowdstrike-cspm-multi-cid \
  --template-body file://init_crowdstrike_multiple_cid.yml \
  --parameters file://params.json \
  --capabilities CAPABILITY_NAMED_IAM
```

#### Step 4: Verify Compatibility

After deploying v2.0.0, verify that the update function can find your tagged stacksets:

```bash
# Invoke the update function
aws lambda invoke \
  --function-name crowdstrike-multi-cid-update-stacksets \
  --payload '{}' \
  response.json

# Check the response
cat response.json
```

The response should show all your existing stacksets were found and processed.

## Template URL Reference

The tagging script automatically determines the correct template URL for base CSPM stacksets based on your AWS partition:

- **Commercial AWS**: `https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json`
- **AWS GovCloud**: `https://cs-csgov-laggar-cloudconnect-templates.s3-us-gov-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json`
- **Air-Gapped/Private**: Specify your custom S3 URL using `--template-url`

**Note**: The tagging script and update function only handle base CSPM stacksets. EB and IOA stacksets are excluded and managed separately.

## Post-Migration

After migration, you can use the new v2.0.0 features:

1. **Unified Registration**: Single Lambda function handles both initial and new account registration
2. **Automatic StackSet Updates**: Update function automatically finds and updates all tagged stacksets
3. **Improved Cleanup**: Enhanced cleanup script with better safety checks and dry-run mode

## Rollback

If you need to rollback to v1.0:

1. The tagging script is **non-destructive** - it only adds tags to stacksets
2. You can safely delete the v2.0.0 stack and redeploy v1.0
3. The `template_url` tags on stacksets will be ignored by v1.0 and won't cause any issues

## Troubleshooting

### Stacksets Not Found by Update Function

If the update function doesn't find your stacksets:

1. Verify stacksets have the `template_url` tag:
   ```bash
   aws cloudformation describe-stack-set --stack-set-name <stackset-name> \
     --query 'StackSet.Tags[?Key==`template_url`]'
   ```

2. Ensure stackset names match the base CSPM pattern: `CrowdStrike-Cloud-Security-Stackset-{account}`
3. Note: EB and IOA stacksets are intentionally excluded from the update function

### Tagging Script Fails

If the tagging script fails with permission errors, ensure your IAM role has:
- `cloudformation:ListStackSets`
- `cloudformation:DescribeStackSet`
- `cloudformation:UpdateStackSet`
- `cloudformation:TagResource`

### Questions?

For issues or questions about the migration, please open an issue at:
https://github.com/CrowdStrike/aws-cspm-registration-multi-cid/issues
