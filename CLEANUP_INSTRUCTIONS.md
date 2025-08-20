# Cleanup

If for any reason you must roll back this deployment, it is very important to first delete the StackSet instances and StackSets created by this approach before deleting the root CloudFormation Stack. These are 'Self-Managed' StackSets which rely on the IAM Roles deployed by the root stack to function.

## Using the Cleanup Script

A stackset cleanup script is included at [`source/cleanup/cleanup.py`](source/cleanup/cleanup.py). This script automatically identifies and safely removes all CrowdStrike stacksets and stack instances created by the init function.

**Basic Usage:**
```bash
# Run interactively with confirmation prompts
python3 source/cleanup/cleanup.py

# Test what would be deleted without actually deleting (recommended first step)
python3 source/cleanup/cleanup.py --dry-run

# Specify a different region
python3 source/cleanup/cleanup.py --region us-west-2

# Use delegated admin context
python3 source/cleanup/cleanup.py --call-as DELEGATED_ADMIN

# Enable debug logging for troubleshooting
python3 source/cleanup/cleanup.py --log-level DEBUG
```

**Safety Process:**
1. The script will display a detailed cleanup plan showing exactly what will be deleted
2. You must type "DELETE" (in caps) to proceed
3. You must then type "YES" to double-confirm
4. The script monitors all operations and reports progress in real-time

**What Gets Cleaned Up:**
- All StackSets created by the init function (identified by `template_url` tags)
- All stack instances within these stacksets across all accounts and regions

**Important Notes:**
- Always run with `--dry-run` first to verify what will be deleted
- The script waits up to 30 minutes for each operation to complete
- After cleanup, you must manually "Deprovision" accounts from the Falcon Console under Cloud Accounts Registration to complete the deregistration process
- Only run this script if you're certain you want to completely remove the CrowdStrike Multi-CID integration

## Post Cleanup Steps

1. Delete the init_crowdstrike_multiple_cid.yml stack in CloudFormation.  
**Note**: the stack will be under the name you entered during initial setup (default: crowfstrike-multi-cid)
2. Deregister accounts in Falcon using the Cloud Accounts Registration page.  