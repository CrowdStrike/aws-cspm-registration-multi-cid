#!/usr/bin/env python3
"""
Tag Existing CrowdStrike StackSets for v2.0.0 Compatibility

This script tags existing CrowdStrike CSPM stacksets with the template_url tag
required by the v2.0.0 update function.
"""

import argparse
import logging
import sys
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Template URL by partition (base CSPM only)
TEMPLATE_URLS = {
    'aws': 'https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json',
    'aws-us-gov': 'https://cs-csgov-laggar-cloudconnect-templates.s3-us-gov-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json',
}


def get_aws_partition(region: str) -> str:
    """Determine AWS partition from region."""
    if region.startswith('us-gov-'):
        return 'aws-us-gov'
    return 'aws'


def list_crowdstrike_stacksets(client, call_as: str = 'SELF') -> List[Dict]:
    """
    List all base CSPM stacksets created by the init function.
    Returns list of stackset summaries.

    Only includes base CSPM stacksets matching the pattern:
    - CrowdStrike-Cloud-Security-Stackset-{account}

    Excludes:
    - Infrastructure stacksets: crowdstrike-stackset-role-setup
    - EB stacksets: CrowdStrike-Cloud-Security-Stackset-{account}-EB
    - IOA stacksets: CrowdStrike-Cloud-Security-Stackset-{account}-IOA
    """
    try:
        stacksets = []
        kwargs = {'Status': 'ACTIVE'}
        if call_as == 'DELEGATED_ADMIN':
            kwargs['CallAs'] = 'DELEGATED_ADMIN'

        response = client.list_stack_sets(**kwargs)
        summaries = response.get('Summaries', [])
        next_token = response.get('NextToken')

        while next_token:
            kwargs['NextToken'] = next_token
            response = client.list_stack_sets(**kwargs)
            summaries.extend(response.get('Summaries', []))
            next_token = response.get('NextToken')

        # Filter for base CSPM stacksets created by init function
        # Pattern: CrowdStrike-Cloud-Security-Stackset-{account}
        # Exclude EB and IOA suffixes
        for summary in summaries:
            stackset_name = summary.get('StackSetName', '')
            if (
                stackset_name.startswith('CrowdStrike-Cloud-Security-Stackset-')
                and '-EB' not in stackset_name.upper()
                and '-IOA' not in stackset_name.upper()
            ):
                stacksets.append(summary)

        return stacksets

    except (ClientError, BotoCoreError) as error:
        logger.error(f"Error listing stacksets: {error}")
        raise


def get_stackset_tags(client, stackset_name: str, call_as: str = 'SELF') -> List[Dict[str, str]]:
    """Get current tags from a stackset."""
    try:
        kwargs = {'StackSetName': stackset_name}
        if call_as == 'DELEGATED_ADMIN':
            kwargs['CallAs'] = 'DELEGATED_ADMIN'

        response = client.describe_stack_set(**kwargs)
        return response.get('StackSet', {}).get('Tags', [])

    except (ClientError, BotoCoreError) as error:
        logger.error(f"Error getting tags for {stackset_name}: {error}")
        return []


def has_template_url_tag(tags: List[Dict[str, str]]) -> Optional[str]:
    """Check if template_url tag exists and return its value."""
    for tag in tags:
        if tag.get('Key') == 'template_url':
            return tag.get('Value')
    return None


def get_stackset_arn(client, stackset_name: str, call_as: str = 'SELF') -> Optional[str]:
    """Get the ARN of a stackset."""
    try:
        kwargs = {'StackSetName': stackset_name}
        if call_as == 'DELEGATED_ADMIN':
            kwargs['CallAs'] = 'DELEGATED_ADMIN'

        response = client.describe_stack_set(**kwargs)
        return response.get('StackSet', {}).get('StackSetArn')

    except (ClientError, BotoCoreError) as error:
        logger.error(f"Error getting ARN for {stackset_name}: {error}")
        return None


def tag_stackset(
    client,
    stackset_name: str,
    template_url: str,
    call_as: str = 'SELF',
    dry_run: bool = False
) -> bool:
    """
    Add or update the template_url tag on a stackset using tag_resource API.
    This is lightweight and does not trigger stack instance operations.
    Returns True if successful or skipped (dry run), False otherwise.
    """
    try:
        # Get existing tags
        existing_tags = get_stackset_tags(client, stackset_name, call_as)

        # Check if template_url already exists
        current_template_url = has_template_url_tag(existing_tags)

        if current_template_url:
            if current_template_url == template_url:
                logger.info(f"  ✓ {stackset_name} already has correct template_url tag")
                return True
            else:
                logger.info(f"  → {stackset_name} has different template_url: {current_template_url}")
                logger.info(f"    Will update to: {template_url}")

        if dry_run:
            logger.info(f"  [DRY RUN] Would tag {stackset_name} with template_url={template_url}")
            return True

        # Get stackset ARN for tag_resource API
        stackset_arn = get_stackset_arn(client, stackset_name, call_as)
        if not stackset_arn:
            logger.error(f"  ✗ Could not get ARN for {stackset_name}")
            return False

        # Use tag_resource API - lightweight, doesn't trigger stack instance operations
        client.tag_resource(
            ResourceArn=stackset_arn,
            Tags=[
                {
                    'Key': 'template_url',
                    'Value': template_url
                }
            ]
        )
        logger.info(f"  ✓ Successfully tagged {stackset_name}")
        return True

    except (ClientError, BotoCoreError) as error:
        logger.error(f"  ✗ Error tagging {stackset_name}: {error}")
        return False


def determine_template_url(
    region: str,
    custom_template_url: Optional[str]
) -> str:
    """
    Determine the appropriate template URL for base CSPM stacksets.
    Priority: custom_template_url > partition-based default
    """
    if custom_template_url:
        return custom_template_url

    # Determine from partition
    partition = get_aws_partition(region)
    return TEMPLATE_URLS.get(partition, TEMPLATE_URLS['aws'])


def main():
    parser = argparse.ArgumentParser(
        description='Tag existing CrowdStrike stacksets with template_url for v2.0.0 compatibility'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--template-url',
        help='Custom template URL to use for all stacksets. If not specified, uses default based on partition.'
    )
    parser.add_argument(
        '--call-as',
        choices=['SELF', 'DELEGATED_ADMIN'],
        default='SELF',
        help='CallAs parameter for StackSet operations (default: SELF)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be tagged without actually tagging'
    )
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompts (for automation). Cannot be used with --dry-run.'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.yes and args.dry_run:
        logger.error("ERROR: --yes and --dry-run cannot be used together")
        return 1

    # Set log level
    logger.setLevel(getattr(logging, args.log_level))

    try:
        # Initialize CloudFormation client
        client = boto3.client('cloudformation', region_name=args.region)

        logger.info("=" * 80)
        logger.info("CrowdStrike Base CSPM StackSet Tagging Tool for v2.0.0 Migration")
        logger.info("=" * 80)
        logger.info(f"Region: {args.region}")
        logger.info(f"Call As: {args.call_as}")
        if args.template_url:
            logger.info(f"Custom Template URL: {args.template_url}")
        if args.dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
        if args.yes:
            logger.info("AUTO-APPROVE MODE - Skipping confirmation prompts")
        logger.info("")
        logger.info("Note: Only base CSPM stacksets will be tagged. EB and IOA stacksets are excluded.")
        logger.info("")

        # List CrowdStrike stacksets
        logger.info("Scanning for base CSPM stacksets...")
        stacksets = list_crowdstrike_stacksets(client, args.call_as)

        if not stacksets:
            logger.warning("No base CSPM stacksets found")
            return 0

        logger.info(f"Found {len(stacksets)} base CSPM stackset(s)")
        logger.info("")

        # Analyze each stackset
        stacksets_to_tag = []
        stacksets_already_tagged = []

        for summary in stacksets:
            stackset_name = summary['StackSetName']
            tags = get_stackset_tags(client, stackset_name, args.call_as)
            current_url = has_template_url_tag(tags)

            if current_url:
                stacksets_already_tagged.append((stackset_name, current_url))
            else:
                template_url = determine_template_url(args.region, args.template_url)
                stacksets_to_tag.append((stackset_name, template_url))

        # Display summary
        logger.info("=" * 80)
        logger.info("TAGGING PLAN")
        logger.info("=" * 80)

        if stacksets_already_tagged:
            logger.info(f"\nAlready tagged ({len(stacksets_already_tagged)}):")
            for name, url in stacksets_already_tagged:
                logger.info(f"  • {name}")
                logger.info(f"    template_url: {url}")

        if stacksets_to_tag:
            logger.info(f"\nWill be tagged ({len(stacksets_to_tag)}):")
            for name, url in stacksets_to_tag:
                logger.info(f"  • {name}")
                logger.info(f"    template_url: {url}")

        if not stacksets_to_tag:
            logger.info("\n✓ All base CSPM stacksets are already tagged!")
            return 0

        logger.info("")
        logger.info("=" * 80)

        # Confirm before proceeding (unless --yes flag is provided)
        if not args.dry_run and not args.yes:
            logger.info("")
            confirmation = input(f"Tag {len(stacksets_to_tag)} stackset(s)? Type 'YES' to confirm: ")
            if confirmation != 'YES':
                logger.info("Tagging cancelled")
                return 0

        # Tag stacksets
        logger.info("")
        logger.info("Tagging stacksets...")
        logger.info("")

        successful = 0
        failed = 0

        for stackset_name, template_url in stacksets_to_tag:
            if tag_stackset(client, stackset_name, template_url, args.call_as, args.dry_run):
                successful += 1
            else:
                failed += 1

        # Final summary
        logger.info("")
        logger.info("=" * 80)
        logger.info("SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Successfully tagged: {successful}")
        if failed > 0:
            logger.error(f"Failed to tag: {failed}")
            return 1

        if args.dry_run:
            logger.info("\nDRY RUN completed - no actual changes were made")
            logger.info("Remove --dry-run flag to apply these changes")
        else:
            logger.info("\n✓ All stacksets successfully tagged!")
            logger.info("\nYour stacksets are now compatible with v2.0.0 update function.")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
