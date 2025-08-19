"""Force Update for Multiple CID CSPM StackSets"""

import logging
import os
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ADMIN_ROLE_ARN = os.environ["admin_role_arn"]
EXEC_ROLE_NAME = os.environ["exec_role_arn"]


def get_stacksets_created_by_init() -> List[Tuple[str, str]]:
    """
    Find all stacksets created by the init function.
    Returns list of tuples: (stackset_name, template_url)
    """
    try:
        stacksets_with_template_urls = []
        client = boto3.client("cloudformation")

        # List all active stacksets
        response = client.list_stack_sets(Status="ACTIVE")
        summaries = response["Summaries"]
        next_token = response.get("NextToken", None)

        while next_token:
            response = client.list_stack_sets(Status="ACTIVE", NextToken=next_token)
            summaries += response["Summaries"]
            next_token = response.get("NextToken", None)

        # Check each stackset for template_url tag
        for summary in summaries:
            stackset_name = summary["StackSetName"]

            # Only check CrowdStrike stacksets for efficiency
            if "CrowdStrike" in stackset_name or "CSPM" in stackset_name:
                try:
                    template_url = get_template_url_from_stackset(client, stackset_name)
                    if template_url:
                        stacksets_with_template_urls.append(
                            (stackset_name, template_url)
                        )
                        logger.info(f"Found stackset created by init: {stackset_name}")
                except Exception as e:
                    logger.warning(
                        f"Could not get template URL for {stackset_name}: {e}"
                    )
                    continue

        return stacksets_with_template_urls
    except (ClientError, BotoCoreError) as error:
        logger.error(f"Error listing stacksets: {error}")
        raise error


def get_template_url_from_stackset(client, stackset_name: str) -> Optional[str]:
    """
    Retrieve the template_url from a stackset's tags.
    Returns None if no template_url tag is found.
    """
    try:
        response = client.describe_stack_set(StackSetName=stackset_name)
        tags = response.get("StackSet", {}).get("Tags", [])

        for tag in tags:
            if tag.get("Key") == "template_url":
                return tag.get("Value")

        return None
    except (ClientError, BotoCoreError) as error:
        logger.error(
            f"Error getting template URL for stackset {stackset_name}: {error}"
        )
        return None


def get_stackset_tags(client, stackset_name: str) -> List[Dict[str, str]]:
    """
    Get all tags from a stackset.
    """
    try:
        response = client.describe_stack_set(StackSetName=stackset_name)
        return response.get("StackSet", {}).get("Tags", [])
    except (ClientError, BotoCoreError) as error:
        logger.error(f"Error getting tags for stackset {stackset_name}: {error}")
        return []


def update_stackset(stackset_name: str, template_url: str) -> bool:
    """
    Update a single stackset with the provided template URL.
    Returns True if successful, False otherwise.
    """
    try:
        client = boto3.client("cloudformation")

        # Get tags from the stackset itself
        stackset_tags = get_stackset_tags(client, stackset_name)

        logger.info(
            f"Updating stackset {stackset_name} with template URL: {template_url}"
        )

        response = client.update_stack_set(
            StackSetName=stackset_name,
            TemplateURL=template_url,
            Capabilities=[
                "CAPABILITY_NAMED_IAM",
            ],
            AdministrationRoleARN=ADMIN_ROLE_ARN,
            ExecutionRoleName=EXEC_ROLE_NAME,
            Parameters=[
                {"ParameterKey": "APICredentialsStorageMode", "UsePreviousValue": True},
                {"ParameterKey": "ClientID", "UsePreviousValue": True},
                {"ParameterKey": "ClientSecret", "UsePreviousValue": True},
                {"ParameterKey": "CSAccountNumber", "UsePreviousValue": True},
                {"ParameterKey": "CSBucketName", "UsePreviousValue": True},
                {"ParameterKey": "CSEventBusName", "UsePreviousValue": True},
                {"ParameterKey": "CSRoleName", "UsePreviousValue": True},
                {"ParameterKey": "DSPMRegions", "UsePreviousValue": True},
                {"ParameterKey": "DSPMRoleName", "UsePreviousValue": True},
                {"ParameterKey": "EnableDSPM", "UsePreviousValue": True},
                {"ParameterKey": "EnableIdentityProtection", "UsePreviousValue": True},
                {"ParameterKey": "EnableIOA", "UsePreviousValue": True},
                {"ParameterKey": "EnableIOM", "UsePreviousValue": True},
                {"ParameterKey": "EnableSensorManagement", "UsePreviousValue": True},
                {"ParameterKey": "ExternalID", "UsePreviousValue": True},
                {"ParameterKey": "PermissionsBoundary", "UsePreviousValue": True},
                {"ParameterKey": "RoleName", "UsePreviousValue": True},
                {"ParameterKey": "UseExistingCloudtrail", "UsePreviousValue": True},
            ],
            Tags=stackset_tags,
        )

        operation_id = response.get("OperationId")
        logger.info(
            f"Successfully initiated update for stackset {stackset_name}. Operation ID: {operation_id}"
        )
        return True

    except (ClientError, BotoCoreError) as error:
        logger.error(f"Error updating stackset {stackset_name}: {error}")
        return False


def lambda_handler(event, context):
    """Main Function"""
    logger.info("Got event %s", event)
    logger.info("Context %s", context)

    try:
        # Get all stacksets created by the init function with their template URLs
        stacksets_with_urls = get_stacksets_created_by_init()

        if not stacksets_with_urls:
            logger.warning("No stacksets created by init function found to update")
            return {"statusCode": 200, "body": "No stacksets found to update"}

        logger.info(f"Found {len(stacksets_with_urls)} stacksets to update")

        # Track results
        successful_updates = []
        failed_updates = []

        # Update each stackset
        for stackset_name, template_url in stacksets_with_urls:
            logger.info(f"Processing stackset: {stackset_name}")

            if update_stackset(stackset_name, template_url):
                successful_updates.append(stackset_name)
            else:
                failed_updates.append(stackset_name)

        # Log results
        logger.info(f"Successfully updated {len(successful_updates)} stacksets")
        if successful_updates:
            logger.info(f"Successful updates: {successful_updates}")

        if failed_updates:
            logger.error(
                f"Failed to update {len(failed_updates)} stacksets: {failed_updates}"
            )

        return {
            "statusCode": 200,
            "body": {
                "message": f"Processed {len(stacksets_with_urls)} stacksets",
                "successful_updates": successful_updates,
                "failed_updates": failed_updates,
            },
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {e}")
        return {
            "statusCode": 500,
            "body": f"Error processing stackset updates: {str(e)}",
        }
