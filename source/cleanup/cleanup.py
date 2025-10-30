"""
Cleanup CrowdStrike Multi-CID Deployment

This script safely removes all CrowdStrike stacksets and stack instances
created by the init function. It identifies stacksets by looking for the
'template_url' tag that the init function adds to all created stacksets.
"""

import argparse
import json
import logging
import sys
import time
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper()))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


class CrowdStrikeCleanup:
    """Main cleanup class for CrowdStrike stacksets"""

    def __init__(
        self, region: Optional[str] = None, call_as: str = "SELF", dry_run: bool = False
    ):
        self.logger = setup_logging()
        self.region = region or boto3.Session().region_name
        self.call_as = call_as
        self.dry_run = dry_run
        self.client = boto3.client("cloudformation", region_name=self.region)

        self.logger.info(f"Initialized cleanup for region: {self.region}")
        self.logger.info(f"Call context: {self.call_as}")
        self.logger.info(f"Dry run mode: {self.dry_run}")

    def get_stacksets_created_by_init(self) -> List[Tuple[str, Dict]]:
        """
        Find all stacksets created by the init function.
        Returns list of tuples: (stackset_name, stackset_details)
        """
        try:
            stacksets_info = []
            next_token = None

            self.logger.info("Searching for stacksets created by init function...")

            while True:
                try:
                    kwargs = {"Status": "ACTIVE", "CallAs": self.call_as}
                    if next_token:
                        kwargs["NextToken"] = next_token

                    response = self.client.list_stack_sets(**kwargs)
                    summaries = response.get("Summaries", [])

                    # Check each stackset for template_url tag
                    for summary in summaries:
                        stackset_name = summary["StackSetName"]

                        # Only check CrowdStrike-related stacksets for efficiency
                        if any(
                            keyword in stackset_name.lower()
                            for keyword in ["crowdstrike", "cspm", "falcon"]
                        ):
                            try:
                                template_url = self._get_template_url_from_stackset(
                                    stackset_name
                                )
                                if template_url:
                                    stackset_details = self._get_stackset_details(
                                        stackset_name
                                    )
                                    stacksets_info.append(
                                        (stackset_name, stackset_details)
                                    )
                                    self.logger.info(
                                        f"Found stackset created by init: {stackset_name}"
                                    )
                            except Exception as e:
                                self.logger.warning(
                                    f"Could not check stackset {stackset_name}: {e}"
                                )
                                continue

                    next_token = response.get("NextToken")
                    if not next_token:
                        break

                except ClientError as e:
                    if e.response["Error"]["Code"] == "InvalidNextToken":
                        break
                    raise

            self.logger.info(
                f"Found {len(stacksets_info)} stacksets created by init function"
            )
            return stacksets_info

        except (ClientError, BotoCoreError) as error:
            self.logger.error(f"Error listing stacksets: {error}")
            raise

    def _get_template_url_from_stackset(self, stackset_name: str) -> Optional[str]:
        """Get template_url from stackset tags"""
        try:
            response = self.client.describe_stack_set(
                StackSetName=stackset_name, CallAs=self.call_as
            )
            tags = response.get("StackSet", {}).get("Tags", [])

            for tag in tags:
                if tag.get("Key") == "template_url":
                    return tag.get("Value")

            return None

        except (ClientError, BotoCoreError):
            return None

    def _get_stackset_details(self, stackset_name: str) -> Dict:
        """Get detailed information about a stackset"""
        try:
            # Get stackset info
            stackset_response = self.client.describe_stack_set(
                StackSetName=stackset_name, CallAs=self.call_as
            )
            stackset_info = stackset_response.get("StackSet", {})

            # Get stack instances
            instances = []
            next_token = None

            while True:
                kwargs = {"StackSetName": stackset_name, "CallAs": self.call_as}
                if next_token:
                    kwargs["NextToken"] = next_token

                instances_response = self.client.list_stack_instances(**kwargs)
                instances.extend(instances_response.get("Summaries", []))

                next_token = instances_response.get("NextToken")
                if not next_token:
                    break

            return {
                "stackset_info": stackset_info,
                "instances": instances,
                "instance_count": len(instances),
                "accounts": list(set(inst["Account"] for inst in instances)),
                "regions": list(set(inst["Region"] for inst in instances)),
            }

        except (ClientError, BotoCoreError) as error:
            self.logger.error(
                f"Error getting details for stackset {stackset_name}: {error}"
            )
            return {}

    def display_cleanup_plan(self, stacksets_info: List[Tuple[str, Dict]]) -> None:
        """Display what will be cleaned up"""
        if not stacksets_info:
            self.logger.warning("No stacksets found to clean up")
            return

        print("\n" + "=" * 80)
        print("CROWDSTRIKE CLEANUP PLAN")
        print("=" * 80)
        print(f"Region: {self.region}")
        print(f"Call context: {self.call_as}")
        print(f"Dry run mode: {self.dry_run}")
        print()

        total_instances = 0
        all_accounts = set()
        all_regions = set()

        for stackset_name, details in stacksets_info:
            instances = details.get("instances", [])
            accounts = details.get("accounts", [])
            regions = details.get("regions", [])

            total_instances += len(instances)
            all_accounts.update(accounts)
            all_regions.update(regions)

            print(f"StackSet: {stackset_name}")
            print(f"  Stack Instances: {len(instances)}")
            print(f"  Accounts: {', '.join(sorted(accounts))}")
            print(f"  Regions: {', '.join(sorted(regions))}")

            # Show template URL if available
            template_url = self._get_template_url_from_stackset(stackset_name)
            if template_url:
                print(f"  Template URL: {template_url}")
            print()

        print("-" * 80)
        print(f"TOTAL SUMMARY:")
        print(f"  StackSets to delete: {len(stacksets_info)}")
        print(f"  Stack instances to delete: {total_instances}")
        print(
            f"  Affected accounts: {len(all_accounts)} ({', '.join(sorted(all_accounts))})"
        )
        print(
            f"  Affected regions: {len(all_regions)} ({', '.join(sorted(all_regions))})"
        )
        print("=" * 80)

    def confirm_cleanup(self) -> bool:
        """Get user confirmation for cleanup"""
        if self.dry_run:
            print("\nDRY RUN MODE - No actual deletion will occur")
            return True

        print(
            "\nWARNING: This will permanently delete all listed stacksets and stack instances!"
        )
        print("This action cannot be undone.")

        confirmation = input(
            "\nType 'DELETE' (in caps) to proceed with cleanup: "
        ).strip()

        if confirmation == "DELETE":
            double_check = input(
                "Are you absolutely sure? Type 'YES' to confirm: "
            ).strip()
            return double_check == "YES"

        return False

    def delete_stack_instances(self, stackset_name: str, instances: List[Dict]) -> bool:
        """Delete all stack instances for a stackset"""
        if not instances:
            self.logger.info(f"No stack instances to delete for {stackset_name}")
            return True

        try:
            # Group instances by account and region for efficient deletion
            account_regions = {}
            for instance in instances:
                account = instance["Account"]
                region = instance["Region"]
                if account not in account_regions:
                    account_regions[account] = []
                account_regions[account].append(region)

            operation_ids = []

            for account, regions in account_regions.items():
                self.logger.info(
                    f"Deleting stack instances for account {account} in regions: {regions}"
                )

                if self.dry_run:
                    self.logger.info(
                        f"DRY RUN: Would delete stack instances for {stackset_name} in account {account}, regions {regions}"
                    )
                    continue

                response = self.client.delete_stack_instances(
                    StackSetName=stackset_name,
                    Accounts=[account],
                    Regions=regions,
                    RetainStacks=False,
                    CallAs=self.call_as,
                )

                operation_id = response.get("OperationId")
                operation_ids.append(operation_id)
                self.logger.info(
                    f"Started deletion operation {operation_id} for account {account}"
                )

            if self.dry_run:
                return True

            # Wait for all operations to complete
            return self._wait_for_operations(
                stackset_name, operation_ids, "delete instances"
            )

        except (ClientError, BotoCoreError) as error:
            self.logger.error(
                f"Error deleting stack instances for {stackset_name}: {error}"
            )
            return False

    def delete_stackset(self, stackset_name: str) -> bool:
        """Delete a stackset"""
        try:
            self.logger.info(f"Deleting stackset: {stackset_name}")

            if self.dry_run:
                self.logger.info(f"DRY RUN: Would delete stackset {stackset_name}")
                return True

            response = self.client.delete_stack_set(
                StackSetName=stackset_name, CallAs=self.call_as
            )

            self.logger.info(f"Successfully deleted stackset {stackset_name}")
            return True

        except (ClientError, BotoCoreError) as error:
            self.logger.error(f"Error deleting stackset {stackset_name}: {error}")
            return False

    def _wait_for_operations(
        self, stackset_name: str, operation_ids: List[str], operation_type: str
    ) -> bool:
        """Wait for stackset operations to complete"""
        if not operation_ids:
            return True

        self.logger.info(
            f"Waiting for {len(operation_ids)} {operation_type} operations to complete..."
        )

        max_wait_time = 1800  # 30 minutes
        check_interval = 30  # 30 seconds
        elapsed_time = 0

        while elapsed_time < max_wait_time:
            all_complete = True

            for operation_id in operation_ids:
                try:
                    response = self.client.describe_stack_set_operation(
                        StackSetName=stackset_name,
                        OperationId=operation_id,
                        CallAs=self.call_as,
                    )

                    status = response.get("StackSetOperation", {}).get("Status")

                    if status in ["RUNNING", "STOPPING"]:
                        all_complete = False
                    elif status == "FAILED":
                        self.logger.error(f"Operation {operation_id} failed")
                        return False
                    elif status == "SUCCEEDED":
                        self.logger.info(
                            f"Operation {operation_id} completed successfully"
                        )

                except (ClientError, BotoCoreError) as error:
                    self.logger.error(
                        f"Error checking operation {operation_id}: {error}"
                    )
                    return False

            if all_complete:
                self.logger.info(
                    f"All {operation_type} operations completed successfully"
                )
                return True

            self.logger.info(
                f"Operations still running... waiting {check_interval}s (elapsed: {elapsed_time}s)"
            )
            time.sleep(check_interval)
            elapsed_time += check_interval

        self.logger.error(
            f"Timeout waiting for {operation_type} operations to complete"
        )
        return False

    def cleanup(self) -> bool:
        """Main cleanup method"""
        try:
            # Find stacksets created by init function
            stacksets_info = self.get_stacksets_created_by_init()

            if not stacksets_info:
                self.logger.info("No CrowdStrike stacksets found to clean up")
                return True

            # Display cleanup plan
            self.display_cleanup_plan(stacksets_info)

            # Get confirmation
            if not self.confirm_cleanup():
                self.logger.info("Cleanup cancelled by user")
                return False

            self.logger.info("Starting cleanup process...")

            # Track results
            successful_cleanups = []
            failed_cleanups = []

            # Process each stackset
            for stackset_name, details in stacksets_info:
                self.logger.info(f"Processing stackset: {stackset_name}")

                # Delete stack instances first
                instances = details.get("instances", [])
                if self.delete_stack_instances(stackset_name, instances):
                    # Then delete the stackset
                    if self.delete_stackset(stackset_name):
                        successful_cleanups.append(stackset_name)
                        self.logger.info(f"Successfully cleaned up {stackset_name}")
                    else:
                        failed_cleanups.append(stackset_name)
                else:
                    failed_cleanups.append(stackset_name)

            # Summary
            self.logger.info(
                f"Cleanup completed. Success: {len(successful_cleanups)}, Failed: {len(failed_cleanups)}"
            )

            if successful_cleanups:
                self.logger.info(f"Successfully cleaned up: {successful_cleanups}")

            if failed_cleanups:
                self.logger.error(f"Failed to clean up: {failed_cleanups}")
                return False

            self.logger.info("All stacksets cleaned up successfully!")
            return True

        except Exception as error:
            self.logger.error(f"Unexpected error during cleanup: {error}")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Cleanup CrowdStrike Multi-CID Deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cleanup.py                              # Interactive cleanup in current region
  python cleanup.py --dry-run                    # Show what would be deleted without doing it
  python cleanup.py --region us-west-2          # Cleanup in specific region
  python cleanup.py --call-as DELEGATED_ADMIN   # Use delegated admin context
  python cleanup.py --log-level DEBUG           # Enable debug logging
        """,
    )

    parser.add_argument(
        "--region", help="AWS region (defaults to current session region)", default=None
    )

    parser.add_argument(
        "--call-as",
        choices=["SELF", "DELEGATED_ADMIN"],
        default="SELF",
        help="CloudFormation call context (default: SELF)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()

    # Setup logging with specified level
    setup_logging(args.log_level)

    try:
        # Create cleanup instance
        cleanup = CrowdStrikeCleanup(
            region=args.region, call_as=args.call_as, dry_run=args.dry_run
        )

        # Run cleanup
        success = cleanup.cleanup()

        if success:
            print("\n✅ Cleanup completed successfully!")
            sys.exit(0)
        else:
            print("\n❌ Cleanup failed or was cancelled")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nCleanup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
