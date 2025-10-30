"""
Register AWS Accounts with Multiple CrowdStrike CIDs
"""

import json
import logging
import os
import sys
import base64
import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Import FalconPy
try:
    from falconpy import CSPMRegistration, CloudAWSRegistration
except ImportError:
    print("ERROR: falconpy not available")
    sys.exit(1)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
SUCCESS = "SUCCESS"
FAILED = "FAILED"
VERSION = "2.1.0"
NAME = "crowdstrike-cloud-reg-multi-cid"
USER_AGENT = f"{NAME}/{VERSION}"


# Configuration validation and parsing
@dataclass
class LambdaConfig:
    """Configuration class with validation"""

    existing_cloudtrail: bool
    sensor_management: bool
    credentials_storage: str
    aws_account_type: str
    aws_region: str
    secret_list: str
    stackset_admin_role: str
    stackset_exec_role: str
    enable_ioa: bool
    s3_bucket: str
    regions: str
    secret: str
    accounts: str
    parent_stack: str
    identity_protection: bool

    @classmethod
    def from_environment(cls) -> "LambdaConfig":
        """Create configuration from environment variables with validation"""

        def parse_bool(value: str, default: bool = False) -> bool:
            """Safely parse boolean from string"""
            if not value:
                return default
            return value.lower() in ("true", "1", "yes", "on")

        def get_required_env(key: str) -> str:
            """Get required environment variable"""
            value = os.environ.get(key)
            if not value:
                raise ValueError(f"Required environment variable {key} is not set")
            return value

        try:
            return cls(
                existing_cloudtrail=parse_bool(
                    os.environ.get("existing_cloudtrail", "false")
                ),
                sensor_management=parse_bool(
                    os.environ.get("sensor_management", "false")
                ),
                credentials_storage=get_required_env("credentials_storage"),
                aws_account_type=get_required_env("aws_account_type"),
                aws_region=get_required_env("current_region"),
                secret_list=get_required_env("secret_list"),
                stackset_admin_role=get_required_env("admin_role"),
                stackset_exec_role=get_required_env("exec_role"),
                enable_ioa=parse_bool(os.environ.get("enable_ioa", "false")),
                s3_bucket=get_required_env("s3_bucket"),
                regions=get_required_env("regions"),
                secret=get_required_env("secret"),
                accounts=get_required_env("accounts"),
                parent_stack=get_required_env("parent_stack"),
                identity_protection=parse_bool(
                    os.environ.get("identity_protection", "false")
                ),
            )
        except (ValueError, KeyError) as e:
            logger.error(f"Configuration error: {e}")
            raise


class AWSClientManager:
    """Centralized AWS client management with error handling"""

    def __init__(self, region: str):
        self.region = region
        self._clients = {}

    def get_client(self, service: str) -> Any:
        """Get AWS client with caching"""
        if service not in self._clients:
            try:
                session = boto3.Session()
                self._clients[service] = session.client(
                    service, region_name=self.region
                )
            except Exception as e:
                logger.error(f"Failed to create {service} client: {e}")
                raise
        return self._clients[service]


class SecretManager:
    """Secure secret management"""

    def __init__(self, aws_client_manager: AWSClientManager):
        self.client_manager = aws_client_manager

    def get_secret(self, secret_name: str, secret_region: str) -> Dict[str, Any]:
        """Retrieve and parse Falcon API Credentials from Secrets Manager"""
        client = self.client_manager.get_client("secretsmanager")

        try:
            logger.info(f"Retrieving secret: {secret_name}")
            response = client.get_secret_value(SecretId=secret_name)

            if "SecretString" in response:
                secret_string = response["SecretString"]
            else:
                secret_string = base64.b64decode(response["SecretBinary"]).decode(
                    "utf-8"
                )

            secret_data = json.loads(secret_string)

            # Validate required fields
            required_fields = ["FalconClientId", "FalconSecret", "FalconCloud"]
            for field in required_fields:
                if field not in secret_data:
                    raise ValueError(
                        f"Secret {secret_name} missing required field: {field}"
                    )

            return secret_data

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Failed to retrieve secret {secret_name}: {error_code}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse secret {secret_name} as JSON: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving secret {secret_name}: {e}")
            raise


class CrowdStrikeRegistrar:
    """Handle CrowdStrike account registration"""

    def __init__(self, config: LambdaConfig):
        self.config = config

    def register_account(
        self, account: str, credentials: Dict[str, str]
    ) -> Dict[str, Any]:
        """Register AWS Account with Falcon CSPM"""
        try:
            falcon = CSPMRegistration(
                client_id=credentials["FalconClientId"],
                client_secret=credentials["FalconSecret"],
                base_url=credentials["FalconCloud"],
                user_agent=USER_AGENT,
            )

            params = {
                "account_id": account,
                "account_type": self.config.aws_account_type,
                "behavior_assessment_enabled": True,
                "sensor_management_enabled": self.config.sensor_management,
                "use_existing_cloudtrail": self.config.existing_cloudtrail,
                "user_agent": USER_AGENT,
            }

            if not self.config.existing_cloudtrail:
                params["aws_cloudtrail_region"] = self.config.aws_region

            response = falcon.create_aws_account(**params)
            logger.info(
                f"Registration response for account {account}: status={response.get('status_code')}"
            )

            return response

        except Exception as e:
            logger.error(f"Failed to register account {account}: {e}")
            raise

    def register_features(
        self, credentials: Dict[str, str], aws_account_id: str
    ) -> Dict[str, Any]:
        """Register account with Cloud features"""
        try:
            falcon_cloud = CloudAWSRegistration(
                client_id=credentials["FalconClientId"],
                client_secret=credentials["FalconSecret"],
                user_agent=USER_AGENT,
            )

            response = falcon_cloud.create_account(
                account_id=aws_account_id,
                user_agent=USER_AGENT,
                is_master=True,
                account_type=self.config.aws_account_type,
                products=[{"features": ["default"], "product": "idp"}],
            )

            logger.info(
                f"Feature registration response for {aws_account_id}: status={response.get('status_code')}"
            )
            return response

        except Exception as e:
            logger.error(
                f"Failed to register features for account {aws_account_id}: {e}"
            )
            raise


class StackSetManager:
    """Manage CloudFormation StackSets with improved error handling"""

    def __init__(self, config: LambdaConfig, aws_client_manager: AWSClientManager):
        self.config = config
        self.client_manager = aws_client_manager

    def _get_timestamp(self) -> str:
        """Generate timestamp for operation IDs"""
        return datetime.datetime.now().strftime("%m%d%y%H%M%S")

    def _get_stack_tags(self) -> List[Dict[str, str]]:
        """Retrieve tags from parent stack"""
        try:
            client = self.client_manager.get_client("cloudformation")
            response = client.describe_stacks(StackName=self.config.parent_stack)
            return response["Stacks"][0].get("Tags", [])
        except Exception as e:
            logger.warning(f"Failed to retrieve parent stack tags: {e}")
            return []

    def _create_stackset_parameters(
        self, params: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Create standardized parameter list for StackSets"""
        parameter_list = []
        for key, value in params.items():
            parameter_list.append(
                {
                    "ParameterKey": key,
                    "ParameterValue": str(value),
                    "UsePreviousValue": False,
                }
            )
        return parameter_list

    def create_standard_stackset(
        self,
        account: str,
        template_url: str,
        parameters: Dict[str, str],
        stackset_suffix: str = "",
        target_regions: Optional[List[str]] = None,
    ) -> bool:
        """Create a standard StackSet with error handling and proper region targeting"""
        stackset_name = (
            f"CrowdStrike-Cloud-Security-Stackset-{account}{stackset_suffix}"
        )
        timestamp = self._get_timestamp()

        # Use provided regions or default to current region
        deployment_regions = target_regions or [self.config.aws_region]

        # Prepare tags: always include template_url, merge with parent stack tags
        parent_tags = self._get_stack_tags()
        template_url_tag = {"Key": "template_url", "Value": template_url}

        # Check if template_url tag already exists in parent tags
        template_url_exists = any(
            tag.get("Key") == "template_url" for tag in parent_tags
        )

        if template_url_exists:
            # Update existing template_url tag with current value
            for tag in parent_tags:
                if tag.get("Key") == "template_url":
                    tag["Value"] = template_url
            stackset_tags = parent_tags
        else:
            # Add template_url tag to parent tags
            stackset_tags = parent_tags + [template_url_tag]

        try:
            client = self.client_manager.get_client("cloudformation")

            # Create StackSet
            client.create_stack_set(
                StackSetName=stackset_name,
                Description=f"StackSet to onboard account {account} with CrowdStrike{stackset_suffix}",
                TemplateURL=template_url,
                Parameters=self._create_stackset_parameters(parameters),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                AdministrationRoleARN=self.config.stackset_admin_role,
                ExecutionRoleName=self.config.stackset_exec_role,
                PermissionModel="SELF_MANAGED",
                CallAs="SELF",
                Tags=stackset_tags,
            )

            # Create StackSet instances in appropriate regions
            client.create_stack_instances(
                StackSetName=stackset_name,
                Accounts=[account],
                Regions=deployment_regions,
                OperationPreferences={
                    "FailureTolerancePercentage": 100,
                    "MaxConcurrentPercentage": 100,
                    "ConcurrencyMode": "SOFT_FAILURE_TOLERANCE",
                },
                OperationId=f"{account}-{timestamp}{stackset_suffix}",
                CallAs="SELF",
            )

            logger.info(
                f"Successfully created StackSet {stackset_name} in regions: {deployment_regions}"
            )
            return True

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NameAlreadyExistsException":
                logger.warning(f"StackSet {stackset_name} already exists")
                return True
            else:
                logger.error(f"Failed to create StackSet {stackset_name}: {error_code}")
                return False
        except Exception as e:
            logger.error(f"Unexpected error creating StackSet {stackset_name}: {e}")
            return False


class RegionManager:
    """Manage AWS regions"""

    def __init__(self, config: LambdaConfig, aws_client_manager: AWSClientManager):
        self.config = config
        self.client_manager = aws_client_manager

    def get_active_regions(self) -> Tuple[List[str], List[str]]:
        """Retrieve active regions with error handling"""
        try:
            client = self.client_manager.get_client("ec2")
            response = client.describe_regions(AllRegions=False)

            active_regions = [region["RegionName"] for region in response["Regions"]]
            configured_regions = self.config.regions.split(",")

            my_regions = [
                region for region in active_regions if region in configured_regions
            ]
            comm_gov_eb_regions = [
                region for region in my_regions if region != self.config.aws_region
            ]

            logger.info(
                f"Active regions: {len(active_regions)}, Configured: {len(my_regions)}"
            )
            return my_regions, comm_gov_eb_regions

        except ClientError as e:
            logger.error(f"Failed to describe regions: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting regions: {e}")
            raise


class OrganizationManager:
    """Manage AWS Organizations operations"""

    def __init__(self, aws_client_manager: AWSClientManager):
        self.client_manager = aws_client_manager

    def get_accounts_from_ous(self, ou_list: str) -> List[str]:
        """Get account IDs from Organizational Units"""
        try:
            client = self.client_manager.get_client("organizations")
            accounts = []

            ous = [ou.strip() for ou in ou_list.split(",") if ou.strip()]

            for ou in ous:
                try:
                    response = client.list_children(ParentId=ou, ChildType="ACCOUNT")
                    ou_accounts = [
                        child["Id"] for child in response.get("Children", [])
                    ]
                    accounts.extend(ou_accounts)
                    logger.info(f"Found {len(ou_accounts)} accounts in OU {ou}")
                except ClientError as e:
                    logger.error(f"Failed to list children for OU {ou}: {e}")
                    continue

            return list(set(accounts))  # Remove duplicates

        except Exception as e:
            logger.error(f"Failed to get accounts from OUs: {e}")
            raise


def is_move_account_event(event: Dict[str, Any]) -> bool:
    """Detect if this is a MoveAccount event from AWS Organizations"""
    try:
        return (
            event.get("source") == "aws.organizations"
            and event.get("detail", {}).get("eventName") == "MoveAccount"
            and "requestParameters" in event.get("detail", {})
            and "accountId" in event.get("detail", {}).get("requestParameters", {})
            and "destinationParentId"
            in event.get("detail", {}).get("requestParameters", {})
        )
    except Exception:
        return False


def find_secret_for_ou(
    target_ou: str, config: LambdaConfig, secret_manager: SecretManager
) -> Optional[Dict[str, Any]]:
    """Find which secret contains the target OU in its OUs list"""
    try:
        secrets = [s.strip() for s in config.secret_list.split(",") if s.strip()]

        for secret_name in secrets:
            try:
                credentials = secret_manager.get_secret(secret_name, config.aws_region)

                if "OUs" in credentials:
                    ou_list = credentials["OUs"]
                    ous = [ou.strip() for ou in ou_list.split(",") if ou.strip()]

                    if target_ou in ous:
                        logger.info(
                            f"Found matching secret {secret_name} for OU {target_ou}"
                        )
                        return credentials

            except Exception as e:
                logger.error(f"Failed to check secret {secret_name}: {e}")
                continue

        logger.warning(f"No secret found containing OU {target_ou}")
        return None

    except Exception as e:
        logger.error(f"Failed to find secret for OU {target_ou}: {e}")
        return None


def process_move_account_event(
    event: Dict[str, Any],
    config: LambdaConfig,
    secret_manager: SecretManager,
    registrar: CrowdStrikeRegistrar,
    stackset_manager: StackSetManager,
    my_regions: List[str],
    comm_gov_eb_regions: List[str],
) -> Tuple[int, int]:
    """Process MoveAccount event"""
    try:
        # Extract account and OU from event
        account = event["detail"]["requestParameters"]["accountId"]
        ou = event["detail"]["requestParameters"]["destinationParentId"]

        logger.info(f"Processing MoveAccount event: account {account} moved to OU {ou}")

        # Find the appropriate secret for this OU
        credentials = find_secret_for_ou(ou, config, secret_manager)

        if not credentials:
            logger.error(
                f"No credentials found for OU {ou}, skipping account {account}"
            )
            return 0, 1

        # Process the single account
        if process_single_account(
            account,
            credentials,
            config,
            registrar,
            stackset_manager,
            my_regions,
            comm_gov_eb_regions,
        ):
            logger.info(
                f"Successfully processed account {account} from MoveAccount event"
            )
            return 1, 0
        else:
            logger.error(f"Failed to process account {account} from MoveAccount event")
            return 0, 1

    except KeyError as e:
        logger.error(f"MoveAccount event missing required field: {e}")
        return 0, 1
    except Exception as e:
        logger.error(f"Failed to process MoveAccount event: {e}")
        return 0, 1


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda handler with comprehensive error handling"""
    logger.info(f"Lambda function started - Version: {VERSION}")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    try:
        # Initialize configuration
        config = LambdaConfig.from_environment()
        logger.info("Configuration loaded successfully")

        # Initialize managers
        aws_client_manager = AWSClientManager(config.aws_region)
        secret_manager = SecretManager(aws_client_manager)
        registrar = CrowdStrikeRegistrar(config)
        stackset_manager = StackSetManager(config, aws_client_manager)
        region_manager = RegionManager(config, aws_client_manager)
        org_manager = OrganizationManager(aws_client_manager)

        # Get regions
        my_regions, comm_gov_eb_regions = region_manager.get_active_regions()

        # Process accounts based on trigger type
        success_count = 0
        failure_count = 0

        # Check if this is a MoveAccount event
        if is_move_account_event(event):
            logger.info("Detected MoveAccount event trigger")
            success_count, failure_count = process_move_account_event(
                event,
                config,
                secret_manager,
                registrar,
                stackset_manager,
                my_regions,
                comm_gov_eb_regions,
            )
        elif config.accounts.lower() == "auto":
            # Auto mode: process from secrets list
            logger.info("Processing in auto mode")
            success_count, failure_count = process_auto_mode(
                config,
                secret_manager,
                registrar,
                stackset_manager,
                org_manager,
                my_regions,
                comm_gov_eb_regions,
            )
        else:
            # Manual mode: process specific accounts
            logger.info("Processing in manual mode")
            success_count, failure_count = process_manual_mode(
                config,
                secret_manager,
                registrar,
                stackset_manager,
                my_regions,
                comm_gov_eb_regions,
            )

        result = {
            "statusCode": 200,
            "body": {
                "message": "Processing completed",
                "success_count": success_count,
                "failure_count": failure_count,
                "version": VERSION,
            },
        }

        logger.info(
            f"Lambda execution completed: {success_count} successes, {failure_count} failures"
        )
        return result

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": {
                "message": f"Lambda execution failed: {str(e)}",
                "version": VERSION,
            },
        }


def process_auto_mode(
    config: LambdaConfig,
    secret_manager: SecretManager,
    registrar: CrowdStrikeRegistrar,
    stackset_manager: StackSetManager,
    org_manager: OrganizationManager,
    my_regions: List[str],
    comm_gov_eb_regions: List[str],
) -> Tuple[int, int]:
    """Process accounts in auto mode"""
    success_count = 0
    failure_count = 0

    try:
        secrets = [s.strip() for s in config.secret_list.split(",") if s.strip()]

        for secret_name in secrets:
            try:
                credentials = secret_manager.get_secret(secret_name, config.aws_region)

                if "OUs" in credentials:
                    accounts = org_manager.get_accounts_from_ous(credentials["OUs"])
                else:
                    logger.warning(f"No OUs found in secret {secret_name}")
                    continue

                for account in accounts:
                    try:
                        if process_single_account(
                            account,
                            credentials,
                            config,
                            registrar,
                            stackset_manager,
                            my_regions,
                            comm_gov_eb_regions,
                        ):
                            success_count += 1
                        else:
                            failure_count += 1
                    except Exception as e:
                        logger.error(f"Failed to process account {account}: {e}")
                        failure_count += 1

            except Exception as e:
                logger.error(f"Failed to process secret {secret_name}: {e}")
                failure_count += 1

    except Exception as e:
        logger.error(f"Failed in auto mode processing: {e}")
        raise

    return success_count, failure_count


def process_manual_mode(
    config: LambdaConfig,
    secret_manager: SecretManager,
    registrar: CrowdStrikeRegistrar,
    stackset_manager: StackSetManager,
    my_regions: List[str],
    comm_gov_eb_regions: List[str],
) -> Tuple[int, int]:
    """Process accounts in manual mode"""
    success_count = 0
    failure_count = 0

    try:
        credentials = secret_manager.get_secret(config.secret, config.aws_region)
        accounts = [acc.strip() for acc in config.accounts.split(",") if acc.strip()]

        for account in accounts:
            try:
                if process_single_account(
                    account,
                    credentials,
                    config,
                    registrar,
                    stackset_manager,
                    my_regions,
                    comm_gov_eb_regions,
                ):
                    success_count += 1
                else:
                    failure_count += 1
            except Exception as e:
                logger.error(f"Failed to process account {account}: {e}")
                failure_count += 1

    except Exception as e:
        logger.error(f"Failed in manual mode processing: {e}")
        raise

    return success_count, failure_count


def process_single_account(
    account: str,
    credentials: Dict[str, str],
    config: LambdaConfig,
    registrar: CrowdStrikeRegistrar,
    stackset_manager: StackSetManager,
    my_regions: List[str],
    comm_gov_eb_regions: List[str],
) -> bool:
    """Process a single account registration"""
    logger.info(f"Processing account: {account}")

    try:
        # Register account with CrowdStrike
        response = registrar.register_account(account, credentials)

        if response.get("status_code") == 400:
            error_msg = (
                response.get("body", {})
                .get("errors", [{}])[0]
                .get("message", "Unknown error")
            )
            logger.error(f"Account {account} registration failed: {error_msg}")
            return False

        elif response.get("status_code") == 201:
            logger.info(f"Account {account} registration succeeded")

            # Register identity protection features if enabled
            if config.identity_protection:
                try:
                    registrar.register_features(credentials, account)
                except Exception as e:
                    logger.error(
                        f"Failed to register identity protection for {account}: {e}"
                    )
                    # Continue processing even if feature registration fails

            # Extract registration details
            try:
                resource = response["body"]["resources"][0]
                cs_account = resource["intermediate_role_arn"].split("::")[1]
                cs_account_id = cs_account.split(":")[0]
                iam_role_name = resource["iam_role_arn"].split("/")[-1]
                cs_role_name = resource["intermediate_role_arn"].split("/")[-1]
                external_id = resource["external_id"]

                # Create StackSets based on cloud type
                return orchestrate_stacksets(
                    credentials["FalconCloud"],
                    response,
                    account,
                    iam_role_name,
                    external_id,
                    cs_role_name,
                    cs_account_id,
                    credentials,
                    config,
                    stackset_manager,
                    my_regions,
                    comm_gov_eb_regions,
                )

            except (KeyError, IndexError) as e:
                logger.error(
                    f"Failed to extract registration details for {account}: {e}"
                )
                return False

        else:
            logger.error(
                f"Unexpected response status for account {account}: {response.get('status_code')}"
            )
            return False

    except Exception as e:
        logger.error(f"Failed to process account {account}: {e}")
        return False


def orchestrate_stacksets(
    falcon_cloud: str,
    response: Dict[str, Any],
    account: str,
    iam_role_name: str,
    external_id: str,
    cs_role_name: str,
    cs_account_id: str,
    credentials: Dict[str, str],
    config: LambdaConfig,
    stackset_manager: StackSetManager,
    my_regions: List[str],
    comm_gov_eb_regions: List[str],
) -> bool:
    """Orchestrate StackSet creation based on cloud type"""

    try:
        # Common parameters
        base_params = {
            "RoleName": iam_role_name,
            "ExternalID": external_id,
            "CSRoleName": cs_role_name,
            "CSAccountNumber": cs_account_id,
            "ClientID": credentials["FalconClientId"],
            "ClientSecret": credentials["FalconSecret"],
            "UseExistingCloudtrail": str(config.existing_cloudtrail).lower(),
            "EnableSensorManagement": str(config.sensor_management).lower(),
            "APICredentialsStorageMode": config.credentials_storage,
        }

        # Add cloud trail bucket if not using existing
        if not config.existing_cloudtrail:
            cs_bucket_name = response["body"]["resources"][0].get(
                "aws_cloudtrail_bucket_name", "none"
            )
        else:
            cs_bucket_name = "none"

        base_params["CSBucketName"] = cs_bucket_name

        # Handle different cloud configurations with proper region targeting
        if "gov" not in falcon_cloud:
            # Commercial cloud - Main stackset deploys to current region only
            cs_eventbus_name = response["body"]["resources"][0].get("eventbus_name", "")
            base_params.update(
                {
                    "CSEventBusName": cs_eventbus_name,
                    "EnableIOA": str(config.enable_ioa).lower(),
                }
            )

            template_url = "https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json"

            # Main CSPM stackset: current region only
            return stackset_manager.create_standard_stackset(
                account,
                template_url,
                base_params,
                target_regions=[config.aws_region],
            )

        elif "gov" in falcon_cloud and config.aws_account_type == "govcloud":
            # Gov to Gov
            cs_eventbus_name = (
                response["body"]["resources"][0].get("eventbus_name", "").split(",")[0]
            )
            base_params.update(
                {
                    "CSEventBusName": cs_eventbus_name,
                    "EnableIOA": str(config.enable_ioa).lower(),
                }
            )

            template_url = "https://cs-csgov-laggar-cloudconnect-templates.s3-us-gov-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json"

            # Main CSPM stackset: current region only
            return stackset_manager.create_standard_stackset(
                account, template_url, base_params, target_regions=[config.aws_region]
            )

        elif "gov" in falcon_cloud and config.aws_account_type == "commercial":
            # Commercial to Gov
            base_params["EnableIOA"] = "false"  # Hardcoded for comm to gov

            template_url = f"https://{config.s3_bucket}.s3.{config.aws_region}.amazonaws.com/crowdstrike_aws_cspm.json"

            # Main CSPM stackset: current region only
            success = stackset_manager.create_standard_stackset(
                account, template_url, base_params, target_regions=[config.aws_region]
            )

            # Create additional StackSets for Commercial to Gov
            if success:
                # EB StackSet - deploy to additional regions
                if comm_gov_eb_regions:
                    eb_params = {"DefaultEventBusRegion": config.aws_region}
                    eb_template_url = "https://cs-prod-cloudconnect-templates.s3.amazonaws.com/aws_cspm_cloudformation_eb_gov_comm_v2.json"

                    # EB stackset: deploy to additional regions (excluding current region)
                    stackset_manager.create_standard_stackset(
                        account,
                        eb_template_url,
                        eb_params,
                        "-EB",
                        target_regions=comm_gov_eb_regions,
                    )
                    logger.info(
                        f"Commercial-to-Gov EB StackSet will be deployed to regions: {comm_gov_eb_regions}"
                    )

                # IOA StackSet - deploy to all configured regions
                if my_regions:
                    ioa_params = {
                        "ClientID": credentials["FalconClientId"],
                        "ClientSecret": credentials["FalconSecret"],
                    }
                    ioa_template_url = "https://cs-prod-cloudconnect-templates.s3.amazonaws.com/aws_cspm_cloudformation_gov_commercial_ioa_lambda_v2.json"

                    # IOA stackset: deploy to all configured regions
                    stackset_manager.create_standard_stackset(
                        account,
                        ioa_template_url,
                        ioa_params,
                        "-IOA",
                        target_regions=my_regions,
                    )
                    logger.info(
                        f"Commercial-to-Gov IOA StackSet will be deployed to regions: {my_regions}"
                    )

            return success

        else:
            logger.error(
                f"Unsupported cloud configuration: {falcon_cloud}, account_type: {config.aws_account_type}"
            )
            return False

    except Exception as e:
        logger.error(f"Failed to orchestrate stacksets for account {account}: {e}")
        return False
