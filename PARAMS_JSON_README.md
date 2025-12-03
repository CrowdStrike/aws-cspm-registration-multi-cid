# CloudFormation Parameter File

**Parameter Files:**
- `params.json`

**Important Notes:**
- It is recommended to copy the template file and customize with your actual values.

## Parameter Details
The Parameters in this template are divided into three sections.

### Multi-CID Configuration
This template provides parameters to create two AWS Secrets Manager Secrets, each to contain a different set of Falcon API credentials and the corresponding list of AWS OUs.  These secrets determine which AWS OUs are registered to which Falcon CID.
| Parameter | Description | Options |
|---|---|---|
|CIDA| Falcon CID for OUA, FalconClientIdA & FalconSecretA |string|
|OUA| List of OUs to register with CIDA |list of string|
|FalconClientIdA| Your CrowdStrike Falcon OAuth2 Client ID for CIDA |string|
|FalconSecretA| Your CrowdStrike Falcon OAuth2 API Secret for CIDA|string|
|CIDB| Falcon CID for OUB, FalconClientIdB & FalconSecretB |string|
|OUB| List of OUs to register with CIDB |list of string|
|FalconClientIdB| Your CrowdStrike Falcon OAuth2 Client ID for CIDB |string|
|FalconSecretB| Your CrowdStrike Falcon OAuth2 API Secret for CIDB|string|

### CSPM Configuration
This section provides the parameters necessary to configure your CSPM Registration.
| Parameter | Description | Options |
|---|---|---|
|EnableIOA| Whether to enable IOAs| true, false |
|EnableIDP| Whether to enable Identity Protection| true, false |
|UseExistingCloudTrail| Select False ONLY if you wish to create a new cloudtrail for Read-Only IOAs (this is not common) | true, false |
|EnableSensorManagement| Whether to enable Sensor Management | true, false|
|APICredentialsStorageMode| If EnableSensorManagement = true, whether to store falcon API credentials in Secrets Manager or as lambda environment variables.| secret, lambda|
|NestedOUs| Whether to register accounts in nested OUs under the provided OUs (True) or only direct children (False)| true, false|
|Regions| Which regions to enable IOA|string|

### Misc
This section provides additional parameters to complete the deployment of this solution.
| Parameter | Description | Options |
|---|---|---|
|S3Bucket| NAME of the S3 Bucket used in Step 3 of Setup| string |
|AWSAccountType| Whether this AWS Organization is commercial or GovCloud | commercial, govcloud |
|RootOU| (Optional/Legacy) Root OU - StackSet roles now deploy to specific OUs (OUA/OUB) instead of root OU | string|
|StackSetAdminRole| What to Name the Administration Role for CrowdStrike StackSets, this role will be created as a part of this stack | string|
|StackSetExecRole| What to Name the Execution Role for CrowdStrike StackSets, this role will be created as a part of this stack |string|
