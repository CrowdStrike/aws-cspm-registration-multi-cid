# Update Instructions

## Apply Latest CSPM Template
On occasion CrowdStrike will add new permissions requirements for the IAM role used for CSPM to ensure the latest AWS services are protected. The update function automatically identifies and updates all stacksets created by the init function.

To update your existing IAM Roles complete the following steps: 

### Invoke Update with CLI

```bash
aws lambda invoke \
    --function-name crowdstrike-multi-cid-update-stacksets \
    --payload '{}' \
    response.json
```

### Invoke Update manually in AWS Console
1. Navigate to Lambda and open the crowdstrike-cloud-update-stacksets function.
2. Create and save an empty test event. eg. {}
3. Click test. This will invoke the function and automatically:
   - Find all stacksets created by the init function (using `template_url` tags)
   - Retrieve the current template URL for each stackset
   - Apply the latest template to update permissions

## Enable/Disable Services
This solution allows for services to be enabled or disabled after the initial deployment.

### 1Click
If 1click was not enabled, ie. the parameter ```EnableSensorManagement``` was set to false, and you wish to enable after deployment of this solution:

**For existing Accounts:**
1. Navigate to CloudFormation StackSets and select the ```CrowdStrike-Cloud-Security-Stackset-{account-id}```.
2. Click **Actions** and click **Override StackSet Parameters**.
3. Add the Account ID and region and click next.
4. Select the ```EnableSensorManagement``` and click **Edit override value** and **Override StackSet Value**.
5. Change the value from ```false``` to ```true``` and **save changes**.
6. Click **Next** then **Submit**

This will update the stack within the target account to deploy 1Click resources.  Within a few minutes, 1Click should be **Active** in the Falcon Console.

**For all Accounts going forward:**
1. Navigate to Lambda and open the function ```crowdstrike-cloud-new-registration```.
2. Click on **Configuration** and **Environment Variables**.
3. Update the value on ```sensor_management``` from ```False``` to ```True```.
4. Save.
5. Repeat the above steps for the Lambda function ```crowdstrike-cloud-initial-registration```.

This will ensure all future account registrations will apply the stacksets with ```EnableSensorManagement``` set to ```true`` which will ensure the target account is onboarded with 1Click Resources.

The above steps are the same if you are instead **Disabling** 1Click after having deployed this solution with 1Click **Enabled**.  For each relevant step, instead change the value from ```True``` to ```False```.
