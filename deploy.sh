#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'  
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo -e "${BLUE}Usage: $0 [OPTIONS] [S3_BUCKET] [STACK_NAME]${NC}"
    echo ""
    echo "Package and deploy CrowdStrike Lambda functions"
    echo ""
    echo "MODES:"
    echo "  1. Package only:           $0"
    echo "  2. Package & upload:       $0 S3_BUCKET"
    echo "  3. Package, upload & deploy: $0 S3_BUCKET --deploy STACK_NAME"
    echo "  4. Deploy only:            $0 --deploy-only STACK_NAME S3_BUCKET"
    echo ""
    echo "OPTIONS:"
    echo "  --deploy STACK_NAME        Deploy CloudFormation stack after packaging and uploading"
    echo "  --deploy-only STACK_NAME   Deploy CloudFormation stack only (skip packaging)"
    echo "  --params-file FILE         CloudFormation parameters file (JSON/YAML)"
    echo "  --template-file FILE       CloudFormation template file (default: init_crowdstrike_multiple_cid.yml)"
    echo ""
    echo "ARGUMENTS:"
    echo "  S3_BUCKET                  S3 bucket name for Lambda functions and template"
    echo "  STACK_NAME                 CloudFormation stack name"
    echo ""
    echo "Examples:"
    echo "  $0                                                    # Package functions locally"
    echo "  $0 my-bucket                                          # Package and upload to S3"
    echo "  $0 my-bucket --deploy my-stack                        # Package, upload, and deploy"
    echo "  $0 --deploy-only my-stack my-bucket                   # Deploy existing resources"
    echo "  $0 my-bucket --deploy my-stack --params-file params.json  # Deploy with parameters"
    echo ""
}

# Function to package a single Lambda function
package_lambda() {
    local lambda_type="$1"
    local lambda_dir="source/$lambda_type"
    local lambda_file="lambda_function.py"
    local output_zip="${lambda_type//-/_}_lambda_function.zip"
    local temp_dir="lambda_package_temp_$lambda_type"

    echo -e "${GREEN}=== Packaging $lambda_type Lambda Function ===${NC}"
    echo "Source: $lambda_dir/$lambda_file"
    echo "Output: $output_zip"
    echo ""

    # Check if source file exists
    if [ ! -f "$lambda_dir/$lambda_file" ]; then
        echo -e "${RED}Error: $lambda_dir/$lambda_file not found!${NC}"
        return 1
    fi

    # Clean up any existing temp directory
    if [ -d "$temp_dir" ]; then
        rm -rf "$temp_dir"
    fi

    # Create temporary directory
    mkdir -p "$temp_dir"

    # Install requirements
    if [ -f "$lambda_dir/requirements.txt" ]; then
        echo -e "${GREEN}Installing Python dependencies from requirements.txt...${NC}"
        pip3 install --target "$temp_dir" -r "$lambda_dir/requirements.txt" --quiet
    fi

    # Copy Lambda function
    cp "$lambda_dir/$lambda_file" "$temp_dir/"

    # Remove unnecessary files to reduce package size
    find "$temp_dir" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$temp_dir" -name "*.pyc" -delete 2>/dev/null || true
    find "$temp_dir" -name "*.pyo" -delete 2>/dev/null || true
    find "$temp_dir" -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true

    # Create zip file
    echo -e "${GREEN}Creating zip file...${NC}"
    cd "$temp_dir"
    zip -r "../$output_zip" . -q
    cd ..

    # Clean up temp directory
    rm -rf "$temp_dir"

    # Show results
    if [ -f "$output_zip" ]; then
        ZIP_SIZE=$(ls -lh "$output_zip" | awk '{print $5}')
        echo -e "${GREEN}✅ Success!${NC}"
        echo "Created: $output_zip ($ZIP_SIZE)"
        echo ""
        return 0
    else
        echo -e "${RED}❌ Error: Failed to create zip file${NC}"
        return 1
    fi
}

# Function to upload files to S3
upload_to_s3() {
    local s3_bucket="$1"
    local zip_files=()
    local additional_files=()
    
    # Find all lambda function zip files
    for zip_file in *_lambda_function.zip; do
        if [ -f "$zip_file" ]; then
            zip_files+=("$zip_file")
        fi
    done
    
    # Add additional template files to upload
    if [ -f "crowdstrike_stackset_role_setup.yml" ]; then
        additional_files+=("crowdstrike_stackset_role_setup.yml")
    fi
    
    local total_files=$((${#zip_files[@]} + ${#additional_files[@]}))
    
    if [ $total_files -eq 0 ]; then
        echo -e "${YELLOW}No files found to upload${NC}"
        return 1
    fi
    
    echo -e "${GREEN}=== Uploading to S3 bucket: s3://$s3_bucket ===${NC}"
    echo ""
    
    # Check if AWS CLI is available
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}Error: AWS CLI not found. Please install AWS CLI to upload to S3.${NC}"
        return 1
    fi
    
    local upload_success=0
    
    # Upload each zip file
    for zip_file in "${zip_files[@]}"; do
        echo -e "${GREEN}Uploading $zip_file...${NC}"
        if aws s3 cp "$zip_file" "s3://$s3_bucket/$zip_file" --quiet; then
            echo -e "${GREEN}✅ Successfully uploaded: s3://$s3_bucket/$zip_file${NC}"
            ((upload_success++))
        else
            echo -e "${RED}❌ Failed to upload: $zip_file${NC}"
        fi
        echo ""
    done
    
    # Upload additional template files
    for template_file in "${additional_files[@]}"; do
        echo -e "${GREEN}Uploading $template_file...${NC}"
        if aws s3 cp "$template_file" "s3://$s3_bucket/$template_file" --quiet; then
            echo -e "${GREEN}✅ Successfully uploaded: s3://$s3_bucket/$template_file${NC}"
            ((upload_success++))
        else
            echo -e "${RED}❌ Failed to upload: $template_file${NC}"
        fi
        echo ""
    done
    
    echo -e "${BLUE}=== S3 Upload Summary ===${NC}"
    echo "Successfully uploaded: $upload_success/$total_files files"
    
    if [ $upload_success -eq $total_files ]; then
        echo -e "${GREEN}✅ All files uploaded successfully to S3!${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Some files failed to upload${NC}"
        return 1
    fi
}

# Function to upload CloudFormation template to S3
upload_template_to_s3() {
    local s3_bucket="$1"
    local template_file="$2"
    
    echo -e "${GREEN}=== Uploading CloudFormation Template ===${NC}"
    echo "Template: $template_file"
    echo "Destination: s3://$s3_bucket/$template_file"
    echo ""
    
    if aws s3 cp "$template_file" "s3://$s3_bucket/$template_file" --quiet; then
        echo -e "${GREEN}✅ Template uploaded successfully${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to upload template${NC}"
        return 1
    fi
}

# Function to parse JSON parameter file and convert to parameter overrides
parse_parameter_file() {
    local params_file="$1"
    local param_overrides=""
    
    if [ ! -f "$params_file" ]; then
        echo ""
        return 1
    fi
    
    # Check if jq is available for JSON parsing
    if command -v jq &> /dev/null; then
        # Use jq to parse JSON parameter file
        local params=$(jq -r '.[] | "\(.ParameterKey)=\(.ParameterValue)"' "$params_file" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$params" ]; then
            param_overrides="$params"
        fi
    else
        # Fallback: basic parsing without jq (less robust)
        echo -e "${YELLOW}Warning: jq not found. Using basic JSON parsing. Install jq for better reliability.${NC}"
        param_overrides=$(grep -o '"ParameterKey"[^}]*"ParameterValue"[^"]*"[^"]*"' "$params_file" | \
                         sed 's/.*"ParameterKey"[^"]*"\([^"]*\)".*"ParameterValue"[^"]*"\([^"]*\)".*/\1=\2/' 2>/dev/null)
    fi
    
    echo "$param_overrides"
    return 0
}

# Function to deploy CloudFormation stack
deploy_cloudformation() {
    local stack_name="$1"
    local s3_bucket="$2"
    local template_file="$3"
    local params_file="$4"
    
    echo -e "${GREEN}=== Deploying CloudFormation Stack ===${NC}"
    echo "Stack Name: $stack_name"
    echo "Template: $template_file"
    echo "S3 Bucket: $s3_bucket"
    echo ""
    
    # Check if AWS CLI is available
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}Error: AWS CLI not found. Please install AWS CLI to deploy CloudFormation.${NC}"
        return 1
    fi
    
    # Check if template file exists
    if [ ! -f "$template_file" ]; then
        echo -e "${RED}Error: Template file $template_file not found!${NC}"
        return 1
    fi
    
    # Upload template to S3
    if ! upload_template_to_s3 "$s3_bucket" "$template_file"; then
        return 1
    fi
    echo ""
    
    # Build CloudFormation command
    local cf_cmd="aws cloudformation deploy"
    cf_cmd+=" --template-file $template_file"
    cf_cmd+=" --stack-name $stack_name"
    cf_cmd+=" --capabilities CAPABILITY_NAMED_IAM CAPABILITY_IAM"
    
    # Build parameter overrides
    local all_param_overrides="S3Bucket=$s3_bucket"
    
    # Add parameters from file if provided
    if [ -n "$params_file" ] && [ -f "$params_file" ]; then
        echo -e "${GREEN}Parsing parameters file: $params_file${NC}"
        local file_params=$(parse_parameter_file "$params_file")
        if [ -n "$file_params" ]; then
            # Add file parameters, with S3Bucket override taking precedence
            all_param_overrides="$file_params $all_param_overrides"
            echo -e "${GREEN}Loaded parameters from file${NC}"
        else
            echo -e "${YELLOW}Warning: Could not parse parameters from file${NC}"
        fi
        echo ""
    fi
    
    # Add all parameter overrides
    cf_cmd+=" --parameter-overrides $all_param_overrides"
    
    echo -e "${GREEN}Executing CloudFormation deployment...${NC}"
    #echo "Command: $cf_cmd"
    echo ""
    
    # Execute deployment
    if eval $cf_cmd; then
        echo ""
        echo -e "${GREEN}✅ CloudFormation stack deployed successfully!${NC}"
        echo "Stack Name: $stack_name"
        
        # Get stack outputs
        echo ""
        echo -e "${BLUE}=== Stack Outputs ===${NC}"
        aws cloudformation describe-stacks --stack-name "$stack_name" --query 'Stacks[0].Outputs' --output table 2>/dev/null || echo "No outputs available"
        
        return 0
    else
        echo ""
        echo -e "${RED}❌ CloudFormation deployment failed${NC}"
        return 1
    fi
}

# Function to parse command line arguments
parse_arguments() {
    # Initialize default values (using global variables for compatibility)
    ARG_MODE=""
    ARG_S3_BUCKET=""
    ARG_STACK_NAME=""
    ARG_TEMPLATE_FILE="init_crowdstrike_multiple_cid.yml"
    ARG_PARAMS_FILE=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deploy)
                ARG_MODE="package_upload_deploy"
                ARG_STACK_NAME="$2"
                shift 2
                ;;
            --deploy-only)
                ARG_MODE="deploy_only"
                ARG_STACK_NAME="$2"
                shift 2
                ;;
            --params-file)
                ARG_PARAMS_FILE="$2"
                shift 2
                ;;
            --template-file)
                ARG_TEMPLATE_FILE="$2"
                shift 2
                ;;
            -h|--help|help)
                usage
                exit 0
                ;;
            -*)
                echo -e "${RED}Error: Unknown option $1${NC}"
                usage
                exit 1
                ;;
            *)
                # Positional argument - could be S3 bucket
                if [ -z "$ARG_S3_BUCKET" ]; then
                    ARG_S3_BUCKET="$1"
                elif [ "$ARG_MODE" = "deploy_only" ] && [ -z "$ARG_S3_BUCKET" ]; then
                    ARG_S3_BUCKET="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Determine mode if not explicitly set
    if [ -z "$ARG_MODE" ]; then
        if [ -n "$ARG_S3_BUCKET" ]; then
            ARG_MODE="package_upload"
        else
            ARG_MODE="package_only"
        fi
    fi
    
    # Validate arguments based on mode
    case "$ARG_MODE" in
        package_only)
            # No additional validation needed
            ;;
        package_upload)
            if [ -z "$ARG_S3_BUCKET" ]; then
                echo -e "${RED}Error: S3 bucket required for upload mode${NC}"
                return 1
            fi
            ;;
        package_upload_deploy)
            if [ -z "$ARG_S3_BUCKET" ] || [ -z "$ARG_STACK_NAME" ]; then
                echo -e "${RED}Error: S3 bucket and stack name required for deploy mode${NC}"
                return 1
            fi
            ;;
        deploy_only)
            if [ -z "$ARG_S3_BUCKET" ] || [ -z "$ARG_STACK_NAME" ]; then
                echo -e "${RED}Error: S3 bucket and stack name required for deploy-only mode${NC}"
                return 1
            fi
            ;;
    esac
    
    return 0
}

# Function to execute packaging workflow
execute_packaging() {
    echo -e "${BLUE}=== CrowdStrike Lambda Packaging Tool ===${NC}"
    echo ""
    echo -e "${GREEN}Packaging all Lambda functions...${NC}"
    echo ""
    
    local functions=("init" "update")
    local success_count=0
    local total_count=${#functions[@]}
    
    for func in "${functions[@]}"; do
        if package_lambda "$func"; then
            ((success_count++))
        fi
        echo "----------------------------------------"
    done
    
    echo -e "${BLUE}=== Packaging Summary ===${NC}"
    echo "Successfully packaged: $success_count/$total_count functions"
    
    if [ $success_count -eq $total_count ]; then
        echo -e "${GREEN}✅ Both functions packaged successfully!${NC}"
        echo ""
        echo "Created zip files:"
        ls -la *_lambda_function.zip 2>/dev/null || echo "No zip files found"
        return 0
    else
        echo -e "${YELLOW}⚠️  Some functions failed to package${NC}"
        return 1
    fi
}

# Main script logic
main() {
    # Parse command line arguments
    if ! parse_arguments "$@"; then
        exit 1
    fi
    
    # Debug output (uncomment for troubleshooting)
    # echo "Mode: $ARG_MODE"
    # echo "S3 Bucket: $ARG_S3_BUCKET"
    # echo "Stack Name: $ARG_STACK_NAME"
    # echo "Template File: $ARG_TEMPLATE_FILE"
    # echo "Params File: $ARG_PARAMS_FILE"
    # echo ""
    
    case "$ARG_MODE" in
        package_only)
            echo -e "${BLUE}=== Mode 1: Package Functions Only ===${NC}"
            echo ""
            if execute_packaging; then
                echo ""
                echo -e "${GREEN}✅ Functions packaged successfully and ready for upload!${NC}"
            else
                exit 1
            fi
            ;;
            
        package_upload)
            echo -e "${BLUE}=== Mode 2: Package and Upload Functions ===${NC}"
            echo ""
            if execute_packaging; then
                echo "----------------------------------------"
                if upload_to_s3 "$ARG_S3_BUCKET"; then
                    echo ""
                    echo -e "${GREEN}✅ Functions packaged and uploaded successfully!${NC}"
                else
                    echo ""
                    echo -e "${YELLOW}⚠️  Functions packaged but S3 upload failed${NC}"
                    exit 1
                fi
            else
                exit 1
            fi
            ;;
            
        package_upload_deploy)
            echo -e "${BLUE}=== Mode 3: Package, Upload, and Deploy ===${NC}"
            echo ""
            if execute_packaging; then
                echo "----------------------------------------"
                if upload_to_s3 "$ARG_S3_BUCKET"; then
                    echo "----------------------------------------"
                    if deploy_cloudformation "$ARG_STACK_NAME" "$ARG_S3_BUCKET" "$ARG_TEMPLATE_FILE" "$ARG_PARAMS_FILE"; then
                        echo ""
                        echo -e "${GREEN}✅ Complete deployment pipeline executed successfully!${NC}"
                    else
                        echo ""
                        echo -e "${YELLOW}⚠️  Functions uploaded but CloudFormation deployment failed${NC}"
                        exit 1
                    fi
                else
                    echo ""
                    echo -e "${YELLOW}⚠️  Functions packaged but S3 upload failed${NC}"
                    exit 1
                fi
            else
                exit 1
            fi
            ;;
            
        deploy_only)
            echo -e "${BLUE}=== Mode 4: Deploy CloudFormation Only ===${NC}"
            echo ""
            # Upload any additional template files to S3 first
            if upload_to_s3 "$ARG_S3_BUCKET"; then
                echo "----------------------------------------"
            fi
            if deploy_cloudformation "$ARG_STACK_NAME" "$ARG_S3_BUCKET" "$ARG_TEMPLATE_FILE" "$ARG_PARAMS_FILE"; then
                echo ""
                echo -e "${GREEN}✅ CloudFormation deployment completed successfully!${NC}"
            else
                echo ""
                echo -e "${RED}❌ CloudFormation deployment failed${NC}"
                exit 1
            fi
            ;;
            
        *)
            echo -e "${RED}Error: Unknown mode $ARG_MODE${NC}"
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
