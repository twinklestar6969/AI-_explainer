#!/usr/bin/env python3
"""
Verify IAM permissions and Bedrock connectivity for GPT-5.6 Luna on Amazon Bedrock.
Tests OpenAI Responses API (invoke_model) instead of Anthropic Converse API.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
import boto3
import json

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

print("=" * 80)
print("BEDROCK IAM PERMISSIONS & GPT-5.6 LUNA CONNECTIVITY VERIFICATION")
print("=" * 80)

# Get AWS identity
sts_client = boto3.client("sts")
identity = sts_client.get_caller_identity()
user_arn = identity['Arn']
user_name = user_arn.split('/')[-1]

print(f"\n✓ AWS Identity: {user_arn}")
print(f"  Account: {identity['Account']}")

# Get bedrock configuration
aws_region = os.getenv("AWS_REGION", "us-east-1")
bedrock_model_id = os.getenv("BEDROCK_MODEL_ID")

print(f"\n✓ Bedrock Configuration:")
print(f"  Region: {aws_region}")
print(f"  Model: {bedrock_model_id}")
print(f"  API: OpenAI Responses API (invoke_model)")

# Check IAM inline policies
print(f"\n✓ Checking IAM Policies for user '{user_name}'...")
iam_client = boto3.client("iam")

try:
    # Get inline policies
    inline_policies = iam_client.list_user_policies(UserName=user_name)
    print(f"\n  Inline Policies ({len(inline_policies['PolicyNames'])}):")
    
    has_bedrock_permission = False
    for policy_name in inline_policies['PolicyNames']:
        policy = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
        policy_doc = policy['UserPolicy']
        policy_json = json.dumps(policy_doc)
        
        print(f"    - {policy_name}")
        
        # Check for bedrock permissions
        if 'bedrock' in policy_json.lower():
            statements = policy_doc.get('Statement', [])
            for stmt in statements:
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if 'bedrock' in action.lower() and 'invoke' in action.lower():
                        has_bedrock_permission = True
                        print(f"      ✓ Contains: {action}")
    
    if has_bedrock_permission:
        print(f"\n✓ Required bedrock:InvokeModel permission found!")
    else:
        print(f"\n⚠ Warning: bedrock:InvokeModel permission not clearly found in explicit scans")
        print(f"  Full policy document:")
        for policy_name in inline_policies['PolicyNames']:
            policy = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
            print(json.dumps(policy['UserPolicy'], indent=4))

except Exception as e:
    print(f"  ✗ Error checking policies: {e}")

# Test Bedrock connection with GPT-5.6 Luna
print(f"\n✓ Testing Bedrock Connection with {bedrock_model_id}...")
try:
    bedrock_runtime = boto3.client("bedrock-runtime", region_name=aws_region)
    
    # OpenAI Responses API format for GPT-5.6 Luna (uses invoke_model, not converse)
    request_body = {
        "messages": [
            {
                "role": "user",
                "content": "Say 'Hello from GPT-5.6 Luna' only."
            }
        ],
        "max_tokens": 100,
        "temperature": 0.5
    }
    
    response = bedrock_runtime.invoke_model(
        modelId=bedrock_model_id,
        body=json.dumps(request_body),
        contentType="application/json",
        accept="application/json"
    )
    
    response_body = json.loads(response["body"].read())
    result_text = response_body["choices"][0]["message"]["content"]
    print(f"  ✓ Bedrock connection successful!")
    print(f"  ✓ Model responded: {result_text}")
    
except Exception as e:
    error_str = str(e)
    print(f"  ✗ Bedrock connection failed: {error_str}")
    
    if "AccessDenied" in error_str or "not authorized" in error_str.lower():
        print(f"\n  ERROR: AWS IAM access denied!")
        print(f"  ACTION REQUIRED:")
        print(f"    1. Verify IAM permissions allow bedrock:InvokeModel")
        print(f"    2. Check AWS credentials are configured correctly")
        print(f"    3. Ensure the IAM user/role has the BedrockInvokeModelAccess policy")
    elif "ResourceNotFoundException" in error_str or "not found" in error_str.lower():
        print(f"\n  ERROR: Model not found!")
        print(f"  ACTION REQUIRED:")
        print(f"    1. Go to: https://console.aws.amazon.com/bedrock/home?region=us-east-1")
        print(f"    2. Click 'Model Access' in the left sidebar")
        print(f"    3. Search for 'GPT-5.6 Luna' by OpenAI")
        print(f"    4. Verify it shows 'Access Granted'")
    elif "ValidationException" in error_str or "Operation not allowed" in error_str:
        print(f"\n  ERROR: Bedrock validation error!")
        print(f"  This may indicate:")
        print(f"    - Model access not enabled in AWS Bedrock console")
        print(f"    - Required service agreement not accepted")
        print(f"  ACTION REQUIRED:")
        print(f"    1. Go to: https://console.aws.amazon.com/bedrock/home?region=us-east-1")
        print(f"    2. Click 'Model Access' in the left sidebar")
        print(f"    3. Find 'GPT-5.6 Luna' and verify access is granted")

print("\n" + "=" * 80)
