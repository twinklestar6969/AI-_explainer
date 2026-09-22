#!/usr/bin/env python3
"""
Diagnostic script to check Bedrock authorization and GPT-5.6 Luna connectivity.
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
print("BEDROCK AUTHORIZATION DIAGNOSTIC")
print("=" * 80)

# Get AWS identity
print("\n1. AWS CALLER IDENTITY")
print("-" * 80)
sts_client = boto3.client("sts")
try:
    identity = sts_client.get_caller_identity()
    print(f"   Account ID: {identity['Account']}")
    print(f"   ARN: {identity['Arn']}")
    print(f"   User ID: {identity['UserId']}")
except Exception as e:
    print(f"   ERROR: {e}")

# Check environment configuration
print("\n2. BEDROCK CONFIGURATION")
print("-" * 80)
aws_region = os.getenv("AWS_REGION", "us-east-1")
bedrock_model_id = os.getenv("BEDROCK_MODEL_ID")
print(f"   AWS Region: {aws_region}")
print(f"   Bedrock Model ID: {bedrock_model_id}")

# Check Bedrock foundation model availability
print("\n3. BEDROCK FOUNDATION MODEL AVAILABILITY")
print("-" * 80)
bedrock_client = boto3.client("bedrock", region_name=aws_region)
try:
    # Get the list of foundation models
    models = bedrock_client.list_foundation_models()
    print(f"   Total foundation models available: {len(models['modelSummaries'])}")
    
    # Find GPT-5.6 Luna
    for model in models['modelSummaries']:
        if 'gpt-5.6-luna' in model.get('modelId', '').lower():
            print(f"\n   Found GPT-5.6 Luna:")
            print(json.dumps(model, indent=4, default=str))
            
except Exception as e:
    print(f"   ERROR: {e}")

# Check IAM permissions for bedrock:InvokeModel
print("\n4. IAM PERMISSIONS CHECK")
print("-" * 80)
iam_client = boto3.client("iam")
try:
    user_name = identity['Arn'].split('/')[-1]
    print(f"   Checking permissions for user: {user_name}")
    
    # Get inline policies
    inline_policies = iam_client.list_user_policies(UserName=user_name)
    print(f"   Inline policies: {len(inline_policies['PolicyNames'])}")
    for policy_name in inline_policies['PolicyNames']:
        policy = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
        print(f"\n   Policy: {policy_name}")
        print(json.dumps(policy['UserPolicy'], indent=4, default=str))
    
    # Get attached policies
    attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
    print(f"\n   Attached policies: {len(attached_policies['AttachedPolicies'])}")
    for policy in attached_policies['AttachedPolicies']:
        print(f"      - {policy['PolicyName']}")
except Exception as e:
    print(f"   ERROR: {e}")

# Try to invoke Bedrock with GPT-5.6 Luna
print("\n5. BEDROCK INVOKE TEST (OpenAI Responses API)")
print("-" * 80)
try:
    bedrock_runtime = boto3.client("bedrock-runtime", region_name=aws_region)
    
    # Use OpenAI Responses API format (invoke_model, not converse)
    request_body = {
        "messages": [
            {
                "role": "user",
                "content": "Hello, are you working?"
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
    print("   ✅ SUCCESS: Bedrock invocation successful!")
    print(f"   Response: {result_text[:100]}...")
except Exception as e:
    error_str = str(e)
    print(f"   ❌ ERROR: {error_str}")
    if "AccessDenied" in error_str or "not authorized" in error_str.lower():
        print("\n   ⚠️  AUTHORIZATION ISSUE DETECTED")
        print("   This indicates insufficient IAM permissions for bedrock:InvokeModel")
        print("   Please verify your IAM policy includes: bedrock:InvokeModel")
    elif "ValidationException" in error_str or "Operation not allowed" in error_str:
        print("\n   ⚠️  BEDROCK MODEL ACCESS ISSUE DETECTED")
        print("   This indicates GPT-5.6 Luna access is not enabled in your account.")
        print("   You must:")
        print("      1. Go to AWS Console -> Amazon Bedrock -> Model Access")
        print("      2. Search for: GPT-5.6 Luna")
        print("      3. Verify the model shows 'Access Granted'")
        print("      4. If not, click to view details and accept any required agreements")
        print("      5. Rerun the scanner")
    elif "ResourceNotFoundException" in error_str:
        print("\n   ⚠️  MODEL NOT FOUND")
        print("   GPT-5.6 Luna may not be available in region: " + aws_region)
        print("   Try a different region or verify model ID is correct")

print("\n" + "=" * 80)
