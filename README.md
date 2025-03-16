# AWS VPC API - FastAPI Secure Implementation

## Overview
This project provides a FastAPI-based API for creating AWS VPCs and subnets securely using authentication and authorization.

## Features
- Secure authentication using JWT (via `python-jose`)
- Password hashing with bcrypt
- AWS VPC creation and listing using `boto3`
- Secure API endpoints with token-based authentication
- No hardcoded secrets (use environment variables or AWS Secrets Manager)

## Prerequisites
1. Python 3.8+
2. AWS credentials configured (`~/.aws/credentials` or IAM roles)
3. Install dependencies:
   ```sh
   pip install fastapi uvicorn boto3 python-jose[cryptography] passlib[bcrypt]
   ```

## Installation & Setup
1. Clone the repository:
   ```sh
   git clone <repo_url>
   cd aws-vpc-api
   ```
2. Create a virtual environment:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Run the API:
   ```sh
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

## API Endpoints
### 1. Authentication
#### Request:
   ```sh
   POST /token
   Content-Type: application/json
   Body: {"username": "admin", "password": "password"}
   ```
#### Response:
   ```json
   {"access_token": "<JWT_TOKEN>", "token_type": "bearer"}
   ```

### 2. Create a VPC
#### Request:
   ```sh
   POST /create_vpc
   Authorization: Bearer <JWT_TOKEN>
   Body: {
      "cidr_block": "10.0.0.0/16",
      "subnets": ["10.0.1.0/24", "10.0.2.0/24"]
   }
   ```
#### Response:
   ```json
   {"VPC_ID": "vpc-xxxxxx", "Subnets": ["subnet-xxxxx", "subnet-yyyyy"]}
   ```

### 3. List VPCs
#### Request:
   ```sh
   GET /vpcs
   Authorization: Bearer <JWT_TOKEN>
   ```
#### Response:
   ```json
   {"VPCs": [...]}
   ```

## Security Considerations
- Use AWS IAM roles for EC2 instances instead of static credentials
- Store secrets in AWS Secrets Manager or environment variables
- Implement role-based access control for different API permissions

## Deployment
To deploy on AWS Lambda with API Gateway, use `serverless` or AWS CDK.

---
This API ensures secure and efficient management of AWS VPCs using FastAPI and follows best security practices.


