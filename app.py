from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
import boto3
import uuid
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext

# Secret key & Algorithm (use AWS Secrets Manager in production)
SECRET_KEY = "your-secret-key"  # Secret key used to sign JWT tokens (should be securely stored)
ALGORITHM = "HS256"  # Algorithm used for JWT encoding and decoding
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Expiration time for access tokens

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to verify if a given password matches the stored hashed password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to hash a given password before storing it
def get_password_hash(password):
    return pwd_context.hash(password)

# Authentication models
class Token(BaseModel):
    access_token: str  # JWT token
    token_type: str  # Token type (usually "bearer")

class TokenData(BaseModel):
    username: str | None = None  # Extracted username from the JWT payload

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Function to create a new JWT token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})  # Setting expiration time
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Function to authenticate user credentials
def authenticate_user(username: str, password: str):
    # Example user store (Replace with a proper database in production)
    fake_users_db = {"admin": get_password_hash("password")}
    if username in fake_users_db and verify_password(password, fake_users_db[username]):
        return username  # Return username if authentication succeeds
    return None  # Return None if authentication fails

# Function to validate JWT token and extract user information
def get_current_user(token: str = Security(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")  # Extract username from token payload
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# AWS Setup
aws_region = "us-east-1"  # AWS region where VPCs will be created
boto3_session = boto3.Session(region_name=aws_region)  # Create a new AWS session
ec2_client = boto3_session.client("ec2")  # Create an EC2 client to manage VPC resources

# API Setup
app = FastAPI()

# Pydantic model to validate VPC creation request
class VPCRequest(BaseModel):
    cidr_block: str  # CIDR block for the VPC
    subnets: List[str]  # List of CIDR blocks for subnets

# Endpoint to authenticate and generate an access token
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token({"sub": user}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint to create a VPC and associated subnets
@app.post("/create_vpc")
def create_vpc(vpc_request: VPCRequest, current_user: str = Depends(get_current_user)):
    try:
        vpc = ec2_client.create_vpc(CidrBlock=vpc_request.cidr_block)  # Create VPC
        vpc_id = vpc['Vpc']['VpcId']  # Extract VPC ID from response
        subnets = []
        
        for subnet_cidr in vpc_request.subnets:
            subnet = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr)  # Create subnets
            subnets.append(subnet['Subnet']['SubnetId'])
        
        return {"VPC_ID": vpc_id, "Subnets": subnets}  # Return created VPC and subnets
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))  # Handle errors

# Endpoint to list all VPCs in the AWS account
@app.get("/vpcs")
def get_vpcs(current_user: str = Depends(get_current_user)):
    vpcs = ec2_client.describe_vpcs()  # Fetch all VPCs
    return {"VPCs": vpcs}  # Return VPC details
