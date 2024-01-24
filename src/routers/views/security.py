import sys
sys.path.append(".src/env")
sys.path.append("./src/schemas")
import os
from blacklisted_token_schema import blacklisted_token
from dotenv import load_dotenv

import jwt
from datetime import datetime, timedelta
from typing import Union, Any
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from pydantic import ValidationError


load_dotenv("./src/env/")
SECURITY_ALGORITHM = 'HS256' # os.getenv('SECURITY_ALGORITHM')
SECRET_KEY = 'thisisnotakey123456'  #os.getenv('SECRET_KEY')


def generate_token(userid: Union[str, Any]) -> str:
    expire = datetime.utcnow() + timedelta(
        seconds=60 * 30
    )
    to_encode = {
        "exp": expire, "id": userid
    }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=SECURITY_ALGORITHM)
    return encoded_jwt

reusable_oauth2 = HTTPBearer(
    scheme_name='Authorization' 
)


def validate_token(http_authorization_credentials=Depends(reusable_oauth2)) -> str:
    #ttp_authorization_credentials là code của HTTPBearer sinh ra

    # giải mã jwt code để xác định username

    try:
        db = blacklisted_token()
        if db.is_token_blacklisted(http_authorization_credentials.credentials) is True:
            raise HTTPException(status_code=404, detail="token expired")
           
        # nếu thời gian hiện tại - thời gian tạo token vượt thời gian sống -> token chết
        payload = jwt.decode(http_authorization_credentials.credentials, SECRET_KEY, algorithms=[SECURITY_ALGORITHM])
        if int((payload.get('exp'))) < int(datetime.utcnow().timestamp()):
            raise HTTPException(status_code=403, detail="Token expired")
        return payload.get('id')
    except(jwt.PyJWTError, ValidationError):
        raise HTTPException(
            status_code=403,
            detail=f"Could not validate credentials"
        )
'''
def destroty_token(http_authorization_credentials=Depends(reusable_oauth2)) -> str:
    try:
        payload = jwt.decode(http_authorization_credentials.credentials, SECRET_KEY, algorithms=[SECURITY_ALGORITHM])
        expire = datetime.utcnow()
        to_encode = {
        "exp": expire, "id": payload.get('id')
        }
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=SECURITY_ALGORITHM)
        return encoded_jwt

    except(jwt.PyJWTError, ValidationError):
        raise HTTPException(
            status_code=403,
            detail=f"Could not validate credentials",
        )
'''