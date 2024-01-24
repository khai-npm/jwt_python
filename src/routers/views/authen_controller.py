import sys
sys.path.append("./src/schemas")
sys.path.append("./src/models")
sys.path.append("./src/routers/views")
from security import validate_token

from security import generate_token, validate_token, reusable_oauth2
from blacklisted_token_schema import blacklisted_token

from account_schema import account_schema
from account import account
from register_obj import register_obj
from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()


@app.post("/api/register")
async def register(new_account : register_obj):
    try:
        db = account_schema()

        db.register_account(username= new_account.username, password= new_account.password, confirm=new_account.confirm)
        return 'success'
    except ValueError as e:
        return HTTPException(status_code=500, detail=str(e))

@app.post("/api/login")
async def check_login(login_account : account):
    db = account_schema()
    if db.check_login(login_account) is not None:
        return generate_token(db.check_login(login_account))
    else: return HTTPException(status_code=404, detail="User not found")

@app.get("/api/user/me", dependencies=[Depends(validate_token)])
async def get_my_info(current_user: str = Depends(validate_token)):
    db = account_schema()
    acc = db.find_by_id(str(current_user))
    if acc is not None:
        return acc
    else:
        return HTTPException(status_code=500, detail="not found")
    

@app.get("/api/user/lists", dependencies=[Depends(validate_token)] )
async def get_list():
    db = account_schema()
    return db.get_account_list()

@app.post("/api/user/add", dependencies=[Depends(validate_token)] )
async def add_account(new_account : account):
    try:
        db = account_schema()
        db.add_account(new_account)
        return 'success'
    
    except ValueError as e:
        return HTTPException(status_code=500, detail=e)
    
@app.get("/api/logout", dependencies=[Depends(validate_token)])
async def logout(current_user  = Depends(reusable_oauth2)):
        db = blacklisted_token()
        db.add_token_to_blacklist(str(current_user.credentials))
        return 'success'



    


