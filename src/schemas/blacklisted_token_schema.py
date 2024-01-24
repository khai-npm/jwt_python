import sys
from fastapi import HTTPException
sys.path.append("./src/models/")
sys.path.append("./src/routers/utils")
import pymongo

from blacklisted_token import bl_token

class blacklisted_token():
    def __init__(self):
        self.Session = pymongo.MongoClient("mongodb://localhost:27017/")
        self.database = self.Session["JWT_authen"]
        self.token_col = self.database["blacklisted_tokens"]
        if len(list(self.token_col.find())) == 0:
            self.token_col.insert_one({
                "token" : "*"
                })
            
    def add_token_to_blacklist(self, token):
        try:
            self.token_col.insert_one({
                "token" : str(token)
                })
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    def is_token_blacklisted(self, token):
        db = self.token_col.find_one({"token" : str(token)})
        if db is None:
            return False
        
        else: 
            return True

