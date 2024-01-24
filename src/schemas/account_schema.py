import sys
sys.path.append("./src/models/")
sys.path.append("./src/routers/utils")
from account import account
from hash_password_util import hash_password
import pymongo
import bcrypt
from bson import ObjectId

class account_schema:
    def __init__(self):
        self.hash_util = hash_password()
        self.Session = pymongo.MongoClient("mongodb://localhost:27017/")
        self.database = self.Session["JWT_authen"]
        self.account_col = self.database["accounts"]
        if len(list(self.account_col.find())) == 0:
            self.account_col.insert_one({
                "username" : "admin",
                "password" : self.hash_util.DoHashPassword("admin")

            })

        
    def get_account_list(self):
        db = self.account_col.find()
        list = []
        for i in db:
            _id = str(i["_id"])
            username = i['username']
            password = i['password']
            respond_account = { 
                                "_id" : _id,
                                "username" : username
                                }
            
            list.append(respond_account)

        return respond_account
    
    def add_account(self, new_account : account):
        try:
            if (new_account.username.replace(" ", "").lower() == "" or
                new_account.password.replace(" ", "").lower() == ""):
                raise ValueError('username or password must not be null')
             
            if  self.account_col.find_one({"username" : new_account.username}) is not None:
                raise ValueError('username existed')
            
            self.account_col.insert_one({
                "username" : new_account.username.replace(" ", "").lower(),
                "password" : self.hash_util.DoHashPassword(new_account.password.replace(" ", "").lower())

            })


        except ValueError as e:
            raise ValueError('error at add_account:' , e)

        

    
    def check_login(self, login_account : account):
        db = self.account_col.find_one({"username" : login_account.username})
        if db is None:
            return None
        
        if bcrypt.checkpw(bytes(login_account.password,'utf-8'), db['password']) is True:
            return str(db['_id'])
        else:
            return None
        
    def find_by_id(self, id):
        db = self.account_col.find_one({"_id" : ObjectId(id)})
        if db is not None:
            _id = str(db['_id'])
            username = db['username']
            return {"_id" : _id, "username" : username}
        else:
            return None
        

    def register_account(self, username : str, password : str , confirm : str):
        try:
            if (username.replace(" ", "").lower() == "" or
                password.replace(" ", "").lower() == ""):
                raise ValueError('username or password must not be null')
             
            if  self.account_col.find_one({"username" : username}) is not None:
                raise ValueError('username existed')
            
            if password.replace(" ", "").lower() != confirm.replace(" ", "").lower():
                raise ValueError(' confirm password is different to password')
            
            self.account_col.insert_one({
                "username" : username.replace(" ", "").lower(),
                "password" : self.hash_util.DoHashPassword(password.replace(" ", "").lower())

            })


        except ValueError as e:
            raise ValueError('error at add_account:', e)
    

        

