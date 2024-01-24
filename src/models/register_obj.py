from pydantic import BaseModel

class register_obj(BaseModel):
    username : str
    password : str
    confirm : str