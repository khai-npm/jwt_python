import bcrypt

class hash_password:

    salt: bytes
    def __init__(self):
        # Adding the salt to password
        self.salt =bcrypt.gensalt()

    def DoHashPassword(self, RawPass):
        tmpPwd = bytes(RawPass,'utf-8')
        
        
        # Hashing the password
        hashed = bcrypt.hashpw(tmpPwd, self.salt)

        return hashed