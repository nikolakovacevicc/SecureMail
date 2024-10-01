import datetime
import pickle


class PublicKeyRing:
    # key: timestamp, keyID, Public key, name, User ID - email
    # nzm da li cemo dodavati owner trust itd
    def __init__(self, keys=None):
        if keys is None:
            keys = []
        self.keys = keys

    def add_key(self, key_id, public_key, name, email):
        timestamp = datetime.datetime.now().timestamp()
        key = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "Public key": public_key,
            "Name": name,
            "UserID": email
        }
        self.keys.append(key)

    def find_key_keyid(self, key_id):
        for key in self.keys:
            if key["KeyID"] == key_id:
                return key
        return None

    def find_keys_userid(self, email):
        keys = []
        for key in self.keys:
            if key["UserID"] == email:
                keys.append(key)
        return keys

    def remove_key_keyid(self, key_id):
        self.keys = [k for k in self.keys if k['KeyID'] != key_id]

    def remove_key_userid(self, email):
        self.keys = [k for k in self.keys if k['UserID'] != email]

    # def __str__(self):
    #     key_info = ""
    #     for i, key in enumerate(self.keys, start=1):
    #         # key_info += f"Index {i}:\n"
    #         key_info += f"Timestamp: {datetime.datetime.fromtimestamp(key['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
    #         key_info += f"Key ID: {key['KeyID']}\n"
    #         key_info += f"Public key: {key['Public key'].save_pkcs1().decode()}\n"
    #         key_info += f"Name: {key['Name']}\n"
    #         key_info += f"Email: {key['UserID']}\n"
    #         key_info += "\n"
    #     return key_info

    def get_key_values(self):
        values = []
        for key in self.keys:
            timestamp = datetime.datetime.fromtimestamp(key['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            key_id = key['KeyID']
            public_key = key['Public key'].save_pkcs1().decode()
            name = key['Name']
            email = key['UserID']
            values.append((timestamp, key_id, public_key, name, email))
        return values

    def get_key_values_by_keyid(self, keyId):
        values = None
        for key in self.keys:
            key_id = key['KeyID']
            if key_id == keyId:
                timestamp = datetime.datetime.fromtimestamp(key['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                public_key = key['Public key'].save_pkcs1().decode()
                name = key['Name']
                email = key['UserID']
                values = (timestamp, key_id, public_key, name, email)
                break
        return values

    def save_to_file(self, username):
        with open(f"public_key_ring_{username}.pkl", "wb") as f:
            pickle.dump(self.keys, f)

    def load_from_file(self, file_path):
        with open(file_path, "rb") as f:
            self.keys = pickle.load(f)
        return self
