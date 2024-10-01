import datetime
import pickle


class PrivateKeyRing:
    # key: timestamp, keyID, Public key, Encrypted private key, name, User ID - email
    def __init__(self):
        self.keys = []

    def add_key(self, key_id, public_key, encrypted_private_key, name, email):
        timestamp = datetime.datetime.now().timestamp()
        key = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "Public key": public_key,
            "Encrypted private key": encrypted_private_key,
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
    #     for i, key in enumerate(self.keys):
    #         # key_info += f"Index {i}:\n"
    #         key_info += f"Timestamp: {datetime.datetime.fromtimestamp(key['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
    #         key_info += f"Key ID: {key['KeyID']}\n"
    #         key_info += f"Public key: {key['Public key'].save_pkcs1().decode()}\n"
    #         key_info += f"Encrypted private key: {key['Encrypted private key']}\n"
    #         key_info += f"Name: {key['Name']}\n"
    #         key_info += f"UserID: {key['UserID']}\n\n"
    #     return key_info

    def get_key_values(self):
        values = []
        for key in self.keys:
            timestamp = datetime.datetime.fromtimestamp(key['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            key_id = key['KeyID']
            public_key = key['Public key'].save_pkcs1().decode()
            encrypted_private_key = key['Encrypted private key']
            name = key['Name']
            email = key['UserID']
            values.append((timestamp, key_id, public_key, encrypted_private_key, name, email))
        return values

    def save_to_file(self, username):
        with open(f"private_key_ring_{username}.pkl", "wb") as f:
            pickle.dump(self.keys, f)

    def load_from_file(self, file_path):
        with open(file_path, "rb") as f:
            self.keys = pickle.load(f)
        return self
