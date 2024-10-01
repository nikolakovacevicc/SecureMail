import datetime


class Message:
    def __init__(self):
        self.data = None
        self.timestamp1 = None
        self.filename = None

        self.message_digest = None
        self.sender_key_id = None
        self.timestamp2 = None
        self.receiver_key_id = None
        self.session_key = None

    def set_data(self, data):
        self.data = data
        self.timestamp1 = datetime.datetime.now().timestamp()

    def set_filename(self, filename):
        self.filename = filename

    def set_message_digest(self, message_digest):
        self.message_digest = message_digest
        self.timestamp2 = datetime.datetime.now().timestamp()

    def set_sender_key_id(self, sender_key_id):
        self.sender_key_id = sender_key_id

    def set_receiver_key_id(self, receiver_key_id):
        self.receiver_key_id = receiver_key_id

    def set_session_key(self, session_key):
        self.session_key = session_key

    def save_message_on_destination(self, filename_path):
        with open(filename_path, 'w') as file:
            file.write(str(self))

    def get_message(self):
        return self.filename + self.timestamp1 + self.data

    def get_message_and_signature(self):
        return self.filename + self.timestamp1 + self.data + self.timestamp2 + self.sender_key_id + self.message_digest

    def get_whole_message(self):
        return self.filename + self.timestamp1 + self.data + self.timestamp2 + self.sender_key_id + self.message_digest + self.receiver_key_id + self.session_key

    def __str__(self):
        return f"Message:\nData: {self.data}\nTimestamp1: {self.timestamp1}\nFilename: {self.filename}\nMessage Digest: {self.message_digest}\nSender Key ID: {self.sender_key_id}\nTimestamp2: {self.timestamp2}\nSession Key: {self.session_key}\nReceiver Key ID: {self.receiver_key_id}"
