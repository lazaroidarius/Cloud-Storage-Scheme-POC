import socket
import os
import hashlib
import time
import pickle
from Client import ClientAuthenticatorModule
from Client import ClientCryptoModule

PORT = 5050
ADDRESS = '127.0.0.1'


class ClientNetworkInterface:

    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logged_in = 0
        self.logged_in_as = ''
        self.r = None
        self.a = None
        self.n = None
        #modify later
        self.connect()
        self.viewed_var = 0
        self.modified_var = 0

    def start(self):
        #self.connect()
        while True:
            command_input = input("input message=")
            self.process_command_and_send(command_input)
            if self.process_received_message(self.receive_message()) == 'disconnect':
                self.disconnect()
                break

    def send_message(self, message):
        if isinstance(message, bytes):
            self.client.sendall(message)
        else:
            self.client.sendall(bytes(message, 'utf-8'))

    def process_command_and_send(self, command_input):
        if self.logged_in == 1 and command_input == "viewfiles":
            self.send_message('view_stored_files')
        elif self.logged_in == 1 and command_input == "view_shared_user_files":
            self.send_message("view_shared_user_files")
        elif self.logged_in == 1 and command_input.split("|")[0] == "get_cocks_params":
            self.send_message('get_cocks_params')
            self.get_cocks_params(command_input.split("|")[1])
        elif self.logged_in == 1 and command_input.split("|")[0] == "send_file":
            self.send_message('sendingfile')
            self.send_file(command_input.split("|")[1])
        elif self.logged_in == 0 and command_input.split("|")[0] == "register":
            self.send_message('register')
            self.register(command_input.split("|")[1], command_input.split("|")[2])
        elif self.logged_in == 0 and command_input.split("|")[0] == "login":
            self.send_message('login')
            self.login(command_input.split("|")[1], command_input.split("|")[2])
        elif self.logged_in == 1 and command_input.split("|")[0] == "delete_file":
            self.send_message('delete_file')
            self.delete_file(command_input.split("|")[1])
        elif self.logged_in == 1 and command_input.split("|")[0] == "download_file":
            self.send_message('download_file')
            self.download_stored_file(command_input.split("|")[1], command_input.split("|")[2], 1)
        elif self.logged_in == 1 and command_input.split("|")[0] == "logout":
            self.send_message('logout')
            self.logout()
        elif self.logged_in == 1 and command_input.split("|")[0] == "view_file_access_list":
            self.send_message("view_file_access_list")
            self.receive_message()
            self.send_message(command_input.split("|")[1])
        elif self.logged_in == 1 and command_input.split("|")[0] == "update_file_access_list":
            self.send_message("update_file_access_list")
            self.update_file_access_list(command_input.split("|")[1], command_input.split("|")[2], command_input)
        elif self.logged_in == 1 and command_input.split("|")[0] == "download_shared_file":
            self.send_message("download_shared_file")
            self.download_shared_file(command_input.split("|")[1], command_input.split("|")[2], command_input.split("|")[3])
        elif self.logged_in == 1 and command_input.split("|")[0] == "upload_shared_file":
            self.send_message("upload_shared_file")
            self.send_shared_file(command_input.split("|")[1], command_input.split("|")[2])
        elif command_input == "disconnect":
            self.send_message('disconnect')
        else:
            self.send_message("nothing")

    def send_shared_file(self, owner, filepath,):

        # send owner|filename
        self.receive_message()
        file = filepath.split("\\")[-1]
        request = owner + "|" +file
        self.send_message(bytes(request,"utf-8"))

        # check initial response
        response = self.receive_message()
        if response == b"u-1":
            self.send_message(b"ok")
            return -1

        # send ok
        self.send_message(b"ok")
        # getkey
        pickled_list = self.receive_file_bits()
        if pickled_list == b"ek-1":
            self.send_message(b"ok")
            return -1

        # unpickle key
        unpickled_list = pickle.loads(pickled_list)
        aes_key = pickle.loads(unpickled_list[0])
        iv = unpickled_list[1]

        #decrypt key
        decrypted_aes_key = ClientCryptoModule.ClientCryptoModule.decrypt_cocks(self.r, self.a, self.n, aes_key)

        # generate file name and size
        file_name = filepath.split("\\")[-1]
        file_size = os.path.getsize(filepath)
        # read the files contents
        file_descriptor = open(filepath, "rb")
        file_content = file_descriptor.read()

        # encrypt file content
        file_content = ClientCryptoModule.ClientCryptoModule.encrypt_aes_cbc(decrypted_aes_key, iv, file_content)

        # send the file
        self.send_file_parts(file_name, file_size, file_content)
        self.receive_message()

        # send iv
        list_to_send = iv
        list_to_send = pickle.dumps(list_to_send)
        self.send_key_iv(list_to_send)

    def download_shared_file(self, owner, file_name, download_location):
        self.receive_message()
        #send the file name and the owner
        self.send_message(bytes(owner + "|" + file_name, 'utf-8'))

        # receive file metadata(file_name|file_size)
        file_size, file_name, received_file, received_hash = self.receive_file()

        if file_size != -1:

            pickled_list = self.receive_file_bits()

            self.receive_message()
            # unpack key,iv and decrypt file
            unpickled_list = pickle.loads(pickled_list)
            aes_key = pickle.loads(unpickled_list[0])

            decrypted_aes_key = ClientCryptoModule.ClientCryptoModule.decrypt_cocks(self.r, self.a, self.n, aes_key)
            decrypted_file = ClientCryptoModule.ClientCryptoModule.decrypt_aes_cbc(decrypted_aes_key, received_file,unpickled_list[1])

            # check digest
            hash_result = self.build_hash(file_name, file_size, received_file)
            if hash_result.digest() != received_hash:
                self.send_message("hash-1")
                return -1
            self.send_message("hash1")
            # send file to storage
            self.save_file(file_name, decrypted_file, download_location)
        else:
            return -1

    def get_cocks_params(self, password):
        #get ok
        self.receive_message()

        #send a login
        # do the login 4 times
        self.fiat_shamir_identification(self.logged_in_as, password)
        self.fiat_shamir_identification(self.logged_in_as, password)
        self.fiat_shamir_identification(self.logged_in_as, password)
        self.fiat_shamir_identification(self.logged_in_as, password)

        received_message = self.receive_message()
        self.send_message(b"ok")
        if received_message == b"login1":
            pickled_list = self.receive_message()
            self.send_message(b"ok")
            unpickled_list = pickle.loads(pickled_list)
            self.save_r_a_n(unpickled_list[0], unpickled_list[1], unpickled_list[2], self.logged_in_as, password)
            self.r, self.a, self.n = self.load_r_a_n(self.logged_in_as, password)
            if self.r == -1:
                print("Local cocks parameters have been compromised. Attempt to reload them")
                return -1
        else:
            return -1

    def update_file_access_list(self, file, operation, command_input):
        # receive ok
        self.receive_message()

        user_list = self.__generate_user_list(command_input)
        # file|add/delete|user1|user2|user3
        request = file + "|" + operation + "|" + user_list
        self.send_message(request)

    def __generate_user_list(self, command_input):
        result = ''
        split_command = command_input.split("|")
        for i in range(3, len(split_command)):
            result += split_command[i] + "|"

        return result[:-1]

    def register(self, username, password):
        if len(password) > 31:
            return -1

        auth_module = ClientAuthenticatorModule.ClientAuthenticatorModule()
        v, n = auth_module.generate_setup_values(password)

        # message structure: username|n|v1|v2|v3....
        register_message = username + "|" + str(n)

        for i in range(0,len(v)):
            register_message += "|" + str(v[i])

        self.send_message(register_message)

        response = self.receive_message()
        if response == b'register1':
            pickled_list = self.receive_message()
            self.send_message(b"ok")
            unpickled_list = pickle.loads(pickled_list)
            self.save_r_a_n(unpickled_list[0], unpickled_list[1], unpickled_list[2], username, password)
        else:
            self.send_message(b"register-1")

    def save_r_a_n(self, r, a, n, username, password, location=r"C:\Users\lazar\Desktop\Scheme\ClientLocalData"):
        #save in a file,encrypt with password
        file_path = location + "\\cocks_params\\" + username
        saved_list = [r, a, n]
        aes_key = ClientCryptoModule.ClientCryptoModule.pad_key(bytes(password, "utf-8"))
        pickle_string = pickle.dumps(saved_list)
        encrypted_content, tag, nonce = ClientCryptoModule.ClientCryptoModule.encrypt_aes_eax(aes_key, pickle_string)

        self.write_to_file(file_path, "_cocks_params", 'wb', encrypted_content)
        self.write_to_file(file_path, "_tag", 'wb', tag)
        self.write_to_file(file_path, "_nonce", 'wb', nonce)

    def write_to_file(self, file_path, extension, mode, content):
        file_descriptor = open(file_path + extension, mode)
        file_descriptor.write(content)
        file_descriptor.close()

    def load_r_a_n(self, username, password, location=r"C:\Users\lazar\Desktop\Scheme\ClientLocalData"):
        file_path = location + "\\cocks_params\\" + username
        aes_key = ClientCryptoModule.ClientCryptoModule.pad_key(bytes(password,"utf-8"))

        encrypted_content = self.load_from_file(file_path, "_cocks_params", 'rb')
        tag               = self.load_from_file(file_path, "_tag", 'rb')
        nonce             = self.load_from_file(file_path, "_nonce", 'rb')

        try:
            saved_list = ClientCryptoModule.ClientCryptoModule.decrypt_aes_eax(aes_key, tag, nonce, encrypted_content)
            saved_list = pickle.loads(saved_list)
            return saved_list[0], saved_list[1], saved_list[2]
        except ValueError:
            return -1, -1, -1

    def load_from_file(self, file_path, extension, mode):
        file_descriptor = open(file_path + extension, mode)
        content = file_descriptor.read()
        file_descriptor.close()
        return content

    def change_password(self, password):
        pass

    def delete_file(self, file_name, location=r"C:\Users\lazar\Desktop\Scheme\ClientLocalData"):
        #receive ok
        self.receive_message()
        self.send_message(file_name)

        response = self.receive_message()
        # delete local data too
        if response == b"del-1":
            self.send_message(b"ok")
        else:
            self.send_message(b"ok")
            file_path = location + "\\" + self.logged_in_as + "_" + file_name + "_ciphertext_hash"
            os.remove(file_path)
            file_path = location + "\\" + self.logged_in_as + "_" + file_name + "_plaintext_hash"
            os.remove(file_path)

    def receive_file(self):
        file_metadata = self.receive_message()
        if file_metadata.decode() == "file-1":
            self.send_message("ok")
            return -1, -1, -1, -1
        else:
            file_name = file_metadata.decode().split("|")[0]
            file_size = file_metadata.decode().split("|")[1]
            self.send_message("ok")
            # receive hash
            received_hash = self.receive_message()
            self.send_message("ok")

            # receive file
            # receive file the file 4096 bytes at a time
            received_message = self.receive_file_bits()

            return file_size, file_name, received_message, received_hash

    def receive_file_bits(self):
        received_file = b''
        received_message = self.receive_message()
        self.send_message("ok")

        while received_message != b'stop':
            received_file = received_file + received_message
            received_message = self.receive_message()
            self.send_message("ok")

        return received_file

    def download_stored_file(self, file_name, download_location, owned):
        #decrypt,check hashes/update hashes?,store

        self.receive_message()
        #send the file name the user wishes to download
        self.send_message(bytes(file_name, 'utf-8'))
        #receive file metadata(file_name|file_size)
        file_size, file_name, received_file, received_hash = self.receive_file()

        if file_size != -1:
            # get key
            pickled_list = self.receive_file_bits()
            if pickled_list == b"ek-1":
                self.send_message(b"ok")
                return -1

            self.receive_message()
            #unpack key,iv and decrypt file
            unpickled_list = pickle.loads(pickled_list)
            aes_key = pickle.loads(unpickled_list[0])

            decrypted_aes_key = ClientCryptoModule.ClientCryptoModule.decrypt_cocks(self.r, self.a, self.n, aes_key)
            decrypted_file = ClientCryptoModule.ClientCryptoModule.decrypt_aes_cbc(decrypted_aes_key, received_file, unpickled_list[1])

            #check digest
            hash_result = self.build_hash(file_name, file_size, received_file)
            if hash_result.digest() != received_hash:
                self.send_message("hash-1")
                return -1
            self.send_message("hash1")
            # send file to storage
            self.save_file(file_name, decrypted_file, download_location)
            if self.check_file_status(file_name, received_file, "view") == -1:
                print("File has been viewed")
                self.viewed_var = 1
            if self.check_file_status(file_name, decrypted_file, "modify") == -1:
                print("File has been modified")
                self.modified_var = 1

    # verifies whether file was modified in any way since last download/ operation = view/modify
    def check_file_status(self, file_name, file_content, operation, location=r"C:\Users\lazar\Desktop\Scheme\ClientLocalData"):
        # load plaintext hash
        if operation == "modify":
            file_descriptor = open(location + "\\" + self.logged_in_as + "_" + file_name + "_plaintext_hash", 'rb')
        elif operation == "view":
            file_descriptor = open(location + "\\" + self.logged_in_as + "_" + file_name + "_ciphertext_hash", 'rb')
        else:
            return 0
        old_hash = file_descriptor.read()
        new_hash = self.build_simple_hash(file_content)
        if old_hash == new_hash:
            return 1
        else:
            return -1

    def save_file(self, file_name, file_content, download_location):
        with open(download_location + "\\"+file_name, 'wb+') as file_descriptor:
            file_descriptor.write(file_content)
        file_descriptor.close()
        return 0

    def fiat_shamir_identification(self, username, password):
        #check_and_send username
        self.send_message(username)
        response = self.receive_message()
        response = response.decode('utf-8')
        if response == '-1':
            return -1, username
        else :
            #receive n
            n = response
            n = int(n)
            auth_module = ClientAuthenticatorModule.ClientAuthenticatorModule()
            s = auth_module.generate_s(password, n)
            #pick random r calculate and x
            x, r = auth_module.step_1(n)
            self.send_message(str(x))
            #receive a
            a_raw = self.receive_message()
            a_string = a_raw.decode('utf-8')
            a_string = a_string.split("|")
            a = []
            for i in range(0, len(a_string)):
                a.append(int(a_string[i]))

            y = auth_module.step_3(a, r, s, n)
            #send y
            self.send_message(str(y))
            return 0

    def login(self, username, password):
        self.logged_in_as = username
        #receive ok
        self.receive_message()
        #do the login 4 times
        self.fiat_shamir_identification(username, password)
        self.fiat_shamir_identification(username, password)
        self.fiat_shamir_identification(username, password)
        self.fiat_shamir_identification(username, password)

        received_message = self.receive_message()
        self.send_message(b"ok")
        if received_message == b"login1":
            self.r, self.a, self.n = self.load_r_a_n(username, password)
            if self.r == -1:
                print("Local cocks parameters have been compromised. Attempt to reload them")
                return -1

    def logout(self):
        self.logged_in = 0
        self.logged_in_as = ''
        self.r = None
        self.a = None
        self.n = None

    def process_received_message(self, received_message):
        if received_message == b'':
            return 'disconnect'
        elif received_message == b'register-1':
            return "Registering failed. Check credentials"
        elif received_message == b'loggedout1':
            return "Logged out succesfully"
        elif received_message == b'register1':
            return "Registering successful."
        elif received_message == b'file-1':
            return "File does not exist"
        elif received_message == b'login-1':
            self.logged_in_as = ''
            return "Login Failed. Check credentials"
        elif received_message == b'login1':
            self.logged_in = 1
            return "Login successful."
        elif received_message == b'hash-1':
            return "Hash result mismatch, try again"
        elif received_message == b'hash1':
            return "Hash result Ok"
        elif received_message == b'del-1':
            return "Failed to delete file. Try again later."
        elif received_message == b'del1':
            return "Deletion successful "
        elif received_message == b'ek-1':
            return "Error at key retrieval"
        elif received_message == b'eu-1':
            return "File does not exist or the user does not own the file"
        elif received_message == b'eu1':
            return "Access list updated successfully"
        elif received_message == b'user-1':
            return "User does not exist"
        elif received_message == b'cocks1':
            return "Cocks params redownloaded successfully"
        elif received_message == b'u-1':
            return "Upload Failed"
        elif received_message == b'pass-1':
            return "Wrong password."
        elif received_message.decode('utf-8').split("|")[0] == "files_stored":
            return self.process_and_print_files(received_message.decode('utf-8'))
        elif received_message.decode('utf-8').split("|")[0] == "files_acess_list":
            return self.process_and_print_access_list(received_message.decode('utf-8'))
        elif received_message.decode('utf-8').split("|")[0] == "shared_user_files":
            return self.process_and_print_shared_user_files(received_message.decode('utf-8'))
        else:
            return "Error"

    def process_and_print_shared_user_files(self, message):
        result = list()
        #print("Files shared with you:")
        message = message.split("|")
        if len(message) >= 3:
            for i in range(1, len(message), 2):
                result.append("Owner:"+message[i] + "|" + "File:"+message[i+1])
        return result

    def process_and_print_access_list(self, message):
        result = ''
        file_list = message.split("|")
        # print("File:"+file_list[1])
        # print("Access list:")
        for i in range(2, len(file_list)):
            result = result + file_list[i] + "\n"
        return result

    def process_and_print_files(self, message):
        result = list()
        file_list = message.split("|")
        for i in range(1, len(file_list)):
            result.append(file_list[i])
        return result

    def connect(self):
        self.client.connect((ADDRESS, PORT))

    def receive_message(self):
        return self.client.recv(4096)

    def disconnect(self):
        try:
            self.client.shutdown(socket.SHUT_RDWR)
            self.client.close()
            print("Connection terminated successfully")
            return 0
        except:
            print("Error occurred during connection termination")
            return -1

    def build_hash(self, file_name, file_size, file_content):
        hash = hashlib.sha3_512()
        hash.update(bytes(file_name, 'utf-8'))
        hash.update(bytes(str(file_size), 'utf-8'))
        hash.update(file_content)

        return hash

    def build_simple_hash(self, content):
        hash = hashlib.sha3_256()
        hash.update(content)
        return hash.digest()

    def send_and_split_file(self, file_content):
        i = 1
        while i * 4096 < len(file_content) + 4096:
            if i * 4096 > len(file_content):
                self.send_message(file_content[4096 * (i - 1):len(file_content)])
                self.receive_message()
                break
            else:
                self.send_message(file_content[4096 * (i - 1):(4096 * i)])
                self.receive_message()
                i = i + 1

    def send_file(self, filepath, location=r"C:\Users\lazar\Desktop\Scheme\ClientLocalData"):
        #sendok
        self.receive_message()
        # generate file name and size
        file_name = filepath.split("\\")[-1]
        file_size = os.path.getsize(filepath)
        # read the files contents
        file_descriptor = open(filepath, "rb")
        file_content = file_descriptor.read()

        # encrypt file content
        plaintext_hash = self.build_simple_hash(file_content)
        aes_key, iv = ClientCryptoModule.ClientCryptoModule.generate_aes_key_and_iv()
        file_content = ClientCryptoModule.ClientCryptoModule.encrypt_aes_cbc(aes_key, iv, file_content)
        ciphertext_hash = self.build_simple_hash(file_content)
        # save hashes for later
        self.write_to_file(location, "\\" + self.logged_in_as + "_" + file_name + "_plaintext_hash", 'wb', plaintext_hash)
        self.write_to_file(location, "\\" + self.logged_in_as + "_" + file_name + "_ciphertext_hash", 'wb', ciphertext_hash)
        #send the file
        self.send_file_parts(file_name, file_size, file_content)
        self.receive_message()
        #send the key and iv
        list_to_send = [aes_key, iv]
        list_to_send = pickle.dumps(list_to_send)
        self.send_key_iv(list_to_send)

    def send_file_parts(self, file_name, file_size, file_content):
        hash_result = self.build_hash(file_name, file_size, file_content)
        # send the file name, size and digest
        self.send_message(file_name+"|"+str(file_size))
        self.receive_message()
        self.send_message(hash_result.digest())
        self.receive_message()

        # if the file is 4096 bytes or less, send the contents in one message
        if len(file_content) <= 4096:
            self.send_message(file_content)
            self.receive_message()
            # this message signals the server that the file is done sending
            self.send_message("finished_sending_file")
        # otherwise split and send multiple 4096 bytes messages
        else:
            self.send_and_split_file(file_content)
            time.sleep(0.1)
            # this message signals the server that the file is done sending
            self.send_message("finished_sending_file")

    def send_key_iv(self, aes_key):
        self.send_message(aes_key)



#obj = ClientNetworkInterface()
#obj.start()

#encrypt file
#if user owns the file save iv and hash locally, trigger warning if they are different
#implement retireve key
#implement view shared files
#implement update access file list
#implement view user shared files sth
#regenerate r,a,n