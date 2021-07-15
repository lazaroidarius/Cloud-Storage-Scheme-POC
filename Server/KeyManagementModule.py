import zmq
import hashlib
import random
import pickle
from cocks.cocks import CocksPKG, Cocks
import os
from tinydb import TinyDB, Query
from tinydb.operations import set
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import gmpy2

class KeyManagementModule:
    def __init__(self):
        context = zmq.Context()
        self.zmq_socket = context.socket(zmq.REP)
        self.zmq_socket.bind("tcp://*:5570")
        self.cocks_pkg = self.load_scheme(location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")

    def start(self):
        while True:
            request = self.zmq_socket.recv()
            print(request.decode())
            split_request = request.decode().split("|")
            if split_request[0] == "register":
                self.__register(split_request[1], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
            elif split_request[0] == "store_key":
                #store_key|username|file
                self.zmq_socket.send(b"ok")
                # recv [key|iv]
                pickled_lits = self.zmq_socket.recv()
                unpickled_list = pickle.loads(pickled_lits)
                self.__store_key(split_request[1], unpickled_list[0], split_request[2], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
                self.__store_iv(split_request[1], unpickled_list[1], split_request[2], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
                # if file doesnt exist already add to db/otherwise don't
                self.__add_file_to_db(split_request[1], split_request[2])
                self.__rebuild_shared_keys(split_request[1], split_request[2], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
                self.zmq_socket.send(b"ok")
            elif split_request[0] == "store_iv_only":
                #store_iv_only|username|file
                self.zmq_socket.send(b"ok")
                # recv iv
                pickled_iv = self.zmq_socket.recv()
                unpickled_list = pickle.loads(pickled_iv)
                self.__store_iv(split_request[1], unpickled_list, split_request[2], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
                # if file doesnt exist already add to db/otherwise don't
                self.zmq_socket.send(b"ok")
            elif split_request[0] == "update_access_list":
                #update_access_list|username|file|delete/|user1|user2
                user_list = self.__process_user_list(split_request)
                if self.__update_file_access_list_db(split_request[1], split_request[2], split_request[3], user_list) == -1:
                    self.zmq_socket.send(b"e-1")
                else:
                    self.__update_file_access_list_keys(split_request[1], split_request[2], split_request[3], user_list, location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
                    self.zmq_socket.send(b"ok")
            elif split_request[0] == "retrieve_key":
                #retreive_key|username|file|owner
                self.__retrieve_key(split_request[1], split_request[2], split_request[3], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
            elif split_request[0] == "view_file_access_list":
                # view_file_access_list|username|file
                result = self.__view_file_access_list(split_request[1], split_request[2])
                self.zmq_socket.send(pickle.dumps(result))
            elif split_request[0] == "view_user_access_list":
                # view_file_access_list|username
                result = self.__view_user_shared_files(split_request[1])
                self.zmq_socket.send(pickle.dumps(result))
            elif split_request[0] == "get_cocks_params":
                #get_cocks_params|username
                self.__generate_and_send_r_a_n(split_request[1])
            elif split_request[0] == "delete_file_keys":
                #delete_file_keys|username|file
                self.__delete_file_keys(split_request[1], split_request[2], location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement")
                self.zmq_socket.send(b"ok")
            elif split_request[0] == "check_if_user_is_on_access_list":
                # user|file|owner
                self.__check_if_user_is_on_access_list(split_request[1], split_request[2], split_request[3])

    def __check_if_user_is_on_access_list(self, user, file, owner):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        result = db.search((Query().SharedWith.test(self.check_if_user_in_shared_list, user)) & (Query().FileName == file) & (Query().Owner == owner))

        if len(result) != 0:
            self.zmq_socket.send(b"1")
        else:
            self.zmq_socket.send(b"-1")


    def __delete_file_keys(self, owner, file, location):
        #delete file from db
        file_path = location + "\\" + owner + "\\" + file
        for current_file in os.listdir(file_path):
            os.remove(file_path+"\\"+current_file)
        self.__delete_file_from_db(owner, file)
        os.rmdir(file_path)

    def __delete_file_from_db(self, owner, file):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        db.remove((Query().FileName == file) & (Query().Owner == owner))
        db.close()

    def __process_user_list(self, split_list):
        user_list = ''
        for i in range(4, len(split_list)):
            user_list += split_list[i] + "|"
        user_list = user_list[:-1]
        return user_list

    def __retrieve_key(self, username, file, owner, location):
        #if user diff than owner do not re-encrypt, otherwise re-encrypt
        #user specifies what file they want using the owner and the filename
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        result = None
        if username == owner:
            result = db.search((Query().FileName == file) & (Query().Owner == owner))
        else:
            result = db.search((Query().SharedWith.test(self.check_if_user_in_shared_list, username)) & (Query().FileName == file) & (Query().Owner == owner))
        if len(result) != 0:
            key_file = ''
            if owner == username:
                key_file = location + "\\" + owner + "\\" + file + "\\" + file + "_key"
            else:
                key_file = location + "\\" + owner + "\\" + file + "\\" + file + "_" + username +"_key"
            file_name, file_size, file_content = self.__get_file_with_FMM(owner, file)
            if file_name == -1 or file_size == -1 or file_content == -1:
                self.zmq_socket.send(b"e-1")
                self.zmq_socket.recv()
            else:
                file_descriptor = open(key_file, 'rb')
                key_content = pickle.load(file_descriptor)
                iv_file = location + "\\" + owner + "\\" + file + "\\" + file + "_iv"
                iv_content = open(iv_file, 'rb').read()

                bandaid = 0

                if owner != username:
                    new_encrypted_file, iv = self.__re_encrypt_file_with_different_iv(key_content,iv_content, file_content, username)
                    self.__store_iv(owner, iv, file, location)
                    if self.__store_file_with_FMM(owner, file_name, file_size, new_encrypted_file) == 1:
                        bandaid = 1

                #iv_content = open(iv_file, 'rb').read()
                key_content = pickle.dumps(key_content)
                file_descriptor.close()

                # send key
                self.zmq_socket.send(key_content)
                # receive ok
                self.zmq_socket.recv()
                # send iv
                self.zmq_socket.send(iv_content)
                #receive ok
                self.zmq_socket.recv()

                if owner != username:
                    if bandaid == 1:
                        self.zmq_socket.send(b"1")
                    else:
                        self.zmq_socket.send(b"-1")
                else:
                    self.zmq_socket.send(b"1")


                    #check if ok,send forwrad
        else:
            self.zmq_socket.send(b"e-1")

    def __re_encrypt_file_with_different_iv(self, key_content, old_iv, file_content, owner):
        iv = get_random_bytes(16)
        aes_key = self.__ibe_decrypt(key_content, owner)
        cipher = AES.new(aes_key, AES.MODE_CBC, old_iv)
        plaintext = unpad(cipher.decrypt(file_content), AES.block_size)
        padded_data = pad(plaintext, AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        return ciphertext, iv

    def __get_file_with_FMM(self, username, file):
        context = zmq.Context()
        zmq_socket = context.socket(zmq.REQ)
        zmq_socket.connect("tcp://localhost:5565")
        request = "retrieve_file|"+username+"|"+file
        #hash?yes.... fix rest
        zmq_socket.send(bytes(request, "utf-8"))

        # receive metadata(file_name|file_size)
        file_metadata = zmq_socket.recv()
        if file_metadata == b'file-1':
            zmq_socket.close()
            return -1, -1, -1
        file_name = file_metadata.decode().split("|")[0]
        file_size = file_metadata.decode().split("|")[1]
        # send ok
        zmq_socket.send(bytes("ok", "utf-8"))
        # receive file content
        file_content = zmq_socket.recv()
        # send ok
        zmq_socket.send(bytes("ok", "utf-8"))
        # receive hash_result
        received_hash = zmq_socket.recv()
        # close socket
        zmq_socket.close()
        hash_result = self.__build_hash(file_name, file_size, file_content)
        zmq_socket.close()
        if self.__verify_hash(received_hash, hash_result) == 0:
            return -1, -1, -1
        else:
            return file_name, file_size, file_content

    def __store_file_with_FMM(self, username, file_name, file_size, file_content):
        context = zmq.Context()
        zmq_socket = context.socket(zmq.REQ)
        #same here finish this
        zmq_socket.connect("tcp://localhost:5565")
        request = "store_file|"+username
        zmq_socket.send(bytes(request, "utf-8"))
        #receive ok
        zmq_socket.recv()
        hash_result = self.__build_hash(file_name, file_size, file_content)
        #send metadata
        file_metadata = file_name+"|"+file_size
        zmq_socket.send(bytes(file_metadata, "utf-8"))
        #receive ok
        zmq_socket.recv()

        #send the file content
        zmq_socket.send(file_content)
        #receive ok
        zmq_socket.recv()

        #send the hash
        zmq_socket.send(hash_result)
        #receive ok
        hash_response = zmq_socket.recv()
        if hash_response.decode() == "Hash1":
            zmq_socket.send(b"hash1")
            zmq_socket.close()
            return 1
        else:
            zmq_socket.send(b"hash-1")
            return -1

    def __add_file_to_db(self, username, file):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        shared_list = ["admin"]
        result = db.search((Query().FileName == file) & (Query().Owner == username))
        if len(result) == 0:
            db.insert({'FileName': file, "Owner": username, "SharedWith": shared_list})
            db.close()
        else:
            db.close()

    #do with list instead of dumb srting
    def __update_file_access_list_db(self, username, file, operation, user_list):
        #operation = add/delete
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        result = db.search((Query().FileName == file) & (Query().Owner == username))
        if len(result) != 0 :
            current_user_list = result[0]['SharedWith']
            user_list = user_list.split("|")
            if len(user_list) != 0:
                for i in range(0, len(user_list)):
                    if operation == "delete":
                        if user_list[i] != "admin":
                            if user_list[i] in current_user_list:
                                current_user_list.remove(user_list[i])
                    elif operation == "add":
                        if user_list[i] not in current_user_list:
                            current_user_list.append(user_list[i])
            #DONT FORGET TO CHANGE IT IN THE DB TOO
            db.update(set('SharedWith', current_user_list), ((Query().Owner == username) & (Query().FileName == file)))
            db.close()
            return 1
        else:
            db.close()
            return -1

    def __update_file_access_list_keys(self, owner, file, operation, user_list, location):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        #operation = add/delete
        user_list = user_list.split("|")
        for i in range(0, len(user_list)):
            if operation == "add":
                self.__add_user_key_to_storage(owner, user_list[i], file, location)
            if operation == "delete":
                if user_list[i] != "admin":
                    file_path = location + "\\" + owner + "\\" + file + "\\" + file + "_" + user_list[i] + "_key"
                    if os.path.isfile(file_path):
                        os.remove(file_path)

    def __rebuild_shared_keys(self, username, file, location):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        result = db.search((Query().FileName == file) & (Query().Owner == username))
        if len(result[0]['SharedWith']) > 1:
            for i in range(1, len(result[0]['SharedWith'])):
                self.__add_user_key_to_storage(username, result[0]['SharedWith'][i], file, location)

    def __add_user_key_to_storage(self, owner, username, file, location):
        # store key for the user
        key = location + "\\" + owner + "\\" + file + "\\" + file + "_key"
        file_descriptor = open(key, 'rb')
        aes_key = pickle.load(file_descriptor)
        decrypted_key = self.__ibe_decrypt(aes_key, owner)
        file_path = location + "\\" + owner + "\\" + file + "\\" + file + "_" + username + "_key"
        ciphertext = self.__ibe_encrypt(decrypted_key, username)
        file_descriptor = open(file_path,'wb')
        pickle.dump(ciphertext, file_descriptor)
        file_descriptor.close()

    def __view_file_access_list(self, username, file):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        result = db.search((Query().FileName == file) & (Query().Owner == username))
        if len(result) != 0:
            current_user_list = result[0]['SharedWith']
            db.close()
            return current_user_list
        else:
            return -1

    def __view_user_shared_files(self, username):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
        result = db.search(Query().SharedWith.test(self.check_if_user_in_shared_list, username))
        shared_file_list = []
        for i in range(0, len(result)):
            shared_file_list.append([result[i]['Owner'],result[i]['FileName']])

        return shared_file_list

    def __store_key(self, username, key, file, location):
        try:
            os.mkdir(location + "\\" + username + "\\" + file)
        except:
            pass
        finally:
            #store key for the user
            file_path = location + "\\" + username + "\\" + file + "\\" + file + "_key"
            ciphertext = self.__ibe_encrypt(key, username)
            file_descriptor = open (file_path,'wb')
            pickle.dump(ciphertext, file_descriptor)

            #store key for the admin
            file_path = location + "\\" + username + "\\" + file + "\\" + file + "_admin_key"
            file_descriptor = open(file_path, 'wb')
            admin_ciphertext = self.__ibe_encrypt(key, "admin")
            pickle.dump(admin_ciphertext, file_descriptor)

    def __store_iv(self, username, iv, file, location):
        file_path = location + "\\" + username + "\\" + file + "\\"+ file+ "_iv"
        file_descriptor = open(file_path, 'wb')
        file_descriptor.write(iv)

    def __register(self, username, location):
        os.mkdir(location + "\\" + username)
        self.__generate_and_send_r_a_n(username)

    def __generate_and_send_r_a_n(self, username):
        r, a = self.__setup(username)
        list_to_send = [r, a, self.cocks_pkg.n]

        self.zmq_socket.send(pickle.dumps(list_to_send))

    def __ibe_encrypt(self, data, username):
        _, a = self.cocks_pkg.extract(username)
        cocks = Cocks(self.cocks_pkg.n)
        ciphertext = cocks.encrypt(data, a)
        return ciphertext

    def __setup(self, username):
        r, a = self.cocks_pkg.extract(username)
        return r, a

    def __ibe_decrypt(self, ciphertext, username):
        cocks = Cocks(self.cocks_pkg.n)
        r, a = self.cocks_pkg.extract(username)
        plaintext = cocks.decrypt(ciphertext, r, a)
        return plaintext

    def __build_hash(self, file_name, file_size, file_content):
        hash_result = hashlib.sha3_512()
        hash_result.update(bytes(file_name, 'utf-8'))
        hash_result.update(bytes(str(file_size), 'utf-8'))
        hash_result.update(file_content)

        return hash_result.digest()

    def __verify_hash(self, hash_1, hash_2):
        if hash_1 == hash_2:
            return 1
        else:
            return 0

    @staticmethod
    def check_if_user_in_shared_list(shared_list, user):
        for i in range(0, len(shared_list)):
            if shared_list[i] == user:
                return 1

    @staticmethod
    def pickle_scheme(obj, location):
        file_descriptor = open(location, 'wb')
        pickle.dump(obj, file_descriptor)

    @staticmethod
    def load_scheme(location):
        file_descriptor = open(location + "\\cocks.pkg", 'rb')
        cocks_pkg = pickle.load(file_descriptor)
        return cocks_pkg

    @staticmethod
    def generate_first_cocks():
        cocks_pkg = CocksPKG()
        KeyManagementModule.pickle_scheme(cocks_pkg, location=r"C:\Users\lazar\Desktop\Scheme\KeyManagement\cocks.pkg")


obj = KeyManagementModule()
obj.start()