import socket
import hashlib
import zmq
import pickle
import os
import threading

PORT = 5050
ADDRESS = '127.0.0.1'


class ServerNetworkInterface:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((ADDRESS, PORT))
        self.active_connections = []

    def start_server(self):
        self.sock.listen()
        while True:
            connection, address = self.sock.accept()
            self.active_connections.append(connection)
            cThread = threading.Thread(target=self.__connection_handler, args=(connection, address))
            cThread.daemon = True
            cThread.start()
            #self.__connection_handler(connection, address)

    def __connection_handler(self, connection, address):
        print("Client ", connection, " connected.")
        login = 0
        logged_in_as = ''
        admin_rights = 0
        while True:
            message = self.__receive_message(connection)
            print(message)
            processed_message = self.__process_message(message)
            if processed_message == 'disconnect':
                self.__disconnect(connection)
                login = 0
                logged_in_as = ''
                admin_rights = 0
                break
            elif login == 1 and processed_message == 'incomingfile':
                self.__receive_file(connection, logged_in_as)
            elif login == 0 and processed_message == 'register':
                self.__register(connection)
            elif login == 0 and processed_message == 'login':
                response, username, admin_rights = self.__login(connection)
                if response == 1:
                    login = 1
                    logged_in_as = username
            elif login == 1 and processed_message == 'delete_file':
                self.__send_message("ok", connection)
                file_to_delete = self.__receive_message(connection)
                self.__delete_file_from_storage(logged_in_as, file_to_delete, connection)
            elif login == 1 and processed_message == 'get_file_list':
                self.__get_stored_file_list(logged_in_as, connection)
            elif login == 1 and processed_message == 'get_file':
                self.__send_message("ok", connection)
                file_to_download = self.__receive_message(connection)
                self.__get_stored_file(logged_in_as, file_to_download, connection)
            elif login == 1 and processed_message == 'logout':
                login = 0
                logged_in_as = ''
                self.__send_message("loggedout1", connection)
            elif login == 1 and processed_message == 'view_file_access_list':
                self.__send_message(b"ok", connection)
                self.__retrieve_file_access_list(logged_in_as, connection)
            elif login == 1 and processed_message == 'view_shared_user_files':
                self.__retrieve_shared_user_files_list(logged_in_as, connection)
            elif login == 1 and processed_message == 'update_file_access_list':
                self.__send_message(b"ok", connection)
                self.__update_shared_file(logged_in_as, connection)
            elif login == 1 and processed_message == 'download_shared_file':
                self.__send_message("ok", connection)
                owner_and_file = self.__receive_message(connection).decode()
                self.__download_shared_file(logged_in_as, owner_and_file.split("|")[0], owner_and_file.split("|")[1], connection)
            elif login == 1 and processed_message == 'upload_shared_file':
                self.__send_message("ok", connection)
                payload = self.__receive_message(connection).decode().split("|")
                self.__upload_shared_file(logged_in_as, payload[0], payload[1], connection)
            elif login == 1 and processed_message == 'get_cocks_params':
                self.__retrieve_cocks_params(connection)
            else:
                self.__send_message(message, connection)

    def __upload_shared_file(self, username, owner, file, connection):
        #check if file exists/
        zmq_socket = self.__initialize_file_management_zmq_socket()
        request = "check_if_file_exists|" + owner + "|" + file
        zmq_socket.send(bytes(request, "utf-8"))
        response = zmq_socket.recv()
        zmq_socket.close()
        if response == b"file-1":
            self.__send_message(b"u-1", connection)
            self.__receive_message(connection)
            self.__send_message(b"u-1", connection)
            return -1

        # check if user can upload
        zmq_socket = self.__initialize_key_management_zmq_socket()
        request = "check_if_user_is_on_access_list|" + username + "|" + file + "|" + owner
        zmq_socket.send(bytes(request, "utf-8"))
        response = zmq_socket.recv()
        zmq_socket.close()
        if response == b"-1":
            self.__send_message(b"u-1", connection)
            self.__receive_message(connection)
            self.__send_message(b"u-1", connection)
            return -1

        self.__send_message(b"u1", connection)
        self.__receive_message(connection)

        #get user key/send user key
        key_and_iv = self.__get_key_and_iv(username, file, owner)
        self.__send_and_split_file(key_and_iv, connection)
        self.__send_message(b'stop', connection)
        self.__receive_message(connection)

        #self.__send_message(b"ok", connection)
        file_name, file_size, hash_received = self.__receive_file_start(connection)
        self.__send_message("ok", connection)
        received_file = self.__receive_file_bits(connection)

         # receive iv
        pickled_list = self.__receive_message(connection)
        unpickled_list = pickle.loads(pickled_list)

        # check digest
        hash_result = self.__build_hash(file_name, file_size, received_file)
        if self.__verify_hash(hash_result, hash_received) == 0:
            self.__send_message("hash-1", connection)
            return -1

        # send file to storage
        self.__send_file_to_storage(file_name, file_size, received_file, hash_result, owner, connection)

        # send key and iv to KMM
        self.__send_iv_to_kmm(file_name, owner, unpickled_list)

    def __download_shared_file(self, username, owner, file_name, connection):
        #check if user can perform operation

        #CHECK IF FILE EXISTS OR NOT
        zmq_socket = self.__initialize_file_management_zmq_socket()
        #send request
        request = "retrieve_file|" + owner + "|" + file_name
        zmq_socket.send(bytes(request, "utf-8"))
        #receive response if file exists or not

        #receive metadata(file_name|file_size)
        file_metadata = zmq_socket.recv()
        if file_metadata == b'file-1':
            zmq_socket.close()
            self.__send_message("file-1", connection)
            self.__receive_message(connection)
            self.__send_message("file-1", connection)
            return -1
        file_name = file_metadata.decode().split("|")[0]
        file_size = file_metadata.decode().split("|")[1]
        #send ok
        zmq_socket.send(bytes("ok", "utf-8"))
        #receive file content
        file_content = zmq_socket.recv()
        #send ok
        zmq_socket.send(bytes("ok", "utf-8"))
        #receive hash_result
        received_hash = zmq_socket.recv()
        #close socket
        zmq_socket.close()
        hash_result = self.__build_hash(file_name, file_size, file_content)

        msg_to_send = self.__get_key_and_iv(username, file_name, owner)

        if self.__verify_hash(received_hash, hash_result) == 0 and msg_to_send != 0:
            self.__send_message("e-1", connection)
            self.__receive_message(connection)
            self.__send_message("hash-1", connection)
            return -1

        if msg_to_send == -1:
            self.__send_message(b"file-1", connection)
            test = self.__receive_message(connection)
            self.__send_message(b"ek-1", connection)
        else:
            self.__send_file_metadata(file_metadata, file_content, hash_result, connection)
            self.__receive_message(connection)
            self.__send_and_split_file(msg_to_send, connection)
            self.__send_message(b'stop', connection)
            self.__receive_message(connection)
            self.__send_message(b"ok", connection)
            message = self.__receive_message(connection)
            self.__send_message(message, connection)

    def __retrieve_shared_user_files_list(self, username, connection):
        #retrieve list
        zmq_socket = self.__initialize_key_management_zmq_socket()
        request = "view_user_access_list|" + username
        zmq_socket.send(bytes(request,"utf-8"))
        response = zmq_socket.recv()
        zmq_socket.close()
        file_list = pickle.loads(response)

        #forward list
        reply = "shared_user_files|"
        for i in range(0,len(file_list)):
            reply += file_list[i][0] + "|" + file_list[i][1] + "|"
        reply = reply[:-1]
        self.__send_message(reply, connection)

    def __retrieve_file_access_list(self,username, connection):

        file = self.__receive_message(connection).decode()

        # check if file exists
        request = "check_if_file_exists|" + username + "|" + file
        zmq_socket = self.__initialize_file_management_zmq_socket()
        zmq_socket.send(bytes(request, "utf-8"))
        response = zmq_socket.recv()
        zmq_socket.close()

        if response == b'file-1':
            self.__send_message(b"file-1", connection)
            return -1

        # retrieve file acess list
        zmq_socket = self.__initialize_key_management_zmq_socket()
        request = "view_file_access_list|" + username + "|" + file
        zmq_socket.send(bytes(request, "utf-8"))
        response = zmq_socket.recv()
        zmq_socket.close()

        #send the list
        unpickled_list = pickle.loads(response)
        response = "files_acess_list|" + file
        for i in range(0, len(unpickled_list)):
            response += "|" + unpickled_list[i]
        self.__send_message(bytes(response, "utf-8"), connection)

    def __retrieve_cocks_params(self, connection):
        self.__send_message(b"ok", connection)
        first_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        second_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        third_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        fourth_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        if first_response == -1 or second_response == -1 or third_response == -1 or fourth_response == -1:
            self.__send_message(b'login-1', connection)
            self.__receive_message(connection)
            self.__send_message(b'pass-1', connection)
        else:
            self.__send_message(b'login1', connection)
            self.__receive_message(connection)
            #Get r_a_n
            zmq_socket = self.__initialize_key_management_zmq_socket()
            request = "get_cocks_params|" + username
            zmq_socket.send(bytes(request,"utf-8"))
            cocks_params = zmq_socket.recv()
            zmq_socket.close()
            #send r a n
            self.__send_message(cocks_params, connection)
            #receive ok
            self.__receive_message(connection)
            self.__send_message(b'cocks1', connection)

    def __update_shared_file(self, username, connection):
        # file|operation|user1|user2|user3

        request = username + "|" + self.__receive_message(connection).decode()

        # does file exist?
        zmq_socket = self.__initialize_file_management_zmq_socket()
        request_fmm = "check_if_file_exists|" + username + "|" + request.split("|")[1]
        zmq_socket.send(bytes(request_fmm, "utf-8"))
        response = zmq_socket.recv()
        zmq_socket.close()
        if response == b'file-1':
            self.__send_message(b"file-1", connection)
            return -1

        # do all the users in the list of users exist?
        if self.__verify_list_of_users(request.split("|")[3:]) == -1:
            self.__send_message(b"user-1", connection)
            return -1

        request = "update_access_list|" + request
        zmq_socket = self.__initialize_key_management_zmq_socket()
        zmq_socket.send(bytes(request, "utf-8"))
        if zmq_socket.recv() == b'e-1':
            self.__send_message(b'eu-1', connection)
        else:
            self.__send_message(b'eu1', connection)
        zmq_socket.close()

    def __verify_list_of_users(self, list_of_users):
        for i in range(0, len(list_of_users)):
            request = "check_if_user_exists|" + list_of_users[i]
            response = self.__request_to_auth_module(request)
            if response == b'-1':
                return -1
        return 1

    def __process_message(self, message):
        if message == b'disconnect':
            return 'disconnect'
        if message == b'':
            print("emtpy message received,disconnecting")
            return 'disconnect'
        if message == b'sendingfile':
            return 'incomingfile'
        if message == b'logout':
            return 'logout'
        if message == b'login':
            return 'login'
        if message == b'register':
            return 'register'
        if message == b'finished_sending_file':
            return b'stop'
        if message == b'view_stored_files':
            return 'get_file_list'
        if message == b'delete_stored_file':
            return 'delete_file'
        if message == b'retrieve_file':
            return 'get_file'
        if message == b'delete_file':
            return 'delete_file'
        if message == b'download_file':
            return 'get_file'
        if message == b'update_file_access_list':
            return 'update_file_access_list'
        if message == b'view_file_access_list':
            return 'view_file_access_list'
        if message == b'get_cocks_params':
            return 'get_cocks_params'
        if message == b'view_shared_user_files':
            return 'view_shared_user_files'
        if message == b'download_shared_file':
            return 'download_shared_file'
        if message == b'upload_shared_file':
            return 'upload_shared_file'
        else:
            return message

    def __login(self, connection):
        self.__send_message(b"ok", connection)
        first_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        second_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        third_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        fourth_response, username, admin_rights = self.__fiat_shamir_identification(connection)
        if first_response == -1 or second_response == -1 or third_response == -1 or fourth_response == -1:
            self.__send_message(b'login-1', connection)
            self.__receive_message(connection)
            self.__send_message(b'login-1', connection)
            return -1, username, admin_rights
        else:
            self.__send_message(b'login1', connection)
            self.__receive_message(connection)
            self.__send_message(b'login1', connection)
            return 1, username, admin_rights

    def __fiat_shamir_identification(self, connection):
        admin_rights = 0
        #receive username
        username = self.__receive_message(connection)

        #first check if the user exists
        username = username.decode("utf-8")
        request = "check_if_user_exists|"+username
        response = self.__request_to_auth_module(request)

        if response.decode('utf-8') == '-1':
            self.__send_message("-1", connection)
            #self.__send_message("login-1", connection)
            return -1, username, admin_rights
        else:
            # check wether user has admin status or not
            request = "check_if_user_is_admin|" + username
            admin_rights = int(self.__request_to_auth_module(request).decode("utf-8"))
            #if yes send 1 and n
            #self.__send_message('1', connection)
            request = "retrieve_n|" + username
            response = self.__request_to_auth_module(request)
            self.__send_message(response, connection)

            #receive x
            x = self.__receive_message(connection)
            x = x.decode('utf-8')
            x = int(x)
            #generate a
            request = "step_2"
            response = self.__request_to_auth_module(request)

            #send and keep a
            a_raw = response.decode('utf-8')
            self.__send_message(a_raw, connection)

            #turn a to int[]
            a_string = a_raw.split("|")
            a = []
            for i in range(0, len(a_string)):
                a.append(int(a_string[i]))

            #receive y
            y = self.__receive_message(connection)
            y = y.decode('utf-8')
            y = int(y)

            #send name|y|x|a1|a2... to auth module
            request = "authenticate_client|" + username+"|"+str(y)+"|"+str(x)
            for i in range(0, len(a)):
                request += "|" + str(a[i])

            response = self.__request_to_auth_module(request)

            if response == b'-1':
                admin_rights = 0
                return -1, username, admin_rights
            else:
                return 1, username, admin_rights

    def __register(self, connection):
        # name|n|v
        raw_data = self.__receive_message(connection)

        raw_data = str(raw_data, 'utf-8')
        name = raw_data.split("|")[0]
        request = 'register|' + raw_data
        response = self.__request_to_auth_module(request)

        if response == b'-1':
            self.__send_message(b'register-1', connection)
            self.__receive_message(connection)
            self.__send_message(b'register-1', connection)
        else:
            self.__send_message(b'register1', connection)
            zmq_socket = self.__initialize_key_management_zmq_socket()
            request = "register|" + name
            zmq_socket.send(bytes(request, "utf-8"))
            pickled_list = zmq_socket.recv()
            self.__send_message(pickled_list, connection)
            self.__receive_message(connection)
            self.__send_message(b'register1', connection)
            self.__create_user_storage(name)
            zmq_socket.close()

    def __create_user_storage(self, username):
        #initialize and send request
        zmq_socket = self.__initialize_file_management_zmq_socket()
        request = "register_user|"+username
        zmq_socket.send(bytes(request, 'utf-8'))
        #receive ok
        zmq_socket.recv()
        zmq_socket.close()

    def __request_to_auth_module(self, request):
        # initialize zmq socket
        context = zmq.Context()
        zmq_socket = context.socket(zmq.REQ)
        zmq_socket.connect("tcp://localhost:5555")

        #build and send request
        request = bytes(request, 'utf-8')
        zmq_socket.send(request)
        response = zmq_socket.recv()
        zmq_socket.close()

        return response

    def __update_user(self):
        pass

    def __receive_file_start(self, connection):
        # file_name+"|"+file_size
        received_message = self.__receive_message(connection)
        #send ok
        self.__send_message("ok", connection)
        # digest
        hash_received = self.__receive_message(connection)
        packed_response = received_message.decode('utf-8').split("|")
        file_name = packed_response[0]
        file_size = packed_response[1]

        return file_name, file_size, hash_received

    def __receive_file_bits(self, connection):
        # receive file the file 4096 bytes at a time
        received_file = b''
        received_message = self.__process_message(self.__receive_message(connection))
        self.__send_message("ok", connection)

        while received_message != b'stop':
            received_file = received_file + received_message
            received_message = self.__process_message(self.__receive_message(connection))
            self.__send_message("ok", connection)

        return received_file

    def __receive_file(self, connection, username):

        self.__send_message(b"ok", connection)
        file_name, file_size, hash_received = self.__receive_file_start(connection)
        self.__send_message("ok", connection)
        received_file = self.__receive_file_bits(connection)

         # receive key,iv
        pickled_list = self.__receive_message(connection)
        unpickled_list = pickle.loads(pickled_list)

        # check digest
        hash_result = self.__build_hash(file_name, file_size, received_file)
        if self.__verify_hash(hash_result, hash_received) == 0:
            self.__send_message("hash-1", connection)
            return -1

        # send file to storage
        self.__send_file_to_storage(file_name, file_size, received_file, hash_result, username, connection)

        # send key and iv to KMM
        self.__send_key_and_iv_to_KMM(file_name, username, unpickled_list[0], unpickled_list[1])

    def __send_key_and_iv_to_KMM(self, file_name, username, aes_key, iv):
        # store_key|username|file|
        # recv [key,iv]
        zmq_socket = self.__initialize_key_management_zmq_socket()
        request = "store_key|" + username + "|" + file_name
        zmq_socket.send(bytes(request, "utf-8"))
        zmq_socket.recv()
        pickled_list = [aes_key, iv]
        pickled_list = pickle.dumps(pickled_list)
        zmq_socket.send(pickled_list)
        zmq_socket.recv()
        zmq_socket.close()

    def __send_iv_to_kmm(self, file_name, username, iv):
        zmq_socket = self.__initialize_key_management_zmq_socket()
        request = "store_iv_only|" + username + "|" + file_name
        zmq_socket.send(bytes(request, "utf-8"))
        zmq_socket.recv()
        pickled_list = iv
        pickled_list = pickle.dumps(pickled_list)
        zmq_socket.send(pickled_list)
        zmq_socket.recv()
        zmq_socket.close()

    def __send_file_to_storage(self, file_name, file_size, file_content, hash_result, username, connection):

        #initialize zmq socket
        zmq_socket = self.__initialize_file_management_zmq_socket()

        #build the request
        request = "store_file|" + username
        request = bytes(request, 'utf-8')
        #send the initial rqeqest
        zmq_socket.send(request)
        #receive ok
        zmq_socket.recv()

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
            self.__send_message(b'hash1', connection)
        else:
            self.__send_message(b'hash-1', connection)

        zmq_socket.close()

    def __initialize_file_management_zmq_socket(self):
        context = zmq.Context()
        zmq_socket = context.socket(zmq.REQ)
        zmq_socket.connect("tcp://localhost:5565")
        return zmq_socket

    def __initialize_key_management_zmq_socket(self):
        context = zmq.Context()
        zmq_socket = context.socket(zmq.REQ)
        zmq_socket.connect("tcp://localhost:5570")
        return zmq_socket

    def __delete_file_from_storage(self, username, file_name, connection):
        # initialize zmq socket
        zmq_socket = self.__initialize_file_management_zmq_socket()

        #build and send request
        request = "delete_file|"+username+"|"+file_name.decode()
        zmq_socket.send(bytes(request, 'utf-8'))
        #receive response
        response = zmq_socket.recv()
        zmq_socket.close()

        if response.decode() == "delete-1":
            self.__send_message("del-1", connection)
            self.__receive_message(connection)
            self.__send_message("del-1", connection)
        else:
            self.__send_message("del1", connection)
            self.__receive_message(connection)
            self.__send_message("del1", connection)
            zmq_socket = self.__initialize_key_management_zmq_socket()
            request = "delete_file_keys|" + username + "|" + file_name.decode()
            zmq_socket.send(bytes(request, "utf-8"))
            zmq_socket.recv()
            zmq_socket.close()

    def __get_stored_file_list(self, username, connection):
        #initialize zmq socket
        zmq_socket = self.__initialize_file_management_zmq_socket()

        #build and send request
        request = "list_files|"+username
        zmq_socket.send(bytes(request, "utf-8"))
        #receive the response
        response = zmq_socket.recv()
        response = "files_stored|"+response.decode("utf-8")
        #files_stored|file1|file2|file3....
        zmq_socket.close()
        self.__send_message(response, connection)

    def __send_file_metadata(self, file_metadata, file_content, hash_result, connection):
        # send metedata
        self.__send_message(file_metadata, connection)
        self.__receive_message(connection)

        # send hash_result
        self.__send_message(hash_result, connection)
        self.__receive_message(connection)

        if len(file_content) <= 4096:
            self.__send_message(file_content, connection)
            self.__receive_message(connection)
            # this message signals the client that the file is done sending
            self.__send_message(b"stop", connection)
        # otherwise split and send multiple 4096 bytes messages
        else:
            self.__send_and_split_file(file_content, connection)
            # this message signals the client that the file is done sending
            self.__send_message(b"stop", connection)

    def __get_stored_file(self, username, file_name, connection):
        #CHECK IF FILE EXISTS OR NOT
        zmq_socket = self.__initialize_file_management_zmq_socket()
        #send request
        request = "retrieve_file|" + username + "|" + file_name.decode()
        zmq_socket.send(bytes(request, "utf-8"))
        #receive response if file exists or not

        #receive metadata(file_name|file_size)
        file_metadata = zmq_socket.recv()
        if file_metadata == b'file-1':
            zmq_socket.close()
            self.__send_message("file-1", connection)
            self.__receive_message(connection)
            self.__send_message("file-1", connection)
            return -1
        file_name = file_metadata.decode().split("|")[0]
        file_size = file_metadata.decode().split("|")[1]
        #send ok
        zmq_socket.send(bytes("ok", "utf-8"))
        #receive file content
        file_content = zmq_socket.recv()
        #send ok
        zmq_socket.send(bytes("ok", "utf-8"))
        #receive hash_result
        received_hash = zmq_socket.recv()
        #close socket
        zmq_socket.close()
        hash_result = self.__build_hash(file_name, file_size, file_content)

        if self.__verify_hash(received_hash, hash_result) == 0:
            self.__send_message("e-1", connection)
            self.__receive_message(connection)
            self.__send_message("hash-1", connection)
        else:
            self.__send_file_metadata(file_metadata, file_content, hash_result, connection)
            self.__receive_message(connection)

            msg_to_send = self.__get_key_and_iv(username, file_name, username)
            if msg_to_send == -1:
                self.__send_message(b"ek-1", connection)
                self.__receive_message(connection)
                self.__send_message(b"ek-1", connection)
            else:
                self.__send_and_split_file(msg_to_send, connection)
                self.__send_message(b'stop', connection)
                self.__receive_message(connection)
                self.__send_message(b"ok", connection)
                message = self.__receive_message(connection)
                if message == b"hash1":
                    self.__send_message(message, connection)
                else:
                    self.__send_message(b"hash-1", connection)

    def __get_key_and_iv(self, username, file, owner):
        zmq_socket = self.__initialize_key_management_zmq_socket()
        request = "retrieve_key|" + username + "|" + file + "|" + owner
        zmq_socket.send(bytes(request, "utf-8"))
        encrypted_key = zmq_socket.recv()
        if encrypted_key == b"e-1":
            zmq_socket.close()
            return -1
        else:
            zmq_socket.send(b"ok")
            iv = zmq_socket.recv()
            zmq_socket.send(b"ok")
            final_response = zmq_socket.recv()
            if final_response == b"-1":
                zmq_socket.close()
                return -1
            else:
                list_to_send = [encrypted_key, iv]
                list_to_send = pickle.dumps(list_to_send)
                zmq_socket.close()
                return list_to_send

    def __send_and_split_file(self, file_content, connection):
        i = 1
        while i * 4096 < len(file_content) + 4096:
            if i * 4096 > len(file_content):
                self.__send_message(file_content[4096 * (i - 1):len(file_content)], connection)
                self.__receive_message(connection)
                break
            else:
                self.__send_message(file_content[4096 * (i - 1):(4096 * i)], connection)
                self.__receive_message(connection)
                i = i + 1

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

    def __send_message(self, message, connection):
        if isinstance(message, bytes):
            connection.send(message)
        else:
            connection.sendall(bytes(message, 'utf-8'))

    def __disconnect(self, connection):
        try:
            self.active_connections.remove(connection)
            connection.shutdown(socket.SHUT_RDWR)
            connection.close()
            print("Client ", connection, " disconnected succesfully.")
            return 0
        except:
            print("Error occured during disconnection at the ", connection, " connection")
            return -1

    def __receive_message(self, connection):
        received_message = connection.recv(4096)
        return received_message


obj = ServerNetworkInterface()
obj.start_server()


#fix admin stuff

#4 rounds auth