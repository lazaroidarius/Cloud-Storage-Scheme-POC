import zmq
import hashlib
import os

class FileManagementModule:
    def __init__(self, path):
        self.path = path
        context = zmq.Context()
        self.zmq_socket = context.socket(zmq.REP)
        self.zmq_socket.bind("tcp://*:5565")

    def start(self):
        while True:
            #request_type|username
            request = self.zmq_socket.recv()
            request = str(request, 'utf-8')
            print(request)
            request = request.split("|")
            if request[0] == "store_file":
                self.zmq_socket.send(bytes("ok", 'utf-8'))
                self.__store_file(request[1])
            elif request[0] == "delete_file":
                self.__delete_file(request[1], request[2])
            elif request[0] == "list_files":
                self.__list_user_file(request[1])
            elif request[0] == "register_user":
                self.zmq_socket.send(bytes("ok", 'utf-8'))
                self.__create_user_storage(request[1])
            elif request[0] == "retrieve_file":
                self.__retrieve_file(request[1], request[2])
            elif request[0] == "check_if_file_exists":
                self.__check_if_file_exists(request[1], request[2])
            else:
                self.zmq_socket.send(b"invalid_request")

    def __check_if_file_exists(self, username, file):
        file_to_retrieve_path = self.__generate_path_to_file(username, file)
        # check if file exists or not
        if not os.path.isfile(file_to_retrieve_path):
            self.zmq_socket.send(b"file-1")
        else:
            self.zmq_socket.send(b"file1")

    def __store_file(self, username):
        #receive file metadata
        file_name, file_size = self.__receive_file_metadata()
        user_directory_path = self.path + "\\" + username + "\\" + file_name

        #send okay to split the buffer
        self.zmq_socket.send(bytes("ok", 'utf-8'))

        #receive the file contents
        file_content = self.zmq_socket.recv()
        self.zmq_socket.send(bytes("ok", 'utf-8'))

        #receie the hash result
        hash_result = self.zmq_socket.recv()
        #self.zmq_socket.send(bytes("ok", 'utf-8'))

        if self.__check_hash(file_name, file_size, file_content, hash_result) == 1:
            self.zmq_socket.send(bytes("Hash1", 'utf-8'))
            with open(user_directory_path, 'wb+') as file_descriptor:
                file_descriptor.write(file_content)
            file_descriptor.close()
        else:
            self.zmq_socket.send("Hash-1")

    def __receive_file_metadata(self):
        #file_name|file_size
        raw_data = self.zmq_socket.recv()
        raw_data = str(raw_data, 'utf-8')

        split_raw_data = raw_data.split("|")
        file_name = split_raw_data[0]
        file_size = split_raw_data[1]

        return file_name, file_size

    def __build_hash(self, file_name, file_size, file_content):
        hash_result = hashlib.sha3_512()
        hash_result.update(bytes(file_name, 'utf-8'))
        hash_result.update(bytes(str(file_size), 'utf-8'))
        hash_result.update(file_content)

        return hash_result.digest()

    def __check_hash(self, file_name, file_size, file_content, received_hash):
        built_hash = self.__build_hash(file_name, file_size, file_content)
        if received_hash == built_hash:
            return 1
        else:
            return 0

    def __generate_path_to_file(self, username, file_name):
        path_to_file = self.path + "\\"+username + "\\" + file_name
        return path_to_file

    def __retrieve_file(self, username, file_name):
        file_to_retrieve_path = self.__generate_path_to_file(username, file_name)
        #check if file exists or not
        if not os.path.isfile(file_to_retrieve_path):
            self.zmq_socket.send(b"file-1")
            return -1
        # generate file name and size
        file_name = file_to_retrieve_path.split("\\")[-1]
        file_size = os.path.getsize(file_to_retrieve_path)
        # read the files contents
        file_descriptor = open(file_to_retrieve_path, "rb")
        file_content = file_descriptor.read()

        hash_result = self.__build_hash(file_name, file_size, file_content)

        #send metada
        file_metadata = file_name + "|" + str(file_size)
        self.zmq_socket.send(bytes(file_metadata, "utf-8"))
        #wait for ok
        self.zmq_socket.recv()
        #send content
        self.zmq_socket.send(file_content)
        #wait for ok
        self.zmq_socket.recv()
        #send hash
        self.zmq_socket.send(hash_result)

    def __retrieve_key(self, key_name):
        pass

    def __create_user_storage(self, username):
        user_directory_path = self.path + "\\" + username
        os.mkdir(user_directory_path)

    def __list_user_file(self, username):
        user_directory_path = self.path + "\\" + username
        result = os.listdir(user_directory_path)
        files_stored = ""
        if len(result) > 0:
            for i in range(0, len(result)):
                files_stored += result[i] + "|"
        files_stored = files_stored[:-1]
        self.zmq_socket.send(bytes(files_stored, 'utf-8'))

    def __delete_file(self, username, file_name):
        file_to_delete_path = self.path + "\\"+username + "\\" + file_name
        if os.path.isfile(file_to_delete_path):
            if os.remove(file_to_delete_path):
                self.zmq_socket.send(bytes("delete-1", "utf-8"))
            else:
                self.zmq_socket.send(bytes("delete1", "utf-8"))
        else:
            self.zmq_socket.send(bytes("delete-1", "utf-8"))


obj = FileManagementModule("C:\\Users\\lazar\\Desktop\Scheme\\Storage")
obj.start()



#file names will be encrypted with a user key(or not?)(creates problems)
#every user will have a folder
#keys will be stored in a filed named hash(file_name,username)
#list user files command
#list other user files as admin
#password
#make admin acc