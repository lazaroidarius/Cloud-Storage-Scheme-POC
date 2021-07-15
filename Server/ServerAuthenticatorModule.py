import zmq
import random
from tinydb import TinyDB, Query
from tinydb.operations import set


class ServerAuthenticatorModule:

    def __init__(self):
        context = zmq.Context()
        self.zmq_socket = context.socket(zmq.REP)
        self.zmq_socket.bind("tcp://*:5555")

    def start(self):
        while True:
            request = self.zmq_socket.recv()
            print("Request received: ", request)
            request = request.decode('utf-8')
            if request == "step_2":
                a = self.step_2()
                self.__send_message(a)
            elif request.split("|")[0] == "check_if_user_exists":
                result = self.__check_for_existing_user(request.split("|")[1])
                self.__send_message(str(result))
            elif request.split("|")[0] == "check_if_user_is_admin":
                result = self.__check_if_user_is_admin(request.split("|")[1])
                self.__send_message(str(result))
            elif request.split("|")[0] == "authenticate_client":
                result = self.authenticate_client(request)
                self.__send_message(str(result))
            elif request.split("|")[0] == "retrieve_n":
                n = self.__get_n_from_db(request.split("|")[1])
                self.__send_message(str(n))
            elif request.split("|")[0] == "register":
                name, n, v = self.get_name_n_v(request)
                if self.register_user(name, n, v) == -1:
                    self.__send_message('-1')
                else:
                    self.__send_message('1')

    def __send_message(self, message):
        if isinstance(message, bytes):
            self.zmq_socket.send(message)
        else:
            self.zmq_socket.send(bytes(message, 'utf-8'))

    def __check_if_user_is_admin(self, username):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\authentication_db.json')
        result = db.search(Query().username == username)
        if result[0]['rights'] == 1:
            return 1
        else:
            return 0

    def get_name_n_v(self, message):
        split_data = message.split("|")
        name = split_data[1]
        n = int(split_data[2])
        v = []
        for i in range(3, len(split_data)):
            v.append(int(split_data[i]))
        return name, n, v

    def get_name_y_x_a(self, message):
        #  request|name|y|x|a1|a2
        split_data = message.split("|")
        name = split_data[1]
        y = int(split_data[2])
        x = int(split_data[3])
        a = []
        for i in range(4, len(split_data)):
            a.append(int(split_data[i]))
        return name, y, x, a

    def register_user(self, username, n, v):
        if self.__check_for_existing_user(username) == 1:
            return -1
        else:
            self.__add_user_to_db(username, n, v)
            return 1

    def __add_user_to_db(self, username, n, v):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\authentication_db.json')
        db.insert({'username': username, 'rights': 0, "n": n, "v": v})
        db.close()

    def __check_for_existing_user(self, username):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\authentication_db.json')
        result = db.search(Query().username == username)
        if len(result) == 1:
            db.close()
            return 1
        else:
            db.close()
            return -1

    def __get_v_from_db(self, username):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\authentication_db.json')
        result = db.search(Query().username == username)

        if len(result) == 0:
            db.close()
            return -1
        else:
            v = result[0]['v']
            db.close()
            return v

    def __get_n_from_db(self, username):
        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\authentication_db.json')
        result = db.search(Query().username == username)

        if len(result) == 0:
            db.close()
            return -1
        else:
            n = result[0]['n']
            n = int(n)
            db.close()
            return n

    def authenticate_client(self, message):
        username, y, x, a = self.get_name_y_x_a(message)
        #pull v,n from database
        v = self.__get_v_from_db(username)
        n = self.__get_n_from_db(username)

        y_2 = x
        for i in range(0, 10):
            y_2 *= v[i] ** a[i]

        y_2 = y_2 % n
        if y ** 2 % n == y_2:
            return 1
        else:
            return -1

    def update_client(self, username, n, v):
        if self.__check_for_existing_user(username) == 0:
            return -1

        db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\authentication_db.json')
        db.update(db.update(set('n', n), Query().username == username))
        db.update(db.update(set('n', v), Query().username == username))
        db.close()

    def step_2(self):
        a = [random.randint(0, 1), random.randint(0, 1), random.randint(0, 1), random.randint(0, 1),
             random.randint(0, 1),
             random.randint(0, 1), random.randint(0, 1), random.randint(0, 1), random.randint(0, 1),
             random.randint(0, 1)]
        string_a = str(a[0])
        for i in range(1,len(a)):
            string_a += "|"+str(a[i])
        return string_a


obj = ServerAuthenticatorModule()
obj.start()

#do admin rights check
#change db
