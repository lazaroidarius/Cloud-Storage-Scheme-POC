import zmq
import threading
import math
import pickle
import random
import numpy
import Crypto.Util.number
from tinydb.operations import set
import hashlib
import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import gmpy2
from Client import ClientCryptoModule


from cocks.utils import InvalidIdentityString
from cocks.cocks import CocksPKG, Cocks

from tinydb import TinyDB, Query
from tinydb.operations import set


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)






"""
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
                key_content = pickle.dumps(key_content)
                file_descriptor.close()
                iv_file = location + "\\" + owner + "\\" + file + "\\" + file + "_iv"
                iv_content = open(iv_file, 'rb').read()
                # send key
                self.zmq_socket.send(key_content)
                # receive ok
                self.zmq_socket.recv()
                # send iv
                self.zmq_socket.send(iv_content)
                #receive ok
                self.zmq_socket.recv()

                if owner != username:
                    new_encrypted_file, iv = self.__re_encrypt_file_with_different_iv(pickle.loads(key_content),iv_content, file_content, username)
                    self.__store_iv(owner, iv, file, location)
                    if self.__store_file_with_FMM(owner, file_name, file_size, new_encrypted_file) == 1:
                        self.zmq_socket.send(b"1")
                    else:
                        self.zmq_socket.send(b"-1")
                else:
                    self.zmq_socket.send(b"1")
                    #check if ok,send forwrad
        else:
            self.zmq_socket.send(b"e-1")
"""

"""

from tkinter import *

win = Tk()

x = IntVar()
x.set(1)
def add():
    x.set(x.get() + 1)

label = Label(win, textvariable=x)
label.pack()

button = Button(win, text="Increment", command=add)
button.pack()

win.mainloop()

"""

"""

def testfunc(sth,test):
    for i in range(len(sth)):
        if test == sth[i]:
            return 1

db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagement\\file_db.json')
result = db.search((Query().SharedWith.test(testfunc, "test1")) & (Query().FileName == "test_file2.txt") & (Query().Owner == "test"))

print(result)
"""

"""
def test( username, plaintext):
    cocks_pkg = CocksPKG(2048)
    r, a = cocks_pkg.extract(username)
    print(r)
    print("---------------------------------------------------------------------------------")
    print(a)
    print("---------------------------------------------------------------------------------")
    cocks = Cocks(cocks_pkg.n)
    criptotext = cocks.encrypt(plaintext, a)
    print(criptotext)
    print("---------------------------------------------------------------------------------")
    r, a = cocks_pkg.extract("cdsfdsfsfdsfsggfh")
    r, a = cocks_pkg.extract("asdsadddddddddddddd")
    r, a = cocks_pkg.extract("gfdgsggggggg")
    r, a = cocks_pkg.extract("cdsfdsfsf")
    r, a = cocks_pkg.extract("cdsdsfsggfh")
    r, a = cocks_pkg.extract("cfdsfsfdsfsggfh")
    r, a = cocks_pkg.extract("cdsfdsfsfdsfsggfh")
    r, a = cocks_pkg.extract("cdsfdsfsfdh")
    msg = cocks.decrypt(criptotext, r, a)
    print(msg)
    print("---------------------------------------------------------------------------------")
    file = open("test.pickle", 'wb')
    pickle.dump(criptotext, file)

test ("test_username",b"teststuff")

#print(os.listdir(r"C))

"""

"""
def receive_message(self):
    return self.client.recv(4096)

test_string = "0|1|2|3|4|5"

print(test_string.split("|")[2:])

key = b"12345"
key = ClientCryptoModule.ClientCryptoModule.pad_key(key)
encrypted, tag, nonce = ClientCryptoModule.ClientCryptoModule.encrypt_aes_eax(key, b"data")
decrypted = ClientCryptoModule.ClientCryptoModule.decrypt_aes_eax(key, tag, nonce, encrypted)
print(decrypted)

"""


"""
file_path = 
file_descriptor = open(file_path, 'w+')
file_descriptor.write("test")
file_descriptor.close()
"""

"""
test = ["sxfv"]
file_descriptor = open()
"""

"""

def testfunc(sth,test):
    for i in range(len(sth)):
        if test == sth[i]:
            return 1


db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\test_db.json')

#list = ["user1","user2"]
#db.insert({'owner': "blah", "SharedWith": list, "File": "test_file_2"})
#result = db.search( Query().SharedWith.test(testfunc, "user3"))
result_2 = db.search((Query().owner == "testowner") & (Query().File == "test_file_2"))
#list_2 = []
#list_2.append("lmaoelelele")
#list_2.append("lmaoelelele")
#db.remove(Query().owner == 'testowner')
#db.update(delete, Query().owner == 'testowner')
#print(db.all())
#print(result)
print(result_2)


"""
"""
obj = ClientCryptoModule()
aes_key, iv = obj.generate_aes_key()
print(aes_key)
print("--------------------------------------------------------------------------------------------------------")
file = open("C:\\Users\\lazar\\Desktop\\test_file2.txt", 'rb')
content = file.read()
cipher_text = obj.encrypt_aes(aes_key,iv,content)
print(cipher_text)
print()
print()
plaintext = obj.decrypt_aes(aes_key,cipher_text)
print(plaintext)
"""


"""
def test( username, plaintext):
    cocks_pkg = CocksPKG(2048)
    r, a = cocks_pkg.extract(username)
    # assert gmpy2.jacobi(a, cocks_pkg.n) == 1
    print(r)
    print("---------------------------------------------------------------------------------")
    print(a)
    print("---------------------------------------------------------------------------------")
    cocks = Cocks(cocks_pkg.n)
    criptotext = cocks.encrypt(plaintext, a)
    print(criptotext)
    print("---------------------------------------------------------------------------------")
    msg = cocks.decrypt(criptotext, r, a)
    print(msg)
    print("---------------------------------------------------------------------------------")
    file = open("test.pickle", 'wb')
    pickle.dump(criptotext, file)

test ("test_username",b"teststuff")
"""


"""
def __add_users_to_file_acess_list(self, username, file, user_list):
    db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagemenet\\file_db.json')
    result = db.search(Query().FileName == file, Query().Username == username)
    if len(result) != 0:
        current_user_list = result[0]['SharedWith']
        user_list = user_list.split("|")
        if len(user_list) != 0:
            for i in range(0, len(user_list)):
                current_user_list += "|" + user_list[i]
        db.close()
        return 1
    else:
        db.close()
        return -1


def __remove_users_from_file_access_list(self, username, file, user_list, change):
    # chage = add/delete
    db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\KeyManagemenet\\file_db.json')
    result = db.search(Query().FileName == file, Query().Username == username)
    if len(result) != 0:
        current_user_list = result[0]['SharedWith']
        user_list = user_list.split("|")
        if len(user_list) != 0:
            for i in range(0, len(user_list)):
                if user_list[i] != "admin":
                    current_user_list = current_user_list.replace(user_list, "")
                    current_user_list = current_user_list.replace("||", "|")
        db.close()
        return 1
    else:
        db.close()
        return -1
        """

"""
def test_encrypt_decrypt():
    m1 = bytes(b"Hello")
    m2 = bytes("Hello world", encoding="utf8")
    #m3 = bytes(12345)
    m4 = bytes(b"aaaaaaaaaaa bbbbbbbbbbbb cccccccccc dddddddddd")
    m5 = bytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.", encoding="utf8")

    cocks_pkg = CocksPKG()
    test_id = "test"
    r, a = cocks_pkg.extract(test_id)

    cocks = Cocks(cocks_pkg.n)
    c_list = cocks.encrypt(m1, a)
    assert m1 == cocks.decrypt(c_list, r, a)
    c_list = cocks.encrypt(m2, a)
    assert m2 == cocks.decrypt(c_list, r, a)
    #c_list = cocks.encrypt(m3, a)
    #assert m3 == cocks.decrypt(c_list, r, a)
    c_list = cocks.encrypt(m4, a)
    assert m4 == cocks.decrypt(c_list, r, a)
    c_list = cocks.encrypt(m5, a)
    assert m5 == cocks.decrypt(c_list, r, a)

def test_pkg_modulus():
    # Test modulus bit lengths.
    # Caution: this will take some time.
    cocks_pkg = CocksPKG()
    assert cocks_pkg.n.bit_length() == 2048
    cocks_pkg = CocksPKG(512)
    assert cocks_pkg.n.bit_length() == 512
    cocks_pkg = CocksPKG(1024)
    assert cocks_pkg.n.bit_length() == 1024
    cocks_pkg = CocksPKG(3072)
    assert cocks_pkg.n.bit_length() == 3072
    cocks_pkg = CocksPKG(4096)
    assert cocks_pkg.n.bit_length() == 4096

def test_pkg_extract():
    cocks_pkg = CocksPKG()
    _, a = cocks_pkg.extract("test")
    assert gmpy2.jacobi(a, cocks_pkg.n) == 1
    _, a = cocks_pkg.extract("012345678938")
    assert gmpy2.jacobi(a, cocks_pkg.n) == 1
    _, a = cocks_pkg.extract("this is a longer user identity string")
    assert gmpy2.jacobi(a, cocks_pkg.n) == 1
    _, a = cocks_pkg.extract("111111111111111111111111111111111111111111111111")
    assert gmpy2.jacobi(a, cocks_pkg.n) == 1


test_encrypt_decrypt()

"""

"""
hash = hashlib.sha3_512()
hash.update(bytes("test123213213213", 'utf-8'))
result = hash.digest()
print(result.decode('utf-8'))
"""




"""
from tinydb import TinyDB, Query
db = TinyDB('C:\\Users\\lazar\\Desktop\\Scheme\\test_db.json')
#table = db.table('test_table')

db.insert({'username': 24, "n": "201", "v" : "56405645640654|5564005606560560|645604606064560456"})
#result = db.search(Query().username == 25)
#print(db.__doc__)
db.update(set('username', 69), Query().username == 24)
#print(result[0]['v'])
print(db.all())

#find out how to work this garbage module
"""

"""
password = "benis"
new_string = ""
for i in range(0,len(password)):
    new_string += str(ord(password[i]))
random.seed(int(new_string))
print(random.randint(1, 2**256))
print(new_string)

#random.seed(70)
#print(random.randint(1, 2**256))
"""

"""
random.seed("test")
p = Crypto.Util.number.getPrime(1024)
q = Crypto.Util.number.getPrime(1024)
n = p*q
s = []
v = []
for i in range(0, 10):
    s.append(Crypto.Util.number.getPrime(256))
    value = numpy.mod(s[i]**(2), n)
    #value = Crypto.Util.number.inverse(s[i]**2, n)
    v.append(value)

r = random.randint(1, n)
x = (r ** 2) % n
a = [random.randint(0, 1), random.randint(0, 1), random.randint(0, 1), random.randint(0, 1), random.randint(0, 1),
     random.randint(0, 1), random.randint(0, 1), random.randint(0, 1), random.randint(0, 1), random.randint(0, 1)]

y = r
for i in range(0, 10):
    y *= s[i]**a[i]
y = y % n

y_2 = x
for i in range(0, 10):
    y_2 *= v[i] ** a[i]
y_2 = y_2 % n
if y**2 % n == y_2:
    print("yes")
else: print("no")
"""

"""
FEIGE-FIAT-SHAMIR - WORKS
p = 101
q = 23
n = p*q
s = [3, 5, 7]
a = [1, 0, 1]

r = 13
x = r ** 2 % n

y1 = (r * s[0]**a[0] * s[2]**a[2] * s[1]**a[1]) % n

v = [0, 0, 0]

v[0] = (s[0]**2) % n
v[1] = (s[1]**2) % n
v[2] = (s[2]**2) % n

y = (x * v[0]**a[0] * v[2]**a[2] * v[1]**a[1]) % n

if y1**2 % n == y:
    print ("Yes")

"""





"""
def stuff():
    import zmq

    context = zmq.Context()

    #  Socket to talk to server
    print("Connecting to hello world server…")
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://localhost:5555")

    #  Do 10 requests, waiting each time for a response
    for request in range(1):
        print("Sending request %s …" % request)
        socket.send(b"Hello")

        #  Get the reply.
        message = socket.recv()
        print("Received reply %s [ %s ]" % (request, message))
        socket.close()


stuff()


print()
"""