import random
import numpy
import Crypto.Util.number


class ClientAuthenticatorModule:
    def __init__(self):
        pass

    def generate_setup_values(self, password):
        p = Crypto.Util.number.getPrime(1024)
        q = Crypto.Util.number.getPrime(1024)
        n = p*q
        v = self.__generate_v(password, n)
        return v, n

    def __string_to_int(self, password):
        new_string = ""
        for i in range(0, len(password)):
            new_string += str(ord(password[i]))

        return int(new_string)

    def __generate_v(self, password, n):
        random.seed(self.__string_to_int(password))
        s = []
        v = []
        for i in range(0, 10):
            s.append(random.randint(1, 2**256))
            value = numpy.mod(s[i] ** 2, n)
            v.append(value)
        return v

    def generate_s(self, password, n):
        random.seed(self.__string_to_int(password))
        s = []
        for i in range(0, 10):
            s.append(random.randint(1, 2**256))
        return s

    def step_1(self, n):
        r = random.randint(1, n)
        x = (r ** 2) % n
        return x, r

    def step_3(self, a, r, s, n):
        y = r
        for i in range(0, 10):
            y *= s[i] ** a[i]
        y = y % n

        return y

