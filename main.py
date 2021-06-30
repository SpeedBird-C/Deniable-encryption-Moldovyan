import os
import random
import string
from timeit import default_timer as timer
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random import random
##############
from PyQt5 import QtWidgets, QtGui,QtCore
import sys
global window
import MainWindow
import Encrypt_settings_window
import Decrypt_settings_window
##############

import pickle
import math
from Cryptodome.Util.number import *

def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def prep_data(u, str):
    d = str.encode("utf-8")
    res = list()
    for i in range(0, len(d), u):
        res.append(d[i:i + u])
    return res


def back_prep_data(data, u=1):
    res = b''
    for d in data:
        res += d.to_bytes(u, 'big')
    return res.decode("utf-8")


# data1 = "Hello world! it is pretty message! I has written it for sure!  "
# data2 = "Goodbye everyone! you cannot prove that it is not a randomness!"
#data1 = "Hello world! it is pretty message! I has written it for sure THIS IS JUST A TEXT!  " # секретный шифртекст вводит пользователь
#data2 = "Goodbye everyone! you cannot prove that it is not a randomness!" #фальшивый шифрттекст  вводит пользователь
lenght_of_str=0
iv = b'Key byte sixteen' # не изменять
#key1 = b'Sixteen byte key'
#key1 = b'Sixteen byte keydgfhfgj'  #вводит пользователь
#key2 = b'Second evil key!' # вводит пользователь


def enc(key_sec, key_fake, iv, data_sec, data_fake, u=8):
    cipher_sec = AES.new(byte_xor(key_sec, iv), AES.MODE_ECB)
    cipher_fake = AES.new(byte_xor(key_fake, iv), AES.MODE_ECB)

    n = 128
    k = n - u

    ds = prep_data(u // 8, data_sec)
    df = prep_data(u // 8, data_fake)
    c = list(ds)

    i = 0
    j = 0
    r = random.getrandbits(k)
    while 1:
        c[i] = (cipher_fake.encrypt(df[i] + r.to_bytes(k // 8, "big")))
        t = cipher_sec.decrypt(c[i])[0:0 + (u // 8)]
        if t != ds[i]:
            if j < 2 ** (2 * u):
                j += 1
                r += 1
                continue
            else:
                print("Encryption of the pair of input data blocks ti and mi has not been fulfilled!")
        if i < len(ds) - 1:
            r = random.getrandbits(k)
            i += 1
            j = 0
            print(i)
        else:
            break
    return c


def dec(key, iv, data):
    cipher = AES.new(byte_xor(key, iv), AES.MODE_ECB)
    w = list(data)
    for i in range(0, len(data)):
        w[i] = cipher.decrypt(data[i])[0]
    print(w)
    return w



def my_hash(d):
    return SHA3_256.new().update(d).digest()

def save(key1,key2,iv,test_enc):
    whole_enc_bytes = b''
    for chunk in test_enc:
        whole_enc_bytes = whole_enc_bytes + chunk
    f = open("myfile.bin", "wb")

    f.write(whole_enc_bytes) # записываем шифртекст
    f.close()

    f=open("mykey1.bin","wb+")
    f.write(key1)
    f.close()

    f=open("mykey2.bin","wb")
    f.write(key2)
    f.close()

    f=open("myIV.bin","wb")
    f.write(iv)
    f.close()
    global lenght_of_str
    temp=lenght_of_str
    with open('length.txt', 'w') as f:
        f.write(str(temp))
        f.flush()

def read():
    test1 = b''
    with open("myfile.bin", "rb") as file:
        test1 = file.read()
    file.close()
    amount_of_lists = int(len(test1) / 16)  # количество листов в листе
    k = list()
    for i in range(amount_of_lists):
        k.append(i)

    test_list = list(k)

    with open("myfile.bin","rb") as file:
        for j in range(amount_of_lists):
           test_list[j] = file.read(16) #шифрт текст в готовм виде

    key1=b''
    with open("mykey1.bin","rb") as file:
        key1 = file.read()
    file.close()

    key2=b''
    with open("mykey2.bin","rb") as file:
        key2 = file.read()
    file.close()

    iv=b''
    with open("myIV.bin","rb") as file:
        iv = file.read()
    file.close()

    return key1,key2,iv,test_list


def check(data1,data2,lenght_of_str):
    if (len(data1) != len(data2)):  # если текста не равны
        if (len(data1) > len(data2)):  # если первый больше, то дополняем второй
            raznost = len(data1) - len(data2)
            lenght_of_str = len(data2)  # запоминаем оригинальную длину до дополнения
            i = 0
            for i in range(raznost):
                data2 = data2 + str("@")  # добиваем значениями
        else:
            if len(data1) < len(data2):  # если первый меньше вторго
                lenght_of_str = len(data1)  # запоминаем оригинальную длину до дополнения
                raznost = len(data2) - len(data1)
                i = 0
                for i in range(raznost):
                    data1 = data1 + str("@")  # добиваем значениями
    return data1,data2,lenght_of_str

def answer(all_str,test_dec,data1_backup,data2_backup,lenght_of_str):
    if(data1_backup==data2_backup):
        return data1_backup
    for letter in test_dec:
        all_str = all_str + chr(letter)

    if (all_str != data1_backup and all_str != data2_backup):
        all_str = all_str[:lenght_of_str]
    return all_str

class ExampleApp(QtWidgets.QMainWindow,MainWindow.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.EncryptButton.clicked.connect(self.on_pushButon1)
        self.Encrypt_dialog=Encrypt_settings()
        self.DecryptButton.clicked.connect(self.on_pushButon2)
        self.Decrypt_dialog=Decrypt_settings()


    def on_pushButon1(self):
        self.Encrypt_dialog.show()
    def on_pushButon2(self):
        self.Decrypt_dialog.show()



class Encrypt_settings(QtWidgets.QDialog,Encrypt_settings_window.Ui_Encrypt_settings_window):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButtonEncryptFinally.clicked.connect(self.EncryptAll)
        #data1=self.plainText1Edit.document().toPlainText()

    def EncryptAll(self):
        data11=self.plainText1Edit.document().toPlainText()
        data22=self.plainText2Edit.document().toPlainText()
        f = open("data1_backup.txt", "w")
        f.write(data11)
        f.close()
        f = open("data2_backup.txt", "w")
        f.write(data22)
        f.close()
        key11=self.text1Key1Edit.document().toPlainText().encode()
        key22=self.text1Key2Edit.document().toPlainText().encode()
        global lenght_of_str
        data11, data22, lenght_of_str = check(data11, data22, lenght_of_str)
        test_enc = enc(key11, key22, iv, data11, data22)
        save(key11, key22, iv, test_enc)
        # temp=5
        # f = open("length.txt", "w")
        # f.write(temp)
        # f.close()
        self.close()

class Decrypt_settings(QtWidgets.QDialog,Decrypt_settings_window.Ui_Decrypt_settings_window):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushDecryptButton.clicked.connect(self.DecryptOne)
        #keyDec=self.plainKeyEdit.document().toPlainText().encode()
    def DecryptOne(self):
        self.textBrowser.clear()
        key11, key22, iv1, test_list = read()
        keyDec = self.plainKeyEdit.document().toPlainText().encode()
        if(keyDec!=key11 and keyDec!= key22):
            self.textBrowser.append("Wrong password!")
        else:
            with open("data1_backup.txt", "r") as file:
                data11_backup = file.read()
            file.close()
            with open("data2_backup.txt", "r") as file:
                data22_backup = file.read()
            file.close()
            test_dec = dec(keyDec, iv1, test_list)
            all_str = ''
            global lenght_of_str
            if(lenght_of_str==0):
                with open("length.txt", "r") as file:
                     lenght_of_str= file.read()
                     lenght_of_str=int(lenght_of_str)

            all_str = answer(all_str, test_dec, data11_backup, data22_backup, lenght_of_str)
            self.textBrowser.append(all_str)






def main():
    app=QtWidgets.QApplication(sys.argv)
    global window
    window=ExampleApp()
    window.show()
    app.exec()





# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
    # print(len(data1))
    # print(len(data2))
    # data1_backup = data1
    # data2_backup = data2
    #
    # #lenght_of_str = 0
    #
    # data1,data2,lenght_of_str=check(data1,data2,lenght_of_str)
    #
    # test_enc = enc(key1, key2, iv, data1, data2)
    #
    # save(key1,key2,iv,test_enc)
    #
    #
    # key1,key2,iv,test_list=read()
    #
    #
    # test_dec = dec(key1, iv, test_list)
    #
    # all_str = ''
    #
    # all_str=answer(all_str,test_dec,data1_backup,data2_backup,lenght_of_str)
    #
    # print(all_str)
    #
    #
    #



