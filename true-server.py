# -*-coding:utf-8 -*-

import os
import uuid
import hashlib 
import socket
import rsa
from Crypto.Cipher import AES
import time

address = ('192.168.43.97',33334)
k='d26a53750bc40b38b65a520292f69306'
tid='7db33e3e8dba11ea907b54ee75d57ea6'
ids='c2add694bf942dc77b376592d9c862cd'

#AES encryption. BEC method is not recommended.
class ASEUtil(object): 
    @staticmethod
    def encrypt(key, text):
        bs = AES.block_size
        def pad(s): return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(text)).encode("hex")
    @staticmethod
    def decrypted(key, Enc_Delta):
        cipher = AES.new(key, AES.MODE_ECB)
        def un_pad(s): return s[0:-ord(s[-1])]
        return un_pad(cipher.decrypt(Enc_Delta.decode("hex")))

def MD5(s1):
    md = hashlib.md5()
    md.update(s1)
    return md.hexdigest()

#generate PK,PR
def create_keys(UAID):  
    (pubkey, privkey) = rsa.newkeys(1024)
    pub = pubkey.save_pkcs1()
    with open('public.pem','wb+')as f:
        f.write(pub) 
    pri = privkey.save_pkcs1()
    pri = pri+UAID
    with open('private.pem','wb+')as f:
        f.write(pri)

#server-client
def socket_sc():

    #waiting client's connection
    global address,k,tid,ids
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(address)
    s.listen(5)
    print('Waiting connect...')
    tcpCliSock, addr = s.accept()
    print('connected from client')
    ma1 = tcpCliSock.recv(1024)#receive ma1

    #confirm client
    if len(ma1)>0: 
        #print('recv ma1:',ma1)
        ma1 = ma1.split(',')
        v0 = ma1[0] 
        n_x = ma1[1]
        tid_r = ma1[2]
        if tid_r == tid:#check id of client
            k_r = k
            n_c = ''.join(chr(ord(a)^ord(b)) for a,b in zip(n_x,k_r))#calculate n_c,32bytes
            v0_cal_temp = n_c+tid_r+k_r
            v0_cal = MD5(v0_cal_temp)
            if v0_cal == v0: #check v0 and finish confirmation
                print('verified client')

                #generate new values
                tid_new = ''.join(str(uuid.uuid1()).split("-")).upper() #set new tid
                tid = tid_new #in reality old tid could be valid in matching for 1 or 2 times to against falied transferring from server to client.
                n_s=''.join(str(uuid.uuid4()).split("-")).upper() #random string n_s,32bytes
                tts = '86400000' #expire in 24h
                UAID = ''.join(str(uuid.uuid1()).split("-")).upper()#UAID for PK/PR
                create_keys(UAID) #{PK,PR}
                with open('public.pem', 'rb') as publickfile:
                    p = publickfile.read()
                pubkey_temp = p

                #Calculate ma2 to client
                X_temp = n_s+tts+tid_new+UAID+pubkey_temp
                X = ASEUtil.encrypt(k_r,X_temp) 
                R_temp = X+k_r+ids+n_c
                R = MD5(R_temp)
                ma2 = X+','+R
                #print('send ma2:',ma2)	
                tcpCliSock.send(ma2) 

                #For ma3 to robot
                QRcode_temp = n_s +tts + k_r
                QRcode = MD5(QRcode_temp)
                tts_start = int(time.time()) #QRcode life start time
                Enc_Delta_temp = QRcode + ids + str(tts) + str(tts_start) 
                #print('step3_QRcode_delta:',QRcode)
                pubkey = rsa.PublicKey.load_pkcs1(pubkey_temp)#read public key
                Enc_Delta = rsa.encrypt(Enc_Delta_temp, pubkey)
            else:
                print('error connection')	
        else:
            print('error connection')	
    else:
        print('error connection')	
    tcpCliSock.close()
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    return Enc_Delta

#server-robot
def socket_sr(Enc_Delta):
    addr = ('192.168.43.69',33334)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.settimeout(10)
    s.connect(addr)
    ma3 = Enc_Delta
    #print('send ma3:',ma3)
    s.sendall(ma3)
    s.shutdown(socket.SHUT_RDWR)
    s.close

if __name__ == '__main__':
    while(1):
        Enc_Delta = socket_sc()
        os.system('sshpass -p ubuntu scp /home/prome/Desktop/private.pem ubuntu@192.168.43.69:/home/ubuntu/Desktop')#assumption of secure channal transferring.
        socket_sr(Enc_Delta)
        raw_input()
