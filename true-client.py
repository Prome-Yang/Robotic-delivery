# -*- coding: utf-8 -*-

import socket
import sys
import hashlib  
import qrcode
import uuid
from Crypto.Cipher import AES
import rsa

address = ('192.168.43.97', 33334)
k='d26a53750bc40b38b65a520292f69306'
tid='7db33e3e8dba11ea907b54ee75d57ea6'
ids='c2add694bf942dc77b376592d9c862cd'

class ASEUtil(object): #AES
    @staticmethod
    def encrypt(key, text):
        bs = AES.block_size
        def pad(s): return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
        cipher = AES.new(key, AES.MODE_ECB)  
        return cipher.encrypt(pad(text)).encode("hex")
    @staticmethod
    def decrypted(key, cipher_text):
        cipher = AES.new(key, AES.MODE_ECB)
        def un_pad(s): return s[0:-ord(s[-1])]
        return un_pad(cipher.decrypt(cipher_text.decode("hex")))

def MD5(s1):
    md = hashlib.md5()
    md.update(s1)
    return md.hexdigest()

#client-server and generate QRcode
def socket_client():
    #send request to server
    global address,k,tid,ids
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.settimeout(10)
    s.connect(address)
    n_c=''.join(str(uuid.uuid4()).split('-')).upper()
    n_x=''.join(chr(ord(a)^ord(b)) for a,b in zip(n_c,k))
    v0_temp = n_c+tid+k
    v0=MD5(v0_temp)
    ma1=v0+','+n_x+','+tid
    #print('send ma1:',ma1)
    s.sendall(ma1)

    #receive message
    while(1):#loop to avoid false servers(attackers)
        
        #check correct server
        ma2=s.recv(1024)
        #print('recv ma2:',ma2)
        ma2=ma2.split(',')
        X = ma2[0]
        R = ma2[1]
        R_cal_temp = X+k+ids+n_c
        R_cal = MD5(R_cal_temp)
        if R_cal == R:
 
            #extract information
            decrypt_x = ASEUtil.decrypted(k,X)	
            n_s = decrypt_x[:32]
            tts = decrypt_x[32:40]
            tid_new = decrypt_x[40:72]
            UAID = decrypt_x[72:104]
            pubkey_temp = decrypt_x[104:]
            
            #generate QRcode
            QRcode_temp = n_s+tts+k
            QRcode = MD5(QRcode_temp)
            pubkey = rsa.PublicKey.load_pkcs1(pubkey_temp)
            Enc_Delta = rsa.encrypt(QRcode,pubkey)
            Enc_delta_and_UAID = Enc_Delta+UAID #QRcode information
            img = qrcode.make(Enc_delta_and_UAID)
            img.save("QRcode.png")
            img.show()
            #print('tid_new:',tid_new)
            break 
    s.shutdown(socket.SHUT_RDWR) 
    s.close()
    #return Enc_delta_and_UAID
    return 0

#def show_ma4(Enc_delta_and_UAID):
    #ma4=Enc_delta_and_UAID
    #print('send ma4:',ma4)

if __name__ == '__main__':
    while(1):	
        Enc_delta_and_UAID = socket_client()
        #show_ma4(Enc_delta_and_UAID)
        raw_input()
