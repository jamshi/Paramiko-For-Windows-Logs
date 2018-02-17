#!/usr/bin/env python
import sys
import psutil
import base64
from Crypto.Cipher import AES
from Crypto import Random
import argparse
import time

#import win32evtlogutil


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class Client:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ))

    def readlog( self, computer = None, logType="Security"):
        h=win32evtlog.OpenEventLog(computer, logType)
        #print h
        numRecords = win32evtlog.GetNumberOfEventLogRecords(h)
        num=0
        while 1:
            objects = win32evtlog.ReadEventLog(h, win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            if not objects:
                break
            for object in objects:
                msg = win32evtlogutil.SafeFormatMessage(object, logType)
                try:
                    sys.stdout.write("%s\n" % ('-' * 50))
                    sys.stdout.write("%s\n" % (self.encrypt(msg)))
                except UnicodeError as e:
                    sys.stdout.write("%s\n" % (self.encrypt(repr(msg))))
                    #sys.exit()
            num = num + len(objects)
            if num > 100:
                break
        win32evtlog.CloseEventLog(h)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cipherkey", help="specifies the AES encryption key",
                    action="store")
    args = parser.parse_args()
    
    if len(args.cipherkey) < 16:
        sys.stdout.write("%s\n" % ('Cipher key should be 16 bytes in length'))
        sys.exit()
    
    aes = Client(args.cipherkey)
    cpu_usage = psutil.cpu_percent()
    sys.stdout.write("%s\n" % (str(aes.encrypt(str(cpu_usage)))))

    memory_usage = psutil.virtual_memory()
    sys.stdout.write("%s\n" % (str(aes.encrypt(str(memory_usage.percent)))))
    
    if sys.platform == "win32":
        try:
            import win32evtlogutil
            import win32evtlog
            import win32api
            import win32con
            aes.readlog()
        except Exception as e:
            print e
        
    
    
            
