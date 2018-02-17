#!/usr/bin/env python
import sys
import paramiko
import base64
from Crypto.Cipher import AES
from Crypto import Random
import sqlite3
import uuid
import os
import smtplib
import argparse
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

sqlite_file = './database.sqllite'
conn = sqlite3.connect(sqlite_file)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS TBL_CLIENTS (
                ClientIP text NOT NULL,
                CPU REAL DEFAULT 0,
                Memory REAL DEFAULT 0,
                LogFile text);''')
conn.commit()
conn.close()

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]



class Server:
    
    def __init__( self, key, filepath=None, xtraCommands=None, pythonenv=None, smtpserver=None,\
                  smtpusername=None, smtppassword=None, smtpttls=False ):
        self.key = key
        self.filepath = filepath
        self.xtraCommands = xtraCommands
        self.pythonenv = pythonenv
        self.smtpserver = 'smtp.gmail.com:587' if smtpserver is None else smtpserver
        self.smtpusername = '<provide your emailid>' if smtpusername is None else smtpusername
        self.smtppassword = '<provide your password>' if smtppassword is None else smtppassword
        self.smtpttls = smtpttls
        
    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ))
    
    def decrypt( self, enc ):
        try:
            enc = base64.b64decode(enc)
            iv = enc[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv )
            return unpad(cipher.decrypt( enc[16:] ))
        except:
            return enc
        
    def send_mail(self, email, alert_msg, logfile):
        msg = MIMEMultipart()
        msg['From'] = 'from@fromdomain.com'
        msg['To'] = email
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = "System Alert"
        message = """From: From SYstem <from@fromdomain.com>
                        To: To Person <to@todomain.com>
                        Subject: System Alert

                        This is a system generated alert!
                        {}
                  """.format(alert_msg)
        
        msg.attach(MIMEText(message))
        with open(logfile, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=basename(logfile)
            )
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(logfile)
            msg.attach(part)
        try:
           smtpObj = smtplib.SMTP(self.smtpserver)
           smtpObj.ehlo()
           if self.smtpttls:
               smtpObj.starttls()
           smtpObj.login(self.smtpusername, self.smtppassword)
           smtpObj.sendmail('from@fromdomain.com', email, msg.as_string())         
           print "Successfully sent email from {}".format(self.smtpusername)
        except Exception as ex:
           print ex
           raise Exception("Error: unable to send email")

    def connect(self, ip, uname, pwd, port):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=uname, password=pwd, port=port)
            print "Connection established to {}".format(ip)
        except Exception as ex:
            raise Exception("Error: Couldn't establish a SSH connection")

        print "Attempting SFTP put to {}, Please wait...".format(ip)
        try:
            #SFTP File Copying
            sftp = ssh.open_sftp()
            sftp.put('./client.py', self.filepath)
            sftp.close()
            #END SFTP
        except Exception as ex:
            raise Exception("Error: SFTP access failed")
        
        final_cmds = self.xtraCommands if self.xtraCommands is not None else ''
        final_cmds += ' && ' + self.pythonenv if self.pythonenv is not None else ' && python '
        
        #if windows we have to use cmd /c "{commands}"
        final_cmds =  'cmd /c "' + final_cmds + ' {1} -c {0}"'.format(self.key, self.filepath)
        print 'Executing Command on System => {}'.format(final_cmds) 
        stdin, stdout, stderr = ssh.exec_command(final_cmds)
        
        channel = stdout.channel
        buff_size = 1024
        stdout_str = ""
        stderr_str = ""

        while not channel.exit_status_ready():
            if channel.recv_ready():
                stdout_str += channel.recv(buff_size)
            if channel.recv_stderr_ready():
                stderr += channel.recv_stderr(buff_size)

        exit_status = channel.recv_exit_status()
        stdout_str = stdout_str.split("\n")
        cpu_percent = self.decrypt(stdout_str.pop(0))
        memory_percent = self.decrypt(stdout_str.pop(0))
        
        print "Reading security audit log file from system at {}...".format(ip)
        if not os.path.exists('Logs'):
            os.makedirs('Logs')
        unique_filename = 'Logs\\' + str(uuid.uuid4()) + '.log'
        dir_path = os.path.dirname(os.path.realpath(__file__))
        unique_filename = os.path.join(dir_path, unique_filename)
        f = open(unique_filename,"w+")
        for lines in stdout_str:
            f.write(self.decrypt(lines))
        f.close()
        print "Audit log file name for system at {0} is {1}".format(ip, unique_filename)

        print "Connecting to Database... "
        try:
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()
            c.execute("INSERT INTO TBL_CLIENTS (ClientIP, CPU, Memory, LogFile) VALUES(?, ?, ?, ?)", (ip, cpu_percent, memory_percent, unique_filename))
            conn.commit()
            conn.close()
            print "Logged to Database successfully"
        except Exception as ex:
            raise Exception("Error: Failed to insert record to database")
        
        ssh.close()
        print ''.join(stderr)
        print "SSH connection to system at {1} exited with status {0}".format(exit_status, ip)
        return cpu_percent, memory_percent, unique_filename
        


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--xtraCommands", help="Commands to execute before client script execution",
                    action="store")
    parser.add_argument("-p", "--pythonenv", help="Python path to invoke",
                    action="store")
    
    # SMTP related args
    parser.add_argument('-s', '--smtpserver', help='Provide the smtp server to use for sending email', action="store")
    parser.add_argument('-u', '--smtpusername', help='Username to login for smtp', action="store")
    parser.add_argument('-w', '--smtppassword', help='Password to login for smtp', action="store")
    parser.add_argument('-t', '--nosmtpttls', dest='smtpttls', help='Turn off TLS for SMTP', action='store_false', default=True)
    # END
    
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-f', '--filepath', help='Location for client script', required=True, action="store")
    requiredNamed.add_argument("-c", "--cipherkey", help="specifies the AES encryption key",
                    action="store", required=True)
    
    args = parser.parse_args()
    
    if args.cipherkey== None or len(args.cipherkey) != 16:
        sys.stdout.write("%s\n" % ('Cipher key should be 16 bytes in length'))
        sys.exit()
    
    server = Server(args.cipherkey, args.filepath, args.xtraCommands, args.pythonenv, args.smtpserver, args.smtpusername, args.smtppassword, args.smtpttls)
    import xml.etree.ElementTree
    e = xml.etree.ElementTree.parse('config.xml').getroot()
    for atype in e.findall('client'):
        try:
            print '-'*100
            memory_alert = ""
            cpu_alert = ""
            for alert in atype.findall('alert'):
                if alert.get('type').lower() == 'memory':
                    memory_alert = float(alert.get('limit')[:-1])
                if alert.get('type').lower() == 'cpu':
                    cpu_alert = float(alert.get('limit')[:-1])
        
            cpu_percent, memory_percent, logfile = server.connect(atype.get('ip'), atype.get('username'), atype.get('password'), int(atype.get('port')))
            email_msg = ""
            if float(memory_percent) >= memory_alert:
                email_msg += "Your system memory usage is beyond the limit, The system memory usage at the moment is {}.\n Please take action immediately.\n"\
                             .format(str(memory_percent))
            elif float(cpu_percent) >= cpu_alert:
                email_msg += "Your system processor usage is beyond the limit, The CPU usage at the moment is {}.\n Please take action immediately.\n"\
                             .format(str(cpu_percent))
            server.send_mail(atype.get('mail'), email_msg, logfile)
            print '-'*100
        except Exception as ex:
            print ex
            print '-'*100
    exit()
        
    
    
            
