#coding: utf-8
#!python3
import socket
import threading
import tkinter
import sys

import pywintypes
import win32event
import numpy as np

import binascii
import time
import queue
import pickle

from win32com.directsound import directsound
from tkinter.messagebox import showinfo, askquestion

# executes invariants, probably should mute it later
from cryptolib import Crypto
from galois import make_keys
# [/done]

sys.argv=['chclient']
CONST = 14400
magNum ={'info': 0x00000009, 'message': 0x0000000A,'data': 0x0000000B,
         'login': 0x0000000C, 'synchro': 0x0000000D, 'ginfo': 0x00030009,
         'gmessage': 0x0003000A, 'stream': 0x0000000E}

class ChatGui(tkinter.Tk):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initialize()
        
    def initialize(self):
        self.grid()
        self.logList=['\n']
        self.chatLog = tkinter.StringVar()
        self.chatLog.set('\n'*8)
        self.recLoop=False

        self.initGui()
        self.drawGui()
               
        self.grid_columnconfigure(0, weight=1, minsize=80)
        self.grid_columnconfigure(1, weight=0, minsize=25)
        self.grid_columnconfigure(2, weight=1, minsize=25)
        self.grid_columnconfigure(3, weight=4, minsize=115)
        
        self.grid_rowconfigure(0, weight=10)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=5)
        self.grid_rowconfigure(22, weight=5)
            
        self.minsize(width=300, height=24)
        #self.resizable(True, False)
        self.IPentry.focus_set()

    def initGui(self):
        self.IPentry = tkinter.Entry(self)
        self.IPentry.insert(0,'127.0.0.1:80')
        self.IPentry.bind('<Return>', self.onPressEnter)

        self.conButton = tkinter.Button(self, text=u'ВХОД',
                                command=(lambda: main(self.IPentry.get())))
        self.IDentry = tkinter.Entry(self)
        self.IDentry.bind('<Return>', lambda e: startChat(self.IDentry.get()))
        self.KeyEntry = tkinter.Entry(self)
        self.KeyEntry.bind('<Return>', lambda e: setCryptoKey(self.KeyEntry.get()))
        self.SetKeyButton = tkinter.Button(self, text = u'УСТАНОВИТЬ КЛЮЧ',
                                           command=(lambda: setCryptoKey(self.KeyEntry.get())))
        self.IDButton = tkinter.Button(self, text = u'СОЕДИНИТЬ',
                                       command=(lambda: startChat(self.IDentry.get())))
        self.callButton = tkinter.Button(self, text = u'ЗВОНОК',
                                         command=(lambda: startCall(self.selfname)))
        self.endButton = tkinter.Button(self, text = u'ВЫКЛ',
                                         command=(lambda: self.endCall(True)))

        
        self.label = tkinter.Listbox(self, fg='white', bg='black',
                                     highlightcolor='red', selectmode='SINGLE')
        self.label.bind('<<ListboxSelect>>', lambda e:
                        self.setEntry())
        self.addConfButton = tkinter.Button(self, text=u'ДОБАВИТЬ В КОНФУ',
                                            command=(lambda: self.addConf()))
        self.delConfButton = tkinter.Button(self, text=u'УДАЛИТЬ ИЗ КОНФЫ',
                                            command=(lambda: self.delConf()))

        self.log = tkinter.Label(self, bg='white', fg='black', anchor='nw',
                                 height = 15, textvariable = self.chatLog,
                                 justify=tkinter.LEFT)
        self.chatEntry = tkinter.Entry(self)
        self.chatEntry.bind('<Return>', self.onChatEnter)

        self.confButton = tkinter.Button(self, text=u'ПОСЛАТЬ В КОНФУ',
                                         command=(lambda: self.onConfEnter()))
        self.login=tkinter.Entry(self)
        self.login.bind('<Return>', login)

        self.synch = tkinter.Button(self, text=u'↑↓', command=(lambda:synch()))

    def drawGui(self):
        self.IPentry.grid(column=0, row=0, sticky='W')
        self.conButton.grid(column=1, row=0, sticky = 'W')

    def addConf(self):
        temp = self.label.curselection()
        if temp:
            self.sock.sendMessage(magNum['ginfo'], self.label.get(temp))
        else:
            showinfo(title='Warning!',message='No selected user to add')

    def delConf(self):
        temp = self.label.curselection()
        if temp:
            self.sock.sendMessage(magNum['ginfo'],
                                  '<del>'+self.label.get(temp))
        else:
            showinfo(title='Warning!',message='No selected user to delete')

    def endCall(self, talk=False):
        self.endButton.grid_forget()
        self.callButton.grid(row=2, column=2, sticky='W')
        self.abort_event.set()
        #self.sock.queue.join()
        if talk:
            self.sock.sendMessage(magNum['info'], '|'.join([self.selfname,'term']))

    def initTalking(self):
        self.recorder = SoundRecord(self.sock.desc, None, self.abort_event)
        self.player = SoundPlayer(self.sock.desc, self.sock.queue, self.abort_event)
        self.abort_event.clear()
        self.recorder.start()
        self.abort_event.clear()
        self.player.start()
        self.callButton.grid_forget()
        self.endButton.grid(row=2, column=2, sticky='W')
        
    def setEntry(self):
        idx = self.label.curselection()
        toAdd = self.label.get(idx)
        self.IDentry.delete(0, tkinter.END)
        self.IDentry.insert(0, toAdd)
        
    def onPressEnter(self, event):
        main(self.IPentry.get())

    def onChatEnter(self, event):
        temp=self.chatEntry.get()
        if temp:
            retcode = self.sock.sendMessage(magNum['message'], ': '.join([self.title(), self.chatEntry.get()]))
            if retcode != -1:
                self.enque('YOU: '+self.chatEntry.get())
                self.chatEntry.delete(0, tkinter.END)

    def onConfEnter(self):
        temp=self.chatEntry.get()
        if temp:
            self.sock.sendMessage(magNum['gmessage'], self.chatEntry.get())
            self.enque('< >YOU: '+self.chatEntry.get())
            self.chatEntry.delete(0, 100)

    def enque(self, msg):
        recordsFit=self.log.winfo_height() // 18
        if len(self.logList) < recordsFit:
            self.logList.append(msg)
        else:
            self.logList.pop(0)
            self.logList.append(msg)
        self.logList=self.logList[-recordsFit:]
        self.logList[0]=time.asctime(time.localtime())
        self.chatLog.set('\n'.join(self.logList))
        
class ChatSocket(socket.socket):
    def __init__(self, family, type_of):
        super().__init__(family, type_of)
        self.cryptor = None
        
    def servConnect(self, addr):
        try:
            self.connect(addr)
        except:
            raise ConnectionError('Failed connecting to server')
        else:
            print('Succesfully connected to remote host ', addr)

    def selectPeer(self, ident):
        buff = binascii.hexlify(ident.encode('utf-8'))
        self.send(int.to_bytes(magNum['info'], 4, 'little'))
        self.send(int.to_bytes(len(buff), 4, 'little'))
        self.send(buff)
        print('Asked to connect with ', ident, ' user')

    def sendMessage(self, mag, msg):
        if mag != magNum['stream']:
            msg = msg.encode('utf-8')
        if mag not in (magNum['stream'], magNum['message']):
            msg = binascii.hexlify(msg)
        if mag in (magNum['message'], magNum['stream']):
            
            if self.cryptor is None:
                showinfo(title='No key set',
                         message='No secret key set, won\'t do')
                return -1
            else:
                msg = self.cryptor.message_encrypt(msg)
        self.send(int.to_bytes(mag, 4, 'little'))
        self.send(int.to_bytes(len(msg), 4, 'little'))
        send_bytes = 0
        while send_bytes < len(msg):
            send_bytes += self.send(msg[:CONST])
            msg = msg[CONST:]
            
    def recvMessage(self):
        magic = int.from_bytes(self.recv(4), 'little')
        msgLen = int.from_bytes(self.recv(4), 'little')
        
        msg, recv_bytes = bytearray(), 0
        while recv_bytes < msgLen:
            dump = self.recv(min(msgLen, CONST))
            recv_bytes += len(dump)
            msg.extend(dump)
        if magic in (magNum['message'], magNum['stream']):
            if self.cryptor is None:
                showinfo(title='No key set',
                         message='No secret key set, can\'t do')
                return magic, -1
            else:
                if magNum['message'] == magic:
                    self.cryptor.chopping_flag = 1
                else:
                    self.cryptor.chopping_flag = 0
                msg = self.cryptor.message_decrypt(msg)
                
        if magic not in (magNum['stream'], magNum['message']):
            try:
                msg = binascii.unhexlify(msg)
            except UnicodeDecodeError:
                print('[!] Error decoding, prolly wrong key')
                #msg = 'error: ' + str(msg)
                msg = -1# shouldn't print unreadable messages
        if magic != magNum['stream']:
            msg = msg.decode('utf-8')
        return magic, msg

    def wipe_key(self):
        self.cryptor = None
        
    def recvChat(self):
        mag, message = self.recvMessage()
        if message == -1:
            return #can't do, no key set
        if magNum['synchro'] == mag:
            myGui.label.delete(0,myGui.label.size())
            self.peerList = message.split('|')
            for idx, peer in enumerate(self.peerList):
                myGui.label.insert(idx, peer)
        elif magNum['message'] == mag:
            myGui.enque(message)
        elif magNum['gmessage'] == mag:
            myGui.enque('< >'+message)
        elif magNum['info'] == mag:
            if message.startswith('Requesting'): # ex: Requesting|abobo
                ans = askquestion(title='Do you wanna voicechat ?',
                            message='User ' + message.split('|')[1] +
                            ' is calling you, do you wanna talk ?')
                myGui.sock.sendMessage(magNum['info'],
                                      '|'.join([myGui.selfname, ans]))
                if ans == 'yes':
                    myGui.initTalking()
            elif message == myGui.IDentry.get()+'|term':
                myGui.endCall()
            elif message != myGui.IDentry.get()+'|yes':
                showinfo(title='Refused!', message=
                         'User ' + myGui.IDentry.get() + ' rejected your call')
            else:
                # start streaming voice data
                myGui.initTalking()
                
        elif magNum['stream'] == mag:
            try:
                print('trying to put data in queue')
                val = pickle.loads(message)
                self.queue.put(val)
                print('succesfully loaded', type(val))
            except:
                showinfo(title='Error!', message='Unrecognized error !')
        elif magNum['login'] == mag:
            if message != 'accepted':
                frmtdString='Your login is %s' % message
                showinfo(title = 'Error!', message = frmtdString)
            else:
                #branch for key
                myGui.KeyEntry.grid(column=0, row=2, columnspan=3, sticky='WE')
                myGui.SetKeyButton.grid(column=3, row=2, sticky='W')
                myGui.KeyEntry.focus_set()
                logMessage = 'Connected, please specify your secret key\n'
                showinfo(title='Chat connected ', message=logMessage)
                myGui.title(myGui.login.get())
                myGui.selfname = myGui.login.get()
                myGui.synch.grid(row=1, column=1, sticky='W')
        else:
            print(mag)
            showinfo(title='Warning!', message='Got some wrong data.')
    
    def recvLoop(self):
        while myGui.recLoop:
            try:
                self.recvChat()
            except ConnectionAbortedError:
                print('terminating application')
                return

class BufferDescriptor:
    def __init__(self, milliseconds=200):
        wfxFormat = pywintypes.WAVEFORMATEX()
        wfxFormat.wFormatTag = pywintypes.WAVE_FORMAT_PCM
        wfxFormat.nChannels = 2
        wfxFormat.nSamplesPerSec = 4000
        wfxFormat.nAvgBytesPerSec = 16000
        wfxFormat.nBlockAlign = 4
        wfxFormat.wBitsPerSample = 16

        self.format = wfxFormat
        self.size = 4 * int((self.format.nSamplesPerSec * milliseconds) / 1000)
        self.milliseconds = milliseconds
        self.shape = self.size//4, 2
        self.dtype = np.int16
        self.Fs = 4000
            
class SoundRecord(threading.Thread):
    def __init__(self, descriptor, queue, abort):
        super().__init__(None, self)
        
        d = directsound.DirectSoundCaptureCreate(None, None)

        sdesc = directsound.DSCBUFFERDESC()
        sdesc.dwBufferBytes = descriptor.size
        sdesc.lpwfxFormat = descriptor.format

        _buffer = d.CreateCaptureBuffer(sdesc)

        event = win32event.CreateEvent(None, 0, 0, None)
        notify = _buffer.QueryInterface(directsound.IID_IDirectSoundNotify)
        notify.SetNotificationPositions((directsound.DSBPN_OFFSETSTOP, event))

        self.device = d
        self.sdesc = sdesc
        self.descriptor = descriptor
        self.buffer = _buffer
        self.event = event
        self.notify = notify
        self.abort = abort
        self.queue = queue
        self.timeout = 2 * descriptor.milliseconds / 1000

    def run(self):
        while not self.abort.isSet():
            self.buffer.Start(0)
            win32event.WaitForSingleObject(self.event, -1)
            data = self.buffer.Update(0, self.descriptor.size)
            print(len(data), type(data), self.descriptor.size)
            dump = np.frombuffer(data,
                                 dtype=self.descriptor.dtype).reshape(self.descriptor.shape)
            myGui.sock.sendMessage(magNum['stream'], pickle.dumps(dump))

class SoundPlayer(threading.Thread):
    def __init__(self, descriptor, queue, abort):
        super().__init__(None, self)
        d = directsound.DirectSoundCreate(None, None)
        d.SetCooperativeLevel(None, directsound.DSSCL_PRIORITY)

        sdesc = directsound.DSBUFFERDESC()
        sdesc.dwFlags = directsound.DSBCAPS_STICKYFOCUS | directsound.DSBCAPS_CTRLPOSITIONNOTIFY
        sdesc.dwBufferBytes = descriptor.size
        sdesc.lpwfxFormat = descriptor.format

        _buffer = d.CreateSoundBuffer(sdesc, None)

        event = win32event.CreateEvent(None, 0, 0, None)
        notify = _buffer.QueryInterface(directsound.IID_IDirectSoundNotify)
        notify.SetNotificationPositions((directsound.DSBPN_OFFSETSTOP, event))
        self.device = d
        self.sdesc = sdesc
        self.descriptor = descriptor
        self.buffer = _buffer
        self.event = event
        self.notify = notify
        self.abort = abort
        self.queue = queue
        self.timeout = 0.5 * descriptor.milliseconds / 1000

    def run(self):
        print('trying to play sounds')
        while not self.abort.isSet():
            try:
                data = self.queue.get(block=True, timeout=self.timeout)
                # print shape of data and dtype
                print(data, len(data), type(data))
                self.buffer.Update(0, data.tostring())
                self.buffer.Play(0)
                win32event.WaitForSingleObject(self.event, -1)
            except queue.Empty:
                # full
                pass
        

def startChat(getAnswer='Some data'):
    mysock = myGui.sock
    if getAnswer not in mysock.peerList:
        showinfo(title='Input error!', message ='Wrong client ID')
        return
    mysock.selectPeer(getAnswer)
    myGui.chatEntry.grid(row=23, column=0, columnspan=2, sticky='WE')
    myGui.chatEntry.focus_set()
    myGui.confButton.grid(row=23, column=3, sticky='E')
    myGui.callButton.grid(row=2, column=2, sticky='W')

def setCryptoKey(secret_key):
    mysock = myGui.sock
    
    if len(secret_key) != 32:
        showinfo(title='Size error!',
                 message='Secret key must be exactly 32 chars long')
        return
    CHOPPING_FLAG = 1
    mysock.cryptor = Crypto(make_keys(secret_key), CHOPPING_FLAG)
    showinfo(title='Success!',
             message='Secret key was succesfully set')
    myGui.addConfButton.grid(row=0, column=3, sticky='E')
    myGui.delConfButton.grid(row=2, column=3, sticky='E')
    myGui.IDentry.grid(column=0, row=3, sticky='W')
    myGui.IDentry.focus_set()
    myGui.IDButton.grid(column=1, row=3, sticky='W')
    myGui.log.grid(row=4, column=0, columnspan=4, rowspan=20,
                   sticky='NSWE')
                    
def main(ad):
    try:
        addr = ad.split(':')[0], int(ad.split(':')[1], 10)
    except IndexError:
        showinfo(title='Error!', message='Check formatting!')
        return
    mysock = ChatSocket(socket.AF_INET,socket.SOCK_STREAM)
    myGui.sock = mysock
    mysock.desc = BufferDescriptor(milliseconds=350)
    mysock.queue = queue.Queue(maxsize=100)
    myGui.abort_event = threading.Event()
    try:
        mysock.servConnect(addr)
    except ConnectionError as e:
        showinfo(message = e, title = str(addr[0]))
    else:
        myGui.label.insert(0,'Your login')
        myGui.label.grid(column=3, row=1, sticky='NE')
        myGui.login.grid(row=1, column=0, sticky='W')
        myGui.login.focus_set()

def synch():
    myGui.sock.sendMessage(magNum['synchro'], 'renew')

def startCall(target):
    myGui.sock.sendMessage(magNum['info'], '|'.join(['Requesting',target]))
        
def login(event):
    temp = myGui.login.get()
    myGui.sock.sendMessage(magNum['login'], temp)
    if not myGui.recLoop:
        receiver = threading.Thread(target=myGui.sock.recvLoop, args=())
        myGui.recLoop=True
        receiver.start()
    myGui.label.delete(0)
    myGui.sock.sendMessage(magNum['synchro'], 'renew')
    

if __name__ == '__main__':
    myGui = ChatGui(None)
    myGui.title('Chat GUI')
    myGui.mainloop()
    try:
        myGui.sock.close()
    except:
        print('Bye-bye!')

            


        
