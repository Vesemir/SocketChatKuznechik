#!python3
import socket
import binascii
import threading
import time
import optparse

from datetime import datetime
from string import ascii_letters, digits

magNum ={'info':0x0009, 'message':0x000A,'data':0x000B,
         'login':0x000C, 'synchro':0x000D, 'stream': 0x000E}

screenLock = threading.Semaphore(value=1)
CONST = 14400

class SockDict(dict):
    def __repr__(self):
        temp = {}
        for sock, li in self.items():
            temp[sock.getpeername()] = [val.getpeername() for val in li]
        result = []
        for rec in temp.keys():
            result.extend([str(rec),' :\n'])
            result.extend(str(temp[rec])+'\n')
        return ''.join(result)

class ServSocket(socket.socket):
    def __init__(self):
        self.peerTable = {}
        self.confTable = SockDict()
        self.Chains = []
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
    def addPeer(self, sock, ad):
        self.peerTable[id(sock)]=[sock, ad, '']

    def testNotPassed(self, string):
        'Checks login for correct syntax, length and uniqueness'
        if string in [x[2] for x in self.peerTable.values()]:
            return 'taken'
        for char in string:
            if char not in ascii_letters+digits:
                return 'wrong syntax'
        if len(string) > 23:
            return 'too long'
        if len(string.strip()) < 5 or not string:
            return 'too small'
        return False

    def curTime(self):
        print(datetime.today().isoformat(),)
        
    def recvData(self, sock):
        magic = int.from_bytes(sock.recv(2),'little')
        gid = int.from_bytes(sock.recv(2), 'little')
        dataLen = int.from_bytes(sock.recv(4),'little')
        data, recv_bytes = bytearray(), 0
        while recv_bytes < dataLen:
            dump = sock.recv(min(dataLen, CONST))
            recv_bytes += len(dump)
            data.extend(dump)
        if magic not in (magNum['stream'], magNum['message']):
            return magic, gid, binascii.unhexlify(data).decode('utf-8')
        else:
            return magic, gid, data

    def sendData(self, sock,  magic, data, gid=0):
        self.curTime()
        #print(magic, gid, data)
        if magic not in (magNum['stream'], magNum['message']):
            data = binascii.hexlify(data.encode('utf-8'))
        dataLen=len(data)
        sock.send(int.to_bytes(0x10000*gid+magic, 4, 'little'))
        sock.send(int.to_bytes(dataLen, 4, 'little'))
        sent_bytes = 0
        while sent_bytes<dataLen:
            sent_bytes += sock.send(data[:CONST])
            data = data[CONST:]
    
    def sendPeerList(self, sock):
        toSend = '|'.join([x[2] for x in self.peerTable.values()])
        self.sendData(sock, magNum['synchro'],   toSend)

    def chainHandler(self, source, dest):
        try:
            while True:
                mag, gid, buff=self.recvData(source)
                #screenLock.acquire()
                #print('[+]magic:', mag, '[+]gid: ',gid, '[+] ', buff)
                #screenLock.release()
                tempDic={x[2]: y for y, x in self.peerTable.items()}
                if magNum['message'] == mag:
                    if not gid:
                        self.sendData(self.peerTable[dest][0], mag, buff)
                        #': '.join([self.peerTable[id(source)][2], buff])
                        #for name : msg, but msg is encrypted, and
                        #sending name in plaintext is dumb then
                    elif gid == 3:
                        for group in self.confTable.values():
                            if source in group:
                                for peer in group:
                                    if peer!=source:
                                        self.sendData(peer, mag, buff, gid)
                elif magNum['stream'] == mag:
                    self.sendData(self.peerTable[dest][0], mag, buff)
                elif magNum['info'] == mag:
                    if not gid:
                        if '|' not in buff:
                            dest = tempDic[buff]
                        else:
                            self.sendData(self.peerTable[dest][0], mag, buff)
                    elif gid == 3:
                        if buff.find('<del>') == -1:
                            var = self.peerTable[tempDic[buff]][0]
                            try:
                                temp = self.confTable[source]
                            except KeyError:
                                self.confTable[source] = [source]
                            else:
                                if var not in temp:
                                    temp.append(var)
                        else:
                            var = self.peerTable[tempDic[buff.split('>')[1]]][0]
                            try:
                                temp = self.confTable[source]
                                temp.remove(var)
                                if not self.confTable[source]:
                                    del self.confTable[source]
                            except (KeyError, ValueError):
                                screenLock.acquire()
                                print('[!]WARNING[!] Host at ',
                                      source,' is forging requests.')

                                screenLock.release()
                        screenLock.acquire()
                        print(self.confTable)
                        screenLock.release()
                elif magNum['synchro'] == mag:
                    self.sendPeerList(source)
                elif magNum['login'] == mag:
                    temp = self.testNotPassed(buff)
                    if temp:
                        self.sendData(source, magNum['login'], temp)
                    else:
                        self.peerTable[id(source)][2] = buff
        except ConnectionResetError:
            screenLock.acquire()
            self.curTime()
            print('peer at IP:%s , port:%s terminated connection'
                  %(source.getsockname()[0],source.getpeername()[1]))
            screenLock.release()
            del self.peerTable[id(source)]
            if source in self.confTable.keys():
                del self.confTable[source]
                for group in self.confTable.values():
                    if source in group:
                        group.remove(source)
            return
    def chainHandle(self):
        """Goes through Chains, taking any entry and creating threads for\
appropriate source and target clients
        """
        while True:
            wkinChains=[]
            time.sleep(2)
            try:
                [source, dest] = self.Chains.pop()
            except IndexError:
                time.sleep(3)
            else:
                if [source, dest] not in wkinChains:
                    upChat=threading.Thread(target=self.chainHandler,
                                            args=(source, dest))
                    upChat.start()
                    wkinChains.append([source, dest])
                    
    def handleClient(self, sock):
        'Checks login and accepts client\'s desired chat partner'
        try:
            while True:
                mag, gid, name = self.recvData(sock)
                print(mag, gid, name)
                if magNum['login'] == mag:
                    temp = self.testNotPassed(name)
                    if not temp:
                        self.sendData(sock, magNum['login'], 'accepted')
                        break
                    else:
                        self.sendData(sock, magNum['login'], temp)
            self.peerTable[id(sock)][2] = name
            while True:
                mag, gid, work = self.recvData(sock)
                if magNum['synchro'] == mag and work == 'renew':
                    self.curTime()
                    print(mag, 'WHAT')
                    self.sendPeerList(sock)
                    print("SENDING NEW PEER LIST")
                elif magNum['login'] == mag:
                    temp = self.testNotPassed(work)
                    if not temp:
                        self.sendData(sock, magNum['login'],'accepted')
                        self.peerTable[id(sock)][2] = work
                    else:
                        self.sendData(sock, magNum['login'], temp)
                elif magNum['info'] == mag:
                    tempDict={cred[2]:ident for ident, cred in self.peerTable.items()}
                    exsock = tempDict[work]
                    self.Chains.append((sock, exsock))
                    break
        except (ConnectionAbortedError, ConnectionResetError):
                screenLock.acquire()
                self.curTime()
                print('peer at IP:%s , port:%s aborted connection'
                      %(sock.getsockname()[0], sock.getpeername()[1]))
                screenLock.release()
                print(self.peerTable)
                del self.peerTable[id(sock)]
                print(self.peerTable)
                return
                        
    def serveForever(self, addr):
        self.bind(addr)
        self.curTime()
        self.listen(8)
        print('Starting to listen at ', self.getsockname(),' on port ',addr[1], '...')
        chaining = threading.Thread(target = self.chainHandle, args=())
        chaining.start()
        while True:
            clsock, addr = self.accept()
            print('Address', addr,' connected,\
 adding to peer table and sending peer list')
            self.sendPeerList(clsock)
            self.addPeer(clsock , addr)
            task = threading.Thread(target = self.handleClient, args=(clsock,))
            task.start()


def main():
    parser = optparse.OptionParser("usage %prog -A <interface>[default:'']"+
                                   " -p <port>[default:80]")
    parser.add_option('-A', dest='ifaceIP', type=str,
                      help='specify required IP to serve (default: eth0')
    parser.add_option('-p', dest='ifacePORT', type=int,
                      help='specify required port to serve (default:80)')
    options, args = parser.parse_args()
    if '/?' in args:
        print(parser.usage)
        exit(0)
    IP, PORT = options.ifaceIP, options.ifacePORT
    if not IP:
        print('No IP specified... Starting service on default IP')
        IP = ''
    if not PORT:
        print('No port specified... Starting service on default port')
        PORT = 80
    addr=(IP, PORT)
    mysock=ServSocket()
    print('Trying to start service on %s:%d' % (IP, PORT))
    try:
        mysock.serveForever(addr)
    except OSError as e:
        print("Couldn't start service on required address: ",e)
    
if __name__ == '__main__':
    main()
    
