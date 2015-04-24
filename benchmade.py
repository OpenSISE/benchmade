#!/usr/bin/env python
# -*- coding utf-8 -*-
# Email: lyleaks@gmail.com

import sys
import socket
import struct
import urllib2
import time
import hashlib

def upnet(sock, packet):
    sock.sendto(packet, ('172.16.1.180', 3848))
    upnet_ret = sock.recv(4096)
    upnet_ret = [i for i in struct.unpack('B' * len(upnet_ret), upnet_ret)]
    decrypt(upnet_ret)
    session_len = upnet_ret[22]
    session = upnet_ret[23:session_len + 23]
    message_len = upnet_ret[session_len + 30]
    message = upnet_ret[session_len + 31:message_len + session_len + 31]
    message = ''.join([struct.pack('B', i) for i in message]).decode('gbk')
    print message
    print 'Ctrl + C to quit'
    return session
    
def breathe(sock, mac_address, ip, session, index):
    time.sleep(30) 
    while True:
        breathe_packet = generate_breathe(mac_address, ip, session, index)
        sock.sendto(breathe_packet, ('172.16.1.180', 3848))
        try:
            breathe_ret = sock.recv(4096)
        except socket.timeout:
            continue
        else:
            status = struct.unpack('B' * len(breathe_ret), breathe_ret)
            if status[20] == 0:
                sock.close()
                main()
            index += 3
            try:
                time.sleep(30)
            except KeyboardInterrupt:
                downnet()
                sock.close()
                sys.exit()
            
def downnet():
    payload = 'imageField%26%2346%3By=37&imageField%26%2346%3Bx=97'
    urllib2.urlopen('http://1.1.1.1/userout.magi', payload)
    
def encrypt(buffer):
    for i in range(len(buffer)):
        buffer[i] = (buffer[i] & 0x80) >> 6 | (buffer[i] & 0x40) >> 4 | (buffer[i] & 0x20) >> 2 | (buffer[i] & 0x10) << 2 | (buffer[i] & 0x08) << 2 | (buffer[i] & 0x04) << 2 | (buffer[i] & 0x02) >> 1 | (buffer[i] & 0x01) << 7

def decrypt(buffer):
    for i in range(len(buffer)):
        buffer[i] = (buffer[i] & 0x80) >> 7 | (buffer[i] & 0x40) >> 2 | (buffer[i] & 0x20) >> 2 | (buffer[i] & 0x10) >> 2 | (buffer[i] & 0x08) << 2 | (buffer[i] & 0x04) << 4 | (buffer[i] & 0x02) << 6 | (buffer[i] & 0x01) << 1        
        
def generate_upnet(mac, ip, user, pwd):
    packet = []
    packet.append(1)
    packet_len = len(user) + len(pwd) + 66
    packet.append(packet_len)
    packet.extend([i * 0 for i in range(16)])
    packet.extend([7, 8])
    packet.extend([int(i, 16) for i in mac.split('-')])
    packet.extend([1, len(user) + 2])
    packet.extend([ord(i) for i in user])
    packet.extend([2, len(pwd) + 2])
    packet.extend([ord(i) for i in pwd])
    packet.extend([9, len(ip) + 2])
    packet.extend([ord(i) for i in ip])
    packet.extend([10, 10, 105, 110, 116, 101, 114, 110, 101, 116, 14, 3, 0, 31, 7, 51, 46, 54, 46, 53])
    md5 = hashlib.md5(''.join([struct.pack('B', i) for i in packet])).digest()
    packet[2:18] = struct.unpack('16B', md5)
    encrypt(packet)
    packet = ''.join([struct.pack('B', i) for i in packet])
    return packet
    
def generate_breathe(mac, ip, session, index):
    index = hex(index)[2:]
    packet = []
    packet.append(3)
    packet_len = len(session) + 88
    packet.append(packet_len)
    packet.extend([i * 0 for i in range(16)])
    packet.extend([8, len(session) + 2])
    packet.extend(session)
    packet.extend([9, 18])
    packet.extend([ord(i) for i in ip])
    packet.extend([i * 0 for i in range(16 - len(ip))])
    packet.extend([7, 8])
    packet.extend([int(i, 16) for i in mac.split('-')])
    packet.extend([20, 6])
    packet.extend([int(index[0:-6],16), int(index[-6:-4],16), int(index[-4:-2],16), int(index[-2:],16)])
    packet.extend([42, 6, 0, 0, 0, 0, 43, 6, 0, 0, 0, 0, 44, 6, 0, 0, 0, 0, 45, 6, 0, 0, 0, 0, 46, 6, 0, 0, 0, 0, 47, 6, 0, 0, 0, 0])
    md5 = hashlib.md5(''.join([struct.pack('B', i) for i in packet])).digest()
    packet[2:18] = struct.unpack('16B', md5)
    encrypt(packet)
    packet = ''.join([struct.pack('B', i) for i in packet])
    return packet
    
def main():
    mac_address = 'FF-FF-FF-FF-FF-FF'
    ip = '172.16.X.X'
    username = ''
    password = ''
    index = 0x01000000
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    upnet_packet = generate_upnet(mac_address, ip, username, password)    
    session = upnet(sock, upnet_packet)
    breathe(sock, mac_address, ip, session, index)
    
if __name__ == '__main__':
    main()
