#!/usr/bin/env python
# -*- coding: utf-8 -*-

from time import sleep
from itertools import zip_longest
from _thread import start_new_thread
import socket

HOST = ''
PORT = 1337
SLEEP_TIME = 0.5
BAD_BOY = "Bad Password!\n".encode('utf-8')
GOOD_BOY = "Good Password!\n".encode('utf-8')
PASSWORD = "1337"


def compare_flag(password1, password2):
    if(len(password1) == 0):
        return False
    for left, right in zip_longest(password1, password2):
        if(left != right):
            return False
        sleep(SLEEP_TIME)  # prevent brute forcing
    return True


def listen(host, port):
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind socket
    s.bind((host, port))
    # Listenning
    s.listen(10)
    print("Listenning ..")
    return s


def client_handle(conn):
    conn.send("Hello !\nPlease Enter your super numeric admin password: ".encode('utf-8'))
    data = ""
    while True:
        data += conn.recv(1024).decode('utf-8')
        if '\n' in data:
            data = data.splitlines()[0]
            break
    password = data
    if compare_flag(password, PASSWORD):
        conn.send(GOOD_BOY)
    else:
        conn.send(BAD_BOY)
    conn.close()

if __name__ == "__main__":
    # Start TCP Server
    s = listen(HOST, PORT)
    while True:
        conn, addr = s.accept()
        start_new_thread(client_handle, (conn,))
    s.close()
