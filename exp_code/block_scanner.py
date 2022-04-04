from collections import OrderedDict
from collections import namedtuple
from bitcoin.wallet import CBitcoinSecret
from bitcoin.core import lx, b2x, COutPoint, CMutableTxOut, CMutableTxIn, \
    CMutableTransaction, Hash160, CBlock
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY,\
    OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.wallet import CBitcoinAddress
from http.client import CannotSendRequest
from bitcoin.rpc import Proxy
from bitcoin.rpc import JSONRPCError
from bitcoin.rpc import DEFAULT_HTTP_TIMEOUT
from binascii import unhexlify, hexlify
from custom_log import log, ERROR, INFO, SUCCESS
import socket
import time
from contextlib import closing


import os
import subprocess
import tempfile

class  TransactionMalleability:

    def __init__(self, rpc_user, rpc_password, rpc_host, rpc_port):

        self.config = {
            "rpc_user" : rpc_user,
            "rpc_password" : rpc_password,
            "rpc_port" : rpc_port,
            "rpc_timeout" : 5,
            "rpc_host": rpc_host
        }

        self.water_mark = "CYBER2"
        self.debug = True
        self.block_count = 0
        self._name = "simcoin-node-1.1"

    def connect_to_rpc(self):
        """Create RPC Proxy that will communicate with RPC server of the bitcoin node"""
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(("rpcconnect=%s\n"%self.config['rpc_host']).encode('utf8'))
            tmp.write(("rpcport=%s\n"%self.config['rpc_port']).encode('utf8'))
            tmp.write(("rpcuser=%s\n"%self.config['rpc_user']).encode('utf8'))
            tmp.write(("rpcpassword=%s\n"%self.config['rpc_password']).encode('utf8'))
            tmp.flush()
            self._rpc_connection = Proxy(
                btc_conf_file=tmp.name  ,
                timeout=self.config['rpc_timeout']
            )


    def __check_socket__(self):
        host = self.config['rpc_host']
        port = self.config['rpc_port']
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                return True
            else:
                return False


    def wait_until_rpc_ready(self):
        """Wait until the RPC server of the node is up and returns a valid result to getnetworkinfo command"""
        connected_tcp = False
        while connected_tcp:
            connected_tcp = self.__check_socket__()
            if not connected_tcp:
                print("Waiting with netcat until port is open")
                time.sleep(1)

        while True:
            try:
                self.execute_rpc('getnetworkinfo')
                break
            except:
                time.sleep(1)

    def execute_rpc(self, *args):
        """"Pass The RPC command to the node and rety it at maximum 30 times if 
            Does not succeed
            you can check the commands in https://developer.bitcoin.org/reference/rpc
        """
        retry = 10
        while retry > 0:
            try:
                return self._rpc_connection.call(args[0], *args[1:])
            except:
                retry -= 1
                self.connect_to_rpc()
        raise Exception('Could not execute RPC-call={} on node {}'.format(args[0], self._name))

    def big_2_little_endian(self,h):
        r = bytearray(h)
        r.reverse()
        return bytes(r)

    def scan(self):
        self.connect_to_rpc()
        while True:
            self.wait_until_rpc_ready()
            count = self._rpc_connection.getblockcount()
            if self.block_count == count:
                time.sleep(1)
            elif self.block_count > count:
                self.block_count = 0
            for index in range(self.block_count + 1, count + 1):
                block_hash = self._rpc_connection.getblockhash(index)
                log("Scanning block_hash: %s" %self.big_2_little_endian(block_hash).hex(), INFO)
                block = self._rpc_connection.getblock(block_hash)
                for tx in block.vtx:
                    self.__scan_tx__(tx)
            self.block_count = count

    def __scan_tx__(self, cmtrx):
        cmtrx = CMutableTransaction.deserialize(cmtrx.serialize())
        for _ , vin in enumerate(cmtrx.vin):
            if len(vin.scriptSig) > 0:
                find_index = vin.scriptSig.find(self.water_mark.encode('utf8'))
                if find_index >= 0:

                    log(
                        'Found transaction with injected SigScript TxId: %s' % self.big_2_little_endian(cmtrx.GetTxid()).hex(), SUCCESS)
                    return


transactionMalleability = TransactionMalleability('admin','admin','240.1.0.1','18332')
transactionMalleability.scan()
