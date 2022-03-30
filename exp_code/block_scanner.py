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

#from rich import print
import time


import os
import subprocess


#Please create a full working node that is malicious this way it can be easier 
#>>This following link seems to be good and juicy and can show you how to connect to a given node to retrieve its transactions and poison them 
#http://sebastianappelt.com/understanding-blockchain-peer-discovery-and-establishing-a-connection-with-python/
#https://dev.to/alecbuda/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets-1le6
#https://www.google.com/search?q=python+connect+to+bitcoin+nodes&sxsrf=APq-WBu-MwrHJqGjuyuUCyordYloBhk5Wg%3A1646774084554&ei=RMcnYq-gIcOVxc8PzrKekA8&ved=0ahUKEwiv0tbCt7f2AhXDSvEDHU6ZB_IQ4dUDCA8&uact=5&oq=python+connect+to+bitcoin+nodes&gs_lcp=Cgdnd3Mtd2l6EAMyBggAEBYQHjoHCAAQRxCwAzoGCCMQJxATOgQIIxAnOggIABCABBCxAzoFCAAQgAQ6CwgAEIAEELEDEIMBOggIABAWEAoQHjoECAAQDToGCAAQDRAeOggIABAIEA0QHjoFCAAQywFKBAhBGABKBAhGGABQ4AdYn1Fg5lZoBHABeAOAAfUCiAHUGpIBCDIwLjcuMi4xmAEAoAEByAEIwAEB&sclient=gws-wiz
class  TransactionMalleability:

    def __init__(self):

        self.config = {
            "btc_node_config_file" : 'simcoin-node-1.1',
            "rpc_timeout" : 3600,
            "rpc_user" : 'admin',
            "rpc_password" : 'admin',
            "rpc_port" : 18332,
            "rpc_timeout" : 3600,
            "rpc_host": "240.1.0.1"
        }
        self.water_mark = "CYBER2"
        self.debug = True
        self._name = "simcoin-node-1.1"

    def close_rpc_connection(self):
        """Close Base Proxy objects that forwads commands to the node RPC Server"""
        if self._rpc_connection is not None:
            self._rpc_connection.__dict__['_BaseProxy__conn'].close()
            print('Closed rpc connection to node={}'.format(self._name))

    def connect_to_rpc(self):
        """Create RPC Proxy that will communicate with RPC server of the bitcoin node"""
        self._rpc_connection = Proxy(
            btc_conf_file=self.config['btc_node_config_file'],
            timeout=self.config['rpc_timeout']
        )



    def bash_check_output(self,cmd):
        """call a command and print the output to the log a;nd return the output"""
        output = self.check_output_without_log(cmd)
        for line in output.splitlines():
            print(line.strip())
        return output

    #call a command in bash and return the output
    def check_output_without_log(self,cmd):
        print(cmd)
        output = subprocess.check_output(cmd, shell=True, executable='/bin/bash')
        encoded_output = output.decode('utf-8').rstrip()
        return encoded_output


    def wait_until_rpc_ready(self):
        """Wait until the RPC server of the node is up and returns a valid result to getnetworkinfo command"""
        while True:
            try:
                self.bash_check_output(
                    "nc -z -w1 {} {}"
                    .format(self.config['rpc_host'], self.config['rpc_port'])
                )
                break
            except Exception:
                print("Waiting with netcat until port is open")

        while True:
            try:
                self.execute_rpc('getnetworkinfo')
                break
            except JSONRPCError:
                print('Waiting until RPC of node={} is ready.'.format(self._name))
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
            except (IOError, CannotSendRequest) as error:
                print('Could not execute RPC-call={} on node={} because of error={}.'
                                  ' Reconnecting and retrying, {} retries left'
                                  .format(args[0], self._name,  error, retry))
                retry -= 1
                self.connect_to_rpc()
        raise Exception('Could not execute RPC-call={} on node {}'.format(args[0], self._name))

    def big_2_little_endian(self,h):
        r = bytearray(h)
        r.reverse()
        return bytes(r)

    def scan(self):
        self.connect_to_rpc()
        self.wait_until_rpc_ready()
        count = self._rpc_connection.getblockcount()
        for index in range(count + 1):
            block = CBlock()
            block_hash = self._rpc_connection.getblockhash(index)
            #print("Big Endian    block_hash: %s" %block_hash.hex())
            #print("Lit Endian block_hash: %s" %self.big_2_little_endian(block_hash).hex())
            block = self._rpc_connection.getblock(block_hash)
            for tx in block.vtx:
                self.__scan_tx__(tx)

    def __scan_tx__(self, cmtrx):
        cmtrx = CMutableTransaction.deserialize(cmtrx.serialize())
        for index, vin in enumerate(cmtrx.vin):
            if len(vin.scriptSig) > 0:
                find_index = vin.scriptSig.find(self.water_mark.encode('utf8'))
                if find_index >= 0:

                    print(
                        '[bold green] [+] [/bold green] Found transaction with injected SigScript TxId: %s' % self.big_2_little_endian(cmtrx.GetTxid()).hex())
                    return


transactionMalleability = TransactionMalleability()
transactionMalleability.scan()
