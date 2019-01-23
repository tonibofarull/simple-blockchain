import hashlib
import pickle
import random

from rsa import *

class transaction:
    def __init__(self, message, RSAkey):
        """
        generates transaction
        """
        self.public_key = rsa_public_key(RSAkey)
        self.message = message
        self.signature = RSAkey.sign(message)

    def verify(self):
        """
        check if 'signature' corresponds to 'message'
        """
        return self.public_key.verify(self.message,self.signature)

    def __str__(self):
        s = '.......................'
        s += '\npublicExponent: {},'.format(self.public_key.publicExponent)
        s += '\n modulus: {}'.format(self.public_key.modulus)
        s += '\n message: {}'.format(self.message)
        s += '\n signature: {}'.format(self.signature)
        s += '\n.......................'
        return s
        
class block:
    
    bits = 256
    d = 8 # 'd' bits of proof of work
    
    def __init__(self):
        """
        creates a block (not necessary valid)
        """
        self.previous_block_hash = None
        
        self.block_hash = None
        self.transaction = None
        self.seed = None

    def genesis(self, transaction):
        """
        first block of a chain:
            - previous_block_hash = 0
            - is valid
        """
        self.previous_block_hash = 0
        self.transaction = transaction
        self.generate_block()
        
    def next_block(self, transaction):
        """
        generates next block
        """
        b = block()
        b.previous_block_hash = self.block_hash
        b.transaction = transaction
        b.generate_block()
        return b

    def verify_block(self):
        """
        verifies if the block is valid:
            - checks if previous_block_hash meets the requeried conditions (proof of work bits)
            - checks if transaction is valid
            - checks if block_hash meets the required conditions
        """
        if self.previous_block_hash >= 2**(block.bits-block.d):
            return False
        if self.block_hash >= 2**(block.bits-block.d) or self.block_hash != self.calculate_hash(self.seed):
            return False
        return self.transaction.verify()
        
    def generate_block(self):
        bits = block.bits
        d = block.d
        cond = False
        seed = None
        h = None
        while not cond:
            seed = random.randint(2**(bits-1),2**bits)
            h = self.calculate_hash(seed)
            cond = h < 2**(bits-d)
        self.seed = seed
        self.block_hash = h
        
    def calculate_hash(self,seed):
        sinput = str(self.previous_block_hash)
        sinput += str(self.transaction.public_key.publicExponent)
        sinput += str(self.transaction.public_key.modulus)
        sinput += str(self.transaction.message)
        sinput += str(self.transaction.signature)
        sinput += str(seed)
        return int(hashlib.sha256(sinput.encode()).hexdigest(),16)

    def __str__(self):
        s = '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
        s += '\nBlock: '
        s += '\n  previous_block_hash: {}'.format(self.previous_block_hash)
        s += '\n  block_hash: {}'.format(self.block_hash)
        s += '\n  seed: {}'.format(self.seed)
        s += '\n  transaction:'
        s += '\n{}'.format(str(self.transaction))
        return s

class block_chain:
    def __init__(self, transaction):
        """
        generates a blockchain of a single valid block (genesis) with transaction
        """
        gen = block()
        gen.genesis(transaction)
        self.list_of_blocks = [gen]
        
    def add_block(self, transaction):
        """
        adds a new valid block (with transaction) to the blockchain
        """
        last_block = self.list_of_blocks[-1]
        bloc = last_block.next_block(transaction)
        self.list_of_blocks.append(bloc)
    
    def verify(self):
        """
        verifies if the blockchain is valid:
            - first block is genesis
            - all blocks are valid
            - previous hashes are correct
        """
        l = len(self.list_of_blocks)
        if l > 0 and self.list_of_blocks[0].previous_block_hash != 0:
            return False
        for i in range(1,l):
            if not self.list_of_blocks[i].verify_block():
                print('Invalid block at position {} of a total of {}'.format(i+1,l))
                return False
            if self.list_of_blocks[i-1].block_hash != self.list_of_blocks[i].previous_block_hash:
                print('previous_hash of block {} does not match with real hash '.format(i+1))
                return False
        return True
        
    def __str__(self):
        l = len(self.list_of_blocks)
        s = '[\n'
        if l > 0:
            s += str(self.list_of_blocks[0])
        for i in range(1,l):
            s += '\n,\n'
            s += str(self.list_of_blocks[i])
        s += '\n]'
        return s
          
# Safe or load blockchain
          
def safe_blocks(bc,f_str):
    with open(f_str,'wb') as f:
        pickle.dump(bc, f)

def open_blocks(f_str):
    with open(f_str,'rb') as f:
        return pickle.load(f)

# Tests

def generate_valid_blockchain(num_blocks):
    """
    generates a blockchain of 'num_blocks' valid blocks
    """
    
    BC = block_chain(transaction(0,rsa_key()))
    for i in range(1,num_blocks):
        print(i)
        BC.add_block(transaction(i,rsa_key()))
    safe_blocks(BC,'valid.block')
    print(str(BC))
    print()
    print(BC.verify())
    

def generate_invalid_blockchain(num_blocks,k):
    """
    generates a blockchain of 'num_blocks'
    from block 'k+1' the chain is unvalid
    """
    BC = block_chain(transaction(0,rsa_key()))
    for i in range(1,num_blocks):
        print(i)
        BC.add_block(transaction(i,rsa_key()))
    BC.list_of_blocks[k].block_hash ^= 1 # hash less significant bit is toggled
    safe_blocks(BC,'invalid.block'.format(k))
    print(str(BC))
    print()
    print(BC.verify())
        
        
# MAIN

def main():
    generate_valid_blockchain(10)
    generate_invalid_blockchain(10,5)

if __name__ == '__main__':
    main()

