@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0
    
    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
            # encode outputs
            out += [encode_varint(len(self.tx_outs))]
            out += [tx_out.encode() for tx_out in self.tx_outs]
            # encode...other metadata
            out += [encode_int(self.locktime, 4)]
            out += [encode_int(1, 4) if sig_index != -1 else b''] # 1 = SIGHASH_ALL
            return b''.join(out)
        
# we also need to know how to encode TxIn. This is serialization protocol
def txin_encode(self, script_override=None):
    out = []
    out += [self.prev_tx[::-1]] # little endian vs big endian encodings, haha
    out += [encode_int(self.prev_index, 4)]
    
    if script_override is None:
        # None = just use actual script
        out += [self.script_sig.encode()]
        
    elif script_override is True:
        # True = override the script with the script_pubkey of the associated input
        out += [self.prev_tx_script_pubkey.encode()]
        
    elif script_override is False:
        # False = override with an empty script
        out += [Script([]).encode()]
    
    else:
        raise ValueError("script_override must be one of None|True|False")
        
    out += [encode_int(self.sequence, 4)]
    return b''.join(out)

TxIn.encode = txin_encode # monkey patch into the class

# and TxOut as well
def txout_encode(self):
    out = []
    out += [encode_int(self.amount, 8)]
    out += [self.script_pubkey.encode()]
    return b''.join(out)

TxOut.encode = txout_encode # monkey patch into class

tx = Tx(
    version = 1,
    tx_ins = [tx_in],
    tx_outs = [tx_out1, tx_out2],
)

-----

source_script = Script([118, 169, out2_pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
print("recall out2_pkb_hash is just raw bytes of the hash of public_key: ", out2_pkb_hash.hex())
print(source_script.encode().hex()) # we can get the bytes of the script_pubkey now

-----

# monkey patch this into the input of the transaction we are trying to sign and construct
tx_in.prev_tx_script_pubkey = source_script

# get the "message" we need to digitally sign!!
message = tx.encode(sig_index = 0)
message.hex()

-----

@dataclass
class Signature:
    r: int
    s: int

def sign(secret_key: int, message: bytes) -> Signature:
    
    # the order of the elliptic curve used in bitcoin
    n = bitcoin_gen.n
    
    # double hash the message and convert to integer
    z = int.from_bytes(sha256(sha256(message)), 'big')
    
    # generate a new secret/public key pair at random
    sk = random.randrange(1, n)
    P = sk * bitcoin_gen.G
    
    # calculate the signature
    r = P.x
    s = inv(sk, n) * (z + secret_key * r) % n
    if s > n / 2:
        s = n - s
        
    sig = Signature(r, s)
    return sig

def verify(public_key: Point, message: bytes, sig: Signature) -> bool:
    # just a stub reference on how a signature would be verified in terms of an API
    # we don't need to verify to craft a transaction, but we would if we were mining
    pass

random.seed(int.from_bytes(sha256(message), 'big')) # see note below
sig = sign(secret_key, message)
sig

-----

def signature_encode(self) -> bytes:
    """ return the DER encoding of this signature """
    
    def dern(n):
        nb = n.to_bytes(32, byteorder='big')
        nb = nb.lstrip(b'\x00') # strip leading zeros
        nb = (b'\x00' if nb[0] >= 0x80 else b'') + nb # preprend 0x00 if first byte >= 0x80
        return nb
    
    rb = dern(self.r)
    sb = dern(self.s)
    content = b''.join([bytes([0x02, len(rb)]), rb, bytes([0x02, len(sb)]), sb])
    frame = b''.join([bytes([0x30, len(content)]), content])
    return frame

Signature.encode = signature_encode # monkey patch into the class
sig_bytes = sig.encode()
sig_bytes.hex()

-----

# Append 1 (=SIGHASH_ALL), indicating this DER signature encoded "ALL" of the tx (by far most common)

sig_bytes_and_type = sig_bytes + b'\x01'

# Encode the public key into bytes, we use hash160=False so it is the full public key to the Blockchain
pubkey_bytes = PublicKey.from_point(public_key).encode(compressed=True, hash160=False)

# Create a lightweight Script that just encodes these two things
script_sig = Script([sig_bytes_and_type, pubkey_bytes])
tx_in.script_sig = script_sig

-----

@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0
    
    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
            # encode outputs
            out += [encode_varint(len(self.tx_outs))]
            out += [tx_out.encode() for tx_out in self.tx_outs]
            # encode... other metadata
            out += [encode_int(self.locktime, 4)]
            out += [encode_int(1, 4) if sig_index != -1 else b''] # 1 = SIGHASH_ALL
            return b''.join(out)
        
# we also need to know how to encode TxIn. This is just serialization protocol.
def txin_encode(self, script_override=None):
    out = []
    out += [self.prev_tx[::-1]] # little endian vs big endian encodings... sigh
    out += [encode_int(self.prev_index, 4)]
    
    if script_override is None:
        # None = just use the actual script
        out += [self.script_sig.encode()]
    elif script_override is True:
        # True = override the script with the script_pubkey of the associated input
        out += [self.prev_tx_script_pubkey.encode()]
    elif script_override is False:
        # False = override with an empty script
        out += [Script([]).encode()]
    else:
        raise ValueError("script_override must be one of None|True|False")
        
    out += [encode_int(self.sequence, 4)]
    return b''.join(out)

TxIn.encode = txin_encode # monkey patch into the class

# and TxOut as well
def txout_encode(self):
    out = []
    out += [encode_int(self.amount, 8)]
    out += [self.script_pubkey.encode()]
    return b''.join(out)

TxOut.encode = txout_encode # monkey patch into the class

tx = Tx(
    version = 1,
    tx_ins = [tx_in],
    tx_outs = [tx_out1, tx_out2],
)

###

def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes using a given byte ordering """
    return i.to_bytes(nbytes, encoding)

def encode_varint(i):
    """ encode a (possibly but rarely large) integer into bytes with a super simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i, ))
        
@dataclass
class Script:
    cmds: List[Union[int, bytes]]
        
    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            elif isinstance(cmd, bytes):
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                assert length < 75 # any longer than this requires a bit of tedious handling that we are skipping here
                out += [encode_int(length, 1), cmd]
                
        ret = b''.join(out)
        return encode_varint(len(ret)) + ret
    
# the first output will go to our 2nd wallet
out1_pkb_hash = PublicKey.from_point(public_key2).encode(compressed=True, hash160=True)
out1_script = Script([118, 169, out1_pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
print(out1_script.encode().hex())

# the second output will go back to us
out2_pkb_hash = PublicKey.from_point(public_key).encode(compressed=True, hash160=True)
out2_script = Script([118, 169, out2_pkb_hash, 136, 172])
print(out2_script.encode().hex())

###

@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0
    
    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
            # encode outputs
            out += [encode_varint(len(self.tx_outs))]
            out += [tx_out.encode() for tx_out in self.tx_outs]
            # encode... other metadata
            out += [encode_int(self.locktime, 4)]
            out += [encode_int(1, 4) if sig_index != -1 else b''] # 1 = SIGHASH_ALL
            return b''.join(out)
        
# we also need to know how to encode TxIn. This is just serialization protocol.
def txin_encode(self, script_override=None):
    out = []
    out += [self.prev_tx[::-1]] # little endian vs big endian encodings... sigh
    out += [encode_int(self.prev_index, 4)]
    
    if script_override is None:
        # None = just use the actual script
        out += [self.script_sig.encode()]
    elif script_override is True:
        # True = override the script with the script_pubkey of the associated input
        out += [self.prev_tx_script_pubkey.encode()]
    elif script_override is False:
        # False = override with an empty script
        out += [Script([]).encode()]
    else:
        raise ValueError("script_override must be one of None|True|False")
        
    out += [encode_int(self.sequence, 4)]
    return b''.join(out)

TxIn.encode = txin_encode # monkey patch into the class

# and TxOut as well
def txout_encode(self):
    out = []
    out += [encode_int(self.amount, 8)]
    out += [self.script_pubkey.encode()]
    return b''.join(out)

TxOut.encode = txout_encode # monkey patch into the class

tx = Tx(
    version = 1,
    tx_ins = [tx_in],
    tx_outs = [tx_out1, tx_out2],
)