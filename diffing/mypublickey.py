class PublicKey(Point):
    """
    The public key is just a Point on a Curve, but has some additional specific 
    encoding / decoding functionality that this class implements.
    """
    
    @classmethod
    def from_point(cls, pt: Point):
        """ promote a Point to be a PublicKey """
        return cls(pt.curve, pt.x, pt.y)
    
    def encode(self, compressed, hash160=False):
        """ Return the SEC bytes encoding of the public key Point """
        # calculate the bytes
        if compressed:
            # (x,y) is redundant, but due to the fact that this is modular arithmetic, there is 
            # no + or - in the terms, instead it can be shown that one y will always be even
            # and the other odd.
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            pkb = prefix + self.x.to_bytes(32, 'big')
        else:
            pkb = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
            # hash if desired
        return ripemd160(sha256(pkb)) if hash160 else pkb
        
    def address(self, net: str, compressed: bool) -> str:
        """ Return the associated bitcoin address for this public key as string """
        # encode the public key into bytes and hash to get the payload
        pkb_hash = self.encode(compressed=compressed, hash160=True)
        # add version byte(0x00 for Main Network, or 0x6f for Test Network)
        version = {'main': b'\x00', 'test': b'\x6f'}
        ver_pkb_hash = version[net] + pkb_hash
        # calculate the checksum
        checksum = sha256(sha256(ver_pkb_hash))[:4]
        # append to form the full 25-byte binary Bitcoin Address
        byte_address = ver_pkb_hash + checksum
        # lastly, b58 encode teh result
        b58check_address = b58encode(byte_address)
        return b58check_address