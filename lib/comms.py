import struct
import Crypto.Cipher.AES as AES
import Crypto.Util.Counter
import base64

from Crypto import Random

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.key = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))
            
            # Set the key to the shared hash (should it always be the first 16?)
            self.key = shared_hash[:16]     
                
    def pad(self, data):
        length = 16 - (len(data) % 16)
        data += bytes([length])*length
        return data

    def send(self, data):
        if self.key:
            # Create random IV and initiate cipher for single message
            IV = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, IV)
            # Pad data to be ciphered in blocks
            data = self.pad(data)
            # Send IV appended with encrypted data
            encrypted_data = IV + cipher.encrypt(data)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def unpad(self, data):
        data = data[:-data[-1]]
        return data

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)    

        if self.key:
            # Obtain sent IV and initiate cipher for single message
            IV = encrypted_data[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, IV)
            # Decrypt the data while ignoring the IV
            data = cipher.decrypt(encrypted_data[AES.block_size:])
            # Unpad data to obtain original message
            data = self.unpad(data)

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))

        else:
            data = encrypted_data
            
        return data

    def close(self):
        self.conn.close()
