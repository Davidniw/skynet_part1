import struct
import Crypto.Cipher.AES as AES
import Crypto.Util.Counter

from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

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
            self.key = shared_hash     
                
    def pad(self, data):
        length = 16 - (len(data) % 16)
        data += bytes([length])*length
        return data

    def send(self, data):
        if self.key:
            hash_key = SHA256.new(str(self.key).encode("ascii"))
            ekey = hash_key.hexdigest()[:32]
            hkey = hash_key.hexdigest()[32:]

            # Create random IV and initiate cipher for single message
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(ekey[:16], AES.MODE_CBC, iv)
            # Pad data to be ciphered in blocks
            data = self.pad(data)           
            cipher_text = cipher.encrypt(data)
            
            # Initialise HMAC by using 128 bits (48-16=32 --> 32*8=128)
            hmac = HMAC.new(str(hkey).encode("ascii"), digestmod=SHA256)
            # h = hash(k[64bit] + cipher)
            hmac.update(str(hkey).encode("ascii") + cipher_text)
            # H = hash(k[64bit] + h)
            hmac.update(str(hkey).encode("ascii") + str(hmac.hexdigest()).encode("ascii"))

            # Send IV and encrypted data and HMAC
            encrypted_data = iv + cipher_text + str(hmac.hexdigest()).encode("ascii")

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
            hash_key = SHA256.new(str(self.key).encode("ascii"))
            ekey = hash_key.hexdigest()[:32]
            hkey = hash_key.hexdigest()[32:]

            # Recalculate HMAC and check if it's identical
            hmac = HMAC.new(str(hkey).encode("ascii"), digestmod=SHA256)
            hmac.update(str(hkey).encode("ascii") + encrypted_data[AES.block_size:32])
            hmac.update(str(hkey).encode("ascii") + str(hmac.hexdigest()).encode("ascii"))

            if str(hmac.hexdigest()).encode("ascii") == encrypted_data[32:]:
                print("HMAC confirmed.")
                # Obtain sent IV and initiate cipher for single message
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(ekey[:16], AES.MODE_CBC, iv)
                # Decrypt the data while ignoring the IV
                data = cipher.decrypt(encrypted_data[AES.block_size:32])
                # Unpad data to obtain original message
                data = self.unpad(data)

                if self.verbose:
                    print("Receiving packet of length {}".format(pkt_len))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Original data: {}".format(data))

            else:
                print("HMAC Modified.")
                print("Received: ", encrypted_data[32:])
                print("Calculated: ", str(hmac.hexdigest()).encode("ascii"))
                data = encrypted_data
                
        else:
            data = encrypted_data
            
        return data

    def close(self):
        self.conn.close()
