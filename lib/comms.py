import random
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

    def split_key(self, key):
         # Hash the shared key and split for encrypting, seeding and hashing
         key = SHA256.new(str(key).encode("ascii"))
         # Encryption key
         ekey = key.hexdigest()[:16]
         # Random key (seed)
         rkey = key.hexdigest()[16:32]
         # Hash key
         hkey = str(key.hexdigest()[32:]).encode("ascii")
         return ekey, rkey, hkey
         
    def gen_random(self, key, min, max):
        # Generate random nonce from key
        random.seed(key)
        random_num = random.randrange(min, max).to_bytes(16, byteorder='big')
        return random_num
                   
    def hash_mac(self, key, cipher):
         # Initialise HMAC
         hmac = HMAC.new(key, digestmod=SHA256)
         # h = hash(key + cipher)
         hmac.update(key + cipher)
         # H = hash(key + h)
         hmac.update(key + str(hmac.hexdigest()).encode("ascii"))
         return hmac
                
    def pad(self, data):
        length = 16 - (len(data) % 16)
        data += bytes([length])*length
        return data

    def send(self, data):
        if self.key:
            # Split the key for use in encryption, random generator and encryption
            ekey, rkey, hkey = self.split_key(self.key)

            # Generate random nonce to be sent
            rand_nonce = self.gen_random(rkey, 0, 100000)

            # Create random IV and initiate cipher for single message
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(ekey, AES.MODE_CBC, iv)
            
            # Pad data to be ciphered in blocks
            data = self.pad(data)           
            cipher_text = cipher.encrypt(data)
            
            # Create HMAC to be sent using key and cipher
            hmac = self.hash_mac(hkey, cipher_text)

            # Send IV, encrypted data, HMAC and Nonce
            encrypted_data = iv + cipher_text + str(hmac.hexdigest()).encode("ascii") + rand_nonce

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
            # Split the key for use in encryption, random generator and encryption
            ekey, rkey, hkey = self.split_key(self.key)

            # Check if random nonce values are correct
            if self.gen_random(rkey, 0, 100000) == encrypted_data[96:]:
                print("Random Nonce confirmed.")
                
                # Recalculate HMAC using received values
                hmac = self.hash_mac(hkey, encrypted_data[AES.block_size:32])

                # Check if HMAC values are equal
                if str(hmac.hexdigest()).encode("ascii") == encrypted_data[32:96]:
                    print("HMAC confirmed.")
                    
                    # Obtain IV from message
                    iv = encrypted_data[:AES.block_size]
                    # Initiate cipher for single message
                    cipher = AES.new(ekey, AES.MODE_CBC, iv)
                    # Decrypt the data while ignoring the plaintext IV
                    data = cipher.decrypt(encrypted_data[AES.block_size:32])
                    # Unpad data to obtain original message
                    data = self.unpad(data)

                    if self.verbose:
                        print("Receiving packet of length {}".format(pkt_len))
                        print("Encrypted data: {}".format(repr(encrypted_data)))
                        print("Original data: {}".format(data))

                else:
                    # HMAC received is not identical to HMAC calculated.
                    print("HMAC Modified.")
                    print("Received: ", encrypted_data[32:96])
                    print("Calculated: ", str(hmac.hexdigest()).encode("ascii"))

            else:
                # Random nonce received is not identical to HMAC calculated.
                print("Random Nonce not identical.")
                print("Received: ", encrypted_data[96:])
                print("Calculated: ", ran_nonce)
      
        else:
            data = encrypted_data
            
        return data

    def close(self):
        self.conn.close()
