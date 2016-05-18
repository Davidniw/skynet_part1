import random
import struct
import Crypto.Cipher.AES as AES

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
         rkey = key.hexdigest()[16:40]
         # Hash key
         hkey = str(key.hexdigest()[40:]).encode("ascii")
         return ekey, rkey, hkey
         
    def gen_random(self, key, min, max):
        # Generate random nonce from key
        random.seed(key)
        r = random.randrange(min, max).to_bytes(16, byteorder='big')
        random_num = SHA256.new(r)
        return str(random_num.hexdigest()).encode("ascii")
        #return random_num 
                  
    def hash_mac(self, key, cipher):
         # Initialise HMAC
         hmac = HMAC.new(key, digestmod=SHA256)
         hmac.update(str(cipher).encode("ascii"))
         return hmac
                
    # ANSI X.923 pads the message with zeroes
    # The last byte is the number of zeroes added
    # This should be checked on unpadding
    def ANSI_X923_pad(self, m, pad_length):
        # Work out how many bytes need to be added
        required_padding = pad_length - (len(m) % pad_length)
        # Use a bytearray so we can add to the end of m
        b = bytearray(m)
        # Then k-1 zero bytes, where k is the required padding
        b.extend(bytes("\x00" * (required_padding-1), "ascii"))
        # And finally adding the number of padding bytes added
        b.append(required_padding)
        return bytes(b)

    def ANSI_X923_unpad(self, m, pad_length):
        # The last byte should represent the number of padding bytes added
        required_padding = m[-1]
        # Ensure that there are required_padding - 1 zero bytes
        if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
            return m[:-required_padding]
        else:
            # Raise an exception in the case of an invalid padding
            raise AssertionError("Padding was invalid")

    def send(self, data):
        if self.key:
            # Split the key for use in encryption, random generator and encryption
            ekey, rkey, hkey = self.split_key(self.key)

            # Generate random nonce to be sent
            rand_nonce = self.gen_random(rkey, 0, pow(2,128))

            # Excrypt data using AES
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(ekey, AES.MODE_CBC, iv)
            # Pad data to be ciphered in blocks
            data = self.ANSI_X923_pad(data, AES.block_size)           
            ciphertext = cipher.encrypt(data)
            
            # Create HMAC to be sent using key and cipher
            hmac = self.hash_mac(hkey, ciphertext)

            # Send IV, encrypted data, HMAC and Nonce
            encrypted_data = iv + ciphertext + str(hmac.hexdigest()).encode("ascii") + rand_nonce

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
            rand_nonce = self.gen_random(rkey, 0, pow(2,128))
            if rand_nonce == encrypted_data[-64:]:
                print("Random Nonce confirmed.")

                # Recalculate HMAC using received values
                hmac = self.hash_mac(hkey, encrypted_data[16:-128])

                # Check if HMAC values are equal
                if str(hmac.hexdigest()).encode("ascii") == encrypted_data[-128:-64]:
                    print("HMAC confirmed.")
                    
                    # Obtain IV from message
                    iv = encrypted_data[:16]
                    # Decrypt ciphertext from message
                    cipher = AES.new(ekey, AES.MODE_CBC, iv)
                    data = cipher.decrypt(encrypted_data[16:-128])
                    # Unpad data to obtain original message
                    data = self.ANSI_X923_unpad(data, AES.block_size)

                    if self.verbose:
                        print("Receiving packet of length {}".format(pkt_len))
                        print("Encrypted data: {}".format(repr(encrypted_data)))
                        print("Original data: {}".format(data))

                else:
                    # HMAC received is not identical to HMAC calculated.
                    print("HMAC Modified.")
                    print("Received: ", encrypted_data[-128:-64])
                    print("Calculated: ", str(hmac.hexdigest()).encode("ascii"))
                    data = encrypted_data

            else:
                # Random nonce received is not identical to HMAC calculated.
                print("Random Nonce not identical.")
                print("Received: ", encrypted_data[-64:])
                print("Calculated: ", rand_nonce)
                data = encrypted_data
      
        else:
            data = encrypted_data
            
        return data

    def close(self):
        self.conn.close()
