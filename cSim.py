
from datetime import datetime
import sys
import hashlib
import binascii
import rsa
import os.path

# sample file commands
# gets the hash of a file; from https://stackoverflow.com/a/44873382
def hashFile(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()


# given an array of bytes, return a hex representation of it
def bytesToString(data):
    return binascii.hexlify(data)


# given a hex representation, convert it to an array of bytes
def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)


# Load the wallet keys from a filename
def loadWallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey


# save the wallet to a file
def saveWallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    privkeyBytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkeyString = pubkeyBytes.decode('ascii')
    privkeyString = privkeyBytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkeyString)
        file.write(privkeyString)
    return


name = 'Tuchelcoin'
special_case_id = 'bigfoot'

if len(sys.argv) == 2:
    # show name
    if sys.argv[1] == 'name':
        print(name)

    # create genesis block
    elif sys.argv[1] == 'genesis':
        gen_block = open("block_0.txt", "w")
        gen_block.write("I will be there no matter what")
        gen_block.close()
        print( 'Genesis block created in', gen_block.name)

    elif sys.argv[1] == 'validate':
        counter = 1
        while True:
            # iterate through all blocks in the chain
            try:
                prev_file = 'block_' + str(counter - 1) + '.txt'
                next_file = 'block_' + str(counter) + '.txt'
                blockchain = open(next_file)
                expected_hash = blockchain.readline().rstrip()
                blockchain.close()
                calc_hash = str(hashFile(prev_file))
                counter += 1
                if expected_hash != calc_hash:
                    print(False)
                    break
            except FileNotFoundError:
                print(True)
                break


elif len(sys.argv) == 3:
    # generate new wallet
    if sys.argv[1] == 'generate':
        (pubkey, privkey) = rsa.newkeys(1024)
        pubkeyBytes = pubkey.save_pkcs1(format='PEM')
        tag = binascii.hexlify(hashlib.sha256(pubkeyBytes).digest()).decode()[0:16]
        saveWallet(pubkey, privkey, sys.argv[2])
        print ("New wallet generated in ", sys.argv[2], " with tag", tag)

    # get the tag of a wallet
    elif sys.argv[1] == 'address':
        (pubkey, privkey) = loadWallet(sys.argv[2])
        pubkeyBytes = pubkey.save_pkcs1(format='PEM')
        tag = binascii.hexlify(hashlib.sha256(pubkeyBytes).digest()).decode()[0:16]
        print(tag)

    # check a balance
    elif sys.argv[1] == 'balance':
        tag = sys.argv[2]
        counter = 0
        balance = 0
        try:
            # find balance from mempool
            mempool = open('mempool.txt')
            lines = mempool.readlines()
            for line in lines:
                line = line.split()
                if line[0] == tag:
                    balance -= int(line[2])
                elif line[4] == tag:
                    balance += int(line[2])
        except FileNotFoundError:
            pass

        while True:
            # find balance from blockchain
            try:
                curr_file = 'block_' + str(counter) + '.txt'
                blockchain = open(curr_file)
                lines = blockchain.readlines()
                for line in lines:
                    line = line.split()
                    if len(line) > 3:
                        if line[0] == tag:
                            balance -= int(line[2])
                        elif line[4] == tag:
                            balance += int(line[2])
                counter += 1
                blockchain.close()
            except FileNotFoundError:
                print(balance)
                break

    # create a new block
    elif sys.argv[1] == 'mine':
        zeros = int(sys.argv[2])
        counter = 0
        nonce_counter = 0
        zeros_str = ''
        for i in range(zeros):
            zeros_str += '0'
        lead_num = ''
        # find what number the new block is
        while os.path.exists('block_' + str(counter) + '.txt'):
            counter += 1
        new_block = 'block_' + str(counter) + '.txt'
        prev_block = 'block_' + str(counter-1) + '.txt'

        # calculate the previous block's hash and add that and the lines in mempool to the new block
        previous_hash = hashFile(prev_block)
        mempool = open('mempool.txt')
        lines = mempool.readlines()
        mempool.close()
        new_blockf = open(new_block, 'w')
        new_blockf.write(previous_hash + '\n')
        for i in lines:
            new_blockf.write(i)
        new_blockf.write(("nonce: " + str(nonce_counter)))
        new_blockf.close()
        # find the hash for the current block and use it to find the nonce
        new_hash = str(hashFile(new_block))
        lead_num = new_hash[0:zeros]
        while lead_num != zeros_str:
            nonce_counter += 1
            file = open(new_block, 'r')
            lines_new = file.readlines()[:-1]
            lines_new.append("nonce: " + str(nonce_counter))
            file.close()
            file = open(new_block, 'w')
            file.writelines(lines_new)
            file.close()
            new_hash = str(hashFile(new_block))
            lead_num = new_hash[0:zeros]

        # clear mempool
        open('mempool.txt', 'w').close()

        print('Mempool transactions moved to', new_block, 'and mined with difficulty', zeros, 'and nonce', nonce_counter)
elif len(sys.argv) == 4:

    # verify transfer of the crypto
    if sys.argv[1] == 'verify':
        wallet = sys.argv[2]
        transaction = sys.argv[3]
        with open(transaction, 'r') as i:
            num_lines = len(i.readlines())
        file = open(transaction)
        lines = file.readlines()
        sender = lines[0].replace("From: ", "").rstrip()
        receiver = lines[1].replace("To: ", "").rstrip()
        amount = lines[2].replace("Amount: ", "").rstrip()
        date = lines[3].replace("Date: ", "").rstrip()

        # check if it's a fund or transfer
        if num_lines > 4:
            # get the hex of the first 3 rows of the file and compare to decoded hash at end of transaction file
            file_sig = lines[4]
            (pubkey, privkey) = loadWallet(wallet)
            file_new = open('dupfile.txt', 'a')
            for i in range(4):
                file_new.write(lines[i])
            expected_hash = hashFile('dupfile.txt')
            file_new.close()
            os.remove('dupfile.txt')


            encoded_hash = file_sig.encode('ascii')
            hash_bytes = stringToBytes(encoded_hash)
            decrypted_hash = rsa.decrypt(hash_bytes, privkey)
            decry_hash = bytesToString(decrypted_hash)
            final_hash = decry_hash.decode('ascii')

            # see if there is enough money to make transaction
            if expected_hash == final_hash:
                tag = sender
                counter = 0
                balance = 0
                try:
                    # find balance from mempool
                    mempool_read = open('mempool.txt')
                    lines = mempool_read.readlines()

                    for line in lines:
                        line.rstrip
                        line = line.split()
                        if line[0] == tag:
                            balance -= int(line[2])
                        elif line[4] == tag:
                            balance += int(line[2])
                    mempool_read.close()
                except FileNotFoundError:
                    pass

                while True:
                    # find balance from blockchain
                    try:
                        curr_file = 'block_' + str(counter) + '.txt'
                        blockchain = open(curr_file)
                        lines = blockchain.readlines()
                        for line in lines:
                            line = line.split()
                            if len(line) > 3:
                                if line[0] == tag:
                                    balance -= int(line[2])
                                elif line[4] == tag:
                                    balance += int(line[2])
                        counter += 1
                        blockchain.close()
                    except FileNotFoundError:
                        break

                balance -= int(amount)
                if balance >= 0:
                    # enough money to make transfer
                    mempool = open('mempool.txt', 'a+')
                    tran_line = sender + " transferred " + amount + " to " + receiver + " on " + date
                    mempool.write(tran_line + "\n")
                    mempool.close()
                    print("The transaction in file", transaction, "with wallet", wallet,
                          "is valid, and was written to the mempool")

                else:
                    # not enough money to make transfer
                    print("The transaction in file", transaction, "with wallet", wallet,
                          "is not valid, and was not written to the mempool, not enough money")

            else:
                # wrong sig at end of file
                print("The transaction in file", transaction, "with wallet", wallet,
                      "is not valid, and was not written to the mempool, wrong sig")

        else:
            # fund file so automatically add to mempool
            mempool = open('mempool.txt', 'a+')
            tran_line = sender + " transferred " + amount + " to " + receiver + " on " + date
            mempool.write(tran_line + "\n")
            mempool.close()
            print("The transaction in file", transaction, "with wallet", wallet, "is valid, and was written to the mempool")


elif len(sys.argv) == 5:

    # fund wallet with money
    if sys.argv[1] == 'fund':
        tag = sys.argv[2]
        amount = sys.argv[3]
        outputf = open(sys.argv[4], "x")
        outputf.write("From: " + special_case_id + "\n" + "To: " + tag + "\n" + "Amount: " + amount + "\n" + "Date: " + str(datetime.now()))
        print("Funded wallet", tag, "with", amount, name, "on", str(datetime.now()))


elif len(sys.argv) == 6:

    # transfer money from one wallet to another
    if sys.argv[1] == 'transfer':
        senderf = sys.argv[2]
        receiver_tag = sys.argv[3]
        amount = sys.argv[4]
        outputf = sys.argv[5]
        time = str(datetime.now())
        (pubkey, privkey) = loadWallet(senderf)

        # get tag of sender and write all but signature to file
        sender_pubkeyBytes = pubkey.save_pkcs1(format='PEM')
        sender_tag = binascii.hexlify(hashlib.sha256(sender_pubkeyBytes).digest()).decode()[0:16]
        outputf_write = open(sys.argv[5], "x")
        outputf_write.write("From: " + sender_tag + "\n" + "To: " + receiver_tag + "\n" + "Amount: " + amount + "\n" + "Date: " + time)

        # get the hash of the file and use it to sign the file
        hash_of_file = stringToBytes(hashFile(outputf))
        sig_bytes = rsa.encrypt(hash_of_file, pubkey)
        signature = bytesToString(sig_bytes).decode('ascii')

        # write signature to file
        outputf_write.write("\n" + signature)
        print("Transferred", amount, "from", senderf, "to", receiver_tag, "and the statement to", outputf, "on", time)