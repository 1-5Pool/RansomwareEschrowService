import os
from web3 import Web3
from Crypto.Cipher import AES
import hashlib

# Connect to the Ethereum network
w3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/00e3e1fc31e54128b0b61f649de128aa'))

# Load the contract ABI and address
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
# Create an instance of the contract
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Add an event filter for the SampleDecryptionKeyRevealed event
sample_decryption_key_filter = contract.events.SampleDecryptionKeyRevealed.create_filter(fromBlock='latest')

# Victim's Ethereum address and private key
victim_address = '0xC6d31D88E818821eB74c3e9bA3f639aCD20f6Cd5'
victim_private_key = '971f372af35eb3cf43b04d686dee81b7a4a1e432501ce44eb1f8e606697115c2'

# Function to register the victim
def register_victim(victim_id):
    nonce = w3.eth.get_transaction_count(victim_address)
    transaction = contract.functions.registerVictim(victim_id).build_transaction({
        'from': victim_address,
        'nonce': nonce,
        'gas': 100000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, victim_private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Victim registered with ID: {victim_id}")

# Function to request sample decryption
def request_samples_decryption(victim_id, sample_ids):
    nonce = w3.eth.get_transaction_count(victim_address)
    transaction = contract.functions.requestSamplesDecryption(victim_id, sample_ids).build_transaction({
        'from': victim_address,
        'nonce': nonce,
        'gas': 200000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, victim_private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Sample decryption requested for Victim ID: {victim_id}")

# Function to pay the ransom
def pay_ransom(victim_id, commitment):
    nonce = w3.eth.get_transaction_count(victim_address)
    transaction = contract.functions.payRansom(victim_id, commitment).build_transaction({
        'from': victim_address,
        'value': contract.functions.ransomAmount().call(),
        'nonce': nonce,
        'gas': 200000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, victim_private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Ransom paid for Victim ID: {victim_id}")

# Function to request a refund
def refund_ransom(victim_id):
    nonce = w3.eth.get_transaction_count(victim_address)
    transaction = contract.functions.refundRansom(victim_id).build_transaction({
        'from': victim_address,
        'nonce': nonce,
        'gas': 100000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, victim_private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Refund requested for Victim ID: {victim_id}")

# Function to check logs for master key
def check_master_key(victim_id):
    master_key = None
    event_filter = contract.events.MasterKeyRevealed.create_filter(fromBlock=0,toBlock='latest')
    event_logs = event_filter.get_all_entries()
    for event in event_logs:
        if event['args']['victimID'] == victim_id:
            master_key = event['args']['masterKey']
            break
    return master_key

# Function to form decryption key from master key and file ID
def form_decryption_key(master_key, file_id,victim_id):
    decryption_key = hashlib.sha256(master_key + str(victim_id).encode() + file_id.encode()).digest()
    return decryption_key

# Function to decrypt files using the decryption key
def decrypt_file(file_path, decryption_key):
    print("Decrypting with ",decryption_key)
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
    print("file path",decrypted_file_path)
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)

# Function to check if the revealed sample decryption keys work correctly
def check_sample_decryption_keys(victim_id, sample_ids, encrypted_files):
    # Get the event logs for the SampleDecryptionKeyRevealed event
    event_filter = contract.events.SampleDecryptionKeyRevealed.create_filter( fromBlock=0, toBlock='latest')
    event_logs = event_filter.get_all_entries()
    
    for log in event_logs:
        print(log['args'])
        
        if log['args']['victimID'] == victim_id:
            print("first of statemetn")
            sample_id = log['args']['sampleID']
            decryption_key = log['args']['decryptionKey']

            if sample_id in sample_ids:
                print("hellloooo")
                # Try to decrypt the corresponding file with the revealed key
                file_path = encrypted_files[sample_id]
                try:
                    decrypt_file(file_path, decryption_key)
                    print(f"File with ID {sample_id} decrypted successfully.")
                except Exception as e:
                    print(f"Error decrypting file with ID {sample_id}: {e}")
                    return False

    return True
def read_commitment_from_file(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("Commitment: "):
                commitment_bytes_str = line.strip().split(": ")[1]
                commitment = eval(commitment_bytes_str)
                return commitment
    return None
def read_encrypted_files_from_file(file_path):
    encrypted_files = {}
    with open(file_path, 'r') as file:
        content = file.read()
        file_data_lines = content.split('\n')[2:]  # Skip the first two lines (Commitment and Encrypted Files)
        for line in file_data_lines:
            if line.startswith("File ID: "):
                file_id, encrypted_file_path = line.split(", ")
                file_id = file_id.split(": ")[1]
                encrypted_file_path = encrypted_file_path.split(": ")[1]
                encrypted_files[file_id] = encrypted_file_path
    return encrypted_files
# Main function with menu options
def main():
    victim_id = input("Enter the Victim ID: ")

    while True:
        print("\nVictim Menu:")
        print("1. Register Victim")
        print("2. Request Sample Decryption")
        print("3. Check Sample Decryption Keys")
        print("4. Pay Ransom")
        print("5. Request Refund")
        print("6. Check Master Key")
        print("7. Decrypt Files")
        print("8. Exit")

        choice = int(input("Enter your choice (1-8): "))

        if choice == 1:
            register_victim(victim_id)
        elif choice == 2:
            sample_ids = input("Enter the sample IDs (comma-separated): ").split(',')
            request_samples_decryption(victim_id, sample_ids)
            print("Sample decryption requested. Waiting for the attacker to reveal keys.")
        elif choice == 3:
            sample_ids = input("Enter the sample IDs (comma-separated): ").split(',')
            file_locations = input("Enter the file locations (comma-separated): ").split(',')
            encrypted_files = {sample_id: file_location for sample_id, file_location in zip(sample_ids, file_locations)}
            if check_sample_decryption_keys(victim_id, sample_ids, encrypted_files):
                print("Sample decryption keys work correctly.")
            else:
                print("Sample decryption keys do not work correctly.")
        elif choice == 4:
            file_path = input("Enter the file to read commitment from: ")
            c= read_commitment_from_file(file_path)

            pay_ransom(victim_id, c)
        elif choice == 5:
            refund_ransom(victim_id)
        elif choice == 6:
            master_key = check_master_key(victim_id)
            if master_key:
                print(f"Master Key: {master_key}")
            else:
                print("Master Key not found in logs.")
        elif choice == 7:
            file_path = input("Enter the path of the encryption data file: ")
            encrypted_files = read_encrypted_files_from_file(file_path)

            master_key = check_master_key(victim_id)
            if master_key:
                for file_id, encrypted_file_path in encrypted_files.items():
                    decryption_key = form_decryption_key(master_key, file_id, victim_id)
                    decrypt_file(encrypted_file_path, decryption_key)
            else:
                print("Master Key not found in logs. Cannot decrypt files.")
        elif choice == 8:
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
