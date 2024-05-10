# Ransomware Eschrow Service

## Project Overview
Ransomware attacks have become increasingly prevalent in recent years, causing significant financial losses and disrupting operations for individuals and organizations alike. Traditional ransomware schemes rely on off-chain payment methods and lack transparency, leaving victims uncertain about the trustworthiness of the attackers. To address these issues, this project explores the concept of blockchain-based ransomware using smart contracts, aiming to introduce a degree of automation and fair exchange to the ransomware process.
The proposed solution leverages the Ethereum blockchain and smart contracts to create a decentralized and transparent ransomware system. By utilizing smart contracts, the project enables victims to interact with the ransomware in a more automated and secure manner. The smart contract acts as an escrow service, holding the ransom payment until the attacker reveals the decryption keys. The project introduces novel features such as proof-of-life, allowing victims to request the decryption of a subset of files as a demonstration of the attacker's ability to decrypt the files. Additionally, the smart contract enforces a deadline for the attacker to reveal the decryption keys, providing a level of protection for the victims. The project aims to explore the technical feasibility and potential implications of blockchain-based ransomware, shedding light on the need for proactive measures to combat this emerging threat.

## Project Structure
```
my-smart-contract-project/
├── clients/
│   ├── attacker.py
│   └── victim.py
├── contracts/
│   └── MyContract.sol
├── tests/
│   └── test_my_contract.py
├── README.md
└── requirements.txt
```

## Installation Instructions
### Prerequisites
- **Node.js:** v14.x or higher
- **Python:** 3.8 or higher
- **Ganache CLI (Optional):** For local blockchain testing

### Installing Dependencies
**Python Dependencies:**
```
pip install -r requirements.txt
```

**Node.js/Truffle Dependencies:**
```
# Install Truffle globally
npm install -g truffle

# Optional: Install Ganache CLI for local testing
npm install -g ganache-cli
```

## Deployment Instructions
### Compile and Deploy Contracts
1. Navigate to the `contracts/` directory.
2. Compile and deploy the contracts using Truffle.
```
# Compile the smart contract(s)
truffle compile

# Deploy to a local blockchain network (e.g., Ganache)
truffle migrate --network development
```

### Alternative Deployment using Hardhat
If using Hardhat instead of Truffle, follow these steps:
```
# Install Hardhat dependencies
npm install --save-dev hardhat @nomiclabs/hardhat-ethers ethers

# Compile the contracts
npx hardhat compile

# Deploy contracts (adjust network settings in hardhat.config.js)
npx hardhat run scripts/deploy.js --network localhost
```

## Running Python Clients
### Configuration
Update the `clients/config.json` file with appropriate smart contract and network information.

### Attacker Client
```
python clients/attacker.py
```

### Victim Client
```
python clients/victim.py
```

## Running Tests (Optional)
### Unit Tests 
Unit tests are written using `pytest` for Python code and the Solidity test suite.

```
# Python Tests
pytest tests/test_my_contract.py

# Solidity Tests (if any)
truffle test
```

## Example Usage
### Attacker Client
```
# clients/attacker.py
from web3 import Web3
import json

# Load contract details
with open('config.json') as config_file:
    config = json.load(config_file)

# Initialize web3 instance and contract
web3 = Web3(Web3.HTTPProvider(config['provider']))
contract = web3.eth.contract(address=config['contract_address'], abi=config['abi'])

# Example attacker logic
def attacker_function():
    pass  # Implement attack logic here

if __name__ == "__main__":
    attacker_function()
```

### Victim Client
```
# clients/victim.py
from web3 import Web3
import json

# Load contract details
with open('config.json') as config_file:
    config = json.load(config_file)

# Initialize web3 instance and contract
web3 = Web3(Web3.HTTPProvider(config['provider']))
contract = web3.eth.contract(address=config['contract_address'], abi=config['abi'])

# Example victim logic
def victim_function():
    pass  # Implement victim logic here

if __name__ == "__main__":
    victim_function()
```
