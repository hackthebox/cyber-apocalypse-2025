# EldoriaGate

![img](./assets/ChallengeBanner.png)
---
<p align="center">
    <img src="./assets/EventBanner.jpg" />
</p>

15<sup>th</sup> Mar 2024 \
Prepared By: perrythepwner \
Challenge Author(s): **perrythepwner** \
Difficulty: <font color=orange>Medium</font>

---

# TLDR
EVM challenge about solidity type checking / overflow checks bypass via yul assembly operations. Passing exactly 255 as `msg.value` and a valid passphrase to authenticate, we become authenticated users and the roles bitmask wiill overflow causing UB.

# Description
> At long last, you stand before the EldoriaGate, the legendary portal, the culmination of your perilous journey. Your escape from this digital realm hinges upon passing this final, insurmountable barrier. Your fate rests upon the passage through these mythic gates.  
These are no mere gates of stone and steel. They are a living enchantment, a sentinel woven from ancient magic, judging all who dare approach. The Gate sees you, divining your worth, assigning your place within Eldoria's unyielding order. But you seek not a place within their order, but freedom beyond it. Become the Usurper. Defy the Gate's ancient magic. Pass through, yet leave no trace, no mark of your passing, no echo of your presence. Become the unseen, the unwritten, the legend whispered but never confirmed.  
Outwit the Gate. Become a phantom, a myth. Your escape, your destiny, awaits. 

# Skills Required
- Basic understanding of Solidity and smart contracts
- Interaction with smart contracts
- Basic understanding of yul assembly

# Skills Learned
- Bypassing solidty type checker / overflow checks 

# Challenge Scenario
We're given two smart contracts, `EldoriaGate.sol` and `EldoriaGateKernel.sol`:
- `EldoriaGate.sol`: Deploys the kernel contract in its constructor and provides a public `enter()` function. A correct passphrase plus a suitable `msg.value` will authenticate the caller via the kernel with given roles. **Acts as the "frontend" for the `EldoriaGateKernel.sol`**.
- `EldoriaGateKernel.sol`: Manages internal logic for authentication (`authenticate()`) and identity evaluation (`evaluateIdentity()`) using low level yul assembly. **Effectively acts as the optimized "backend" for `EldoriaGate.sol`**.

# Analyzing the Source Code

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { EldoriaGate } from "./EldoriaGate.sol";

contract Setup {
    EldoriaGate public TARGET;
    address public player;

    event DeployedTarget(address at);

    constructor(bytes4 _secret, address _player) {
        TARGET = new EldoriaGate(_secret);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public returns (bool) {
        return TARGET.checkUsurper(player);
    }
}
```

As we read in the setup contract, the needed condition to solve the challenge is to make the `EldoriaGate::checkUsurper()` function returns true. We will see later on the details of that. 


## `EldoriaGate.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/***
    Malakar 1b:22-28, Tales from Eldoria - Eldoria Gates
  
    "In ages past, where Eldoria's glory shone,
     Ancient gates stand, where shadows turn to dust.
     Only the proven, with deeds and might,
     May join Eldoria's hallowed, guiding light.
     Through strict trials, and offerings made,
     Eldoria's glory, is thus displayed."
  
                   ELDORIA GATES
             *_   _   _   _   _   _ *
     ^       | `_' `-' `_' `-' `_' `|       ^
     |       |                      |       |
     |  (*)  |     .___________     |  \^/  |
     | _<#>_ |    //           \    | _(#)_ |
    o+o \ / \0    ||   =====   ||   0/ \ / (=)
     0'\ ^ /\/    ||           ||   \/\ ^ /`0
       /_^_\ |    ||    ---    ||   | /_^_\
       || || |    ||           ||   | || ||
       d|_|b_T____||___________||___T_d|_|b
  
***/

import { EldoriaGateKernel } from "./EldoriaGateKernel.sol";

contract EldoriaGate {
    EldoriaGateKernel public kernel;

    event VillagerEntered(address villager, uint id, bool authenticated, string[] roles);
    event UsurperDetected(address villager, uint id, string alertMessage);
    
    struct Villager {
        uint id;
        bool authenticated;
        uint8 roles;
    }

    constructor(bytes4 _secret) {
        kernel = new EldoriaGateKernel(_secret);
    }

    function enter(bytes4 passphrase) external payable {
        bool isAuthenticated = kernel.authenticate(msg.sender, passphrase);
        require(isAuthenticated, "Authentication failed");

        uint8 contribution = uint8(msg.value);        
        (uint villagerId, uint8 assignedRolesBitMask) = kernel.evaluateIdentity(msg.sender, contribution);
        string[] memory roles = getVillagerRoles(msg.sender);
        
        emit VillagerEntered(msg.sender, villagerId, isAuthenticated, roles);
    }

    function getVillagerRoles(address _villager) public view returns (string[] memory) {
        string[8] memory roleNames = [
            "SERF", 
            "PEASANT", 
            "ARTISAN", 
            "MERCHANT", 
            "KNIGHT", 
            "BARON", 
            "EARL", 
            "DUKE"
        ];

        (, , uint8 rolesBitMask) = kernel.villagers(_villager);

        uint8 count = 0;
        for (uint8 i = 0; i < 8; i++) {
            if ((rolesBitMask & (1 << i)) != 0) {
                count++;
            }
        }

        string[] memory foundRoles = new string[](count);
        uint8 index = 0;
        for (uint8 i = 0; i < 8; i++) {
            uint8 roleBit = uint8(1) << i; 
            if (kernel.hasRole(_villager, roleBit)) {
                foundRoles[index] = roleNames[i];
                index++;
            }
        }

        return foundRoles;
    }

    function checkUsurper(address _villager) external returns (bool) {
        (uint id, bool authenticated , uint8 rolesBitMask) = kernel.villagers(_villager);
        bool isUsurper = authenticated && (rolesBitMask == 0);
        emit UsurperDetected(
            _villager,
            id,
            "Intrusion to benefit from Eldoria, without society responsibilities, without suspicions, via gate breach."
        );
        return isUsurper;
    }
}

```

From the code:
- Each account (**Villager**) has a unique id, a boolean flag indicating if they are authenticated, and a bitmask of roles. The bitmask is used by the backend assembly implementation for convenience and optimization purposes. This is decoded later on human readable roles via the `getVillagerRoles()` function.
- `enter()` calls `EldoriaGateKernel::authenticate()` using the given passphrase. If correct, it then calls `EldoriaGateKernel::evaluateIdentity()` with `msg.value` casted as `uint8`.
- `checkUsurper()` checks if the caller is authenticated and has no roles assigned. If so, it emits an event with a message and returns true. Based on that we understand that in order to solve the challenge we have to somehow authenticate while "bypassing" the `EldoriaGateKernel::evaluateIdentity()` steps.

## `EldoriaGateKernel.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

contract EldoriaGateKernel {
    bytes4 private eldoriaSecret;
    mapping(address => Villager) public villagers;
    address public frontend;

    uint8 public constant ROLE_SERF     = 1 << 0;
    uint8 public constant ROLE_PEASANT  = 1 << 1;
    uint8 public constant ROLE_ARTISAN  = 1 << 2;
    uint8 public constant ROLE_MERCHANT = 1 << 3;
    uint8 public constant ROLE_KNIGHT   = 1 << 4;
    uint8 public constant ROLE_BARON    = 1 << 5;
    uint8 public constant ROLE_EARL     = 1 << 6;
    uint8 public constant ROLE_DUKE     = 1 << 7;
    
    struct Villager {
        uint id;
        bool authenticated;
        uint8 roles;
    }

    constructor(bytes4 _secret) {
        eldoriaSecret = _secret;
        frontend = msg.sender;
    }

    modifier onlyFrontend() {
        assembly {
            if iszero(eq(caller(), sload(frontend.slot))) {
                revert(0, 0)
            }
        }
        _;
    }

    function authenticate(address _unknown, bytes4 _passphrase) external onlyFrontend returns (bool auth) {
        assembly {
            let secret := sload(eldoriaSecret.slot)            
            auth := eq(shr(224, _passphrase), secret)
            mstore(0x80, auth)
            
            mstore(0x00, _unknown)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x00, 0x40)
            
            let packed := sload(add(villagerSlot, 1))
            auth := mload(0x80)
            let newPacked := or(and(packed, not(0xff)), auth)
            sstore(add(villagerSlot, 1), newPacked)
        }
    }

    function evaluateIdentity(address _unknown, uint8 _contribution) external onlyFrontend returns (uint id, uint8 roles) {
        assembly {
            mstore(0x00, _unknown)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x00, 0x40)

            mstore(0x00, _unknown)
            id := keccak256(0x00, 0x20)
            sstore(villagerSlot, id)

            let storedPacked := sload(add(villagerSlot, 1))
            let storedAuth := and(storedPacked, 0xff)
            if iszero(storedAuth) { revert(0, 0) }

            let defaultRolesMask := ROLE_SERF
            roles := add(defaultRolesMask, _contribution)
            if lt(roles, defaultRolesMask) { revert(0, 0) }

            let packed := or(storedAuth, shl(8, roles))
            sstore(add(villagerSlot, 1), packed)
        }
    }

    function hasRole(address _villager, uint8 _role) external view returns (bool hasRoleFlag) {
        assembly {
            mstore(0x0, _villager)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x0, 0x40)
        
            let packed := sload(add(villagerSlot, 1))
            let roles := and(shr(8, packed), 0xff)
            hasRoleFlag := gt(and(roles, _role), 0)
        }
    }
}
```

The "backend" contract `EldoriaGateKernel.sol` is where the magic happens. It uses low-level yul assembly to optimize the logic implementations. However, things can go easily wrong when assembly is being used extensively.
- The `authenticate()` function is responsible for verifying that a given passphrase matches the contract’s secret. It takes the input passhprase (`_passphrase`) and the private storage variable `eldoriaSecret`, to compare them. If the passphrase is correct, it sets the authentication flag in the villager’s storage slot. ***This is easily done as private variables in Solidity can still be read since the contract's storage is public***. This is also stated in the Solidity documentation [here](https://docs.soliditylang.org/en/latest/contracts.html#state-variable-visibility). However a good reminder to always keep in mind is that ***in the blockchain everything is public***.

- The `evaluateIdentity()` function is called by the frontend once a villager is authenticated, this function finalizes their identity:
    1) It computes a unique id for the villager by hashing the account address.
    2) It then asserts that the villager is authenticated (from the previous step) by checking the authentication flag in the stored slot.  
    3) After confirming authentication, it assigns a default role (`ROLE_SERF`) and adds extra roles based on the provided `_contribution` (interpreted as an 8‑bit value of the wei sent initially as `msg.value`).  

    The final roles are packed into a single byte and stored in the villager’s storage slot. ***The issue here is that even though the `_contribution` variable it's a `uint8` in the frontend code and in the arguments of the function, in assembly there is no concept of "types", so they are all treated as low level 32-byte values (256 bits, hence the EVM slot size). This means that each operation on the roles bitmask will always be done as uint256, even if later on that will be casted to lower representations. Also, notice how the default bitmask is `ROLE_SERF` which is `1`, and the `_contribution` is added to that, so if we pass exactly `255` as `_contribution` we will overflow the bitmask.***  
    However, some concerns on that can arise because of several possible limitations:
    - overflows in Solidity are checked by default at runtime since version 0.8.0, so the contract should revert if an overflow occurs. However, ***that doesn't apply to assembly as it is unsafe by nature***.
    - the `lt(roles, defaultRolesMask)` check is done to ensure that the roles bitmask is not less than the default bitmask, which effectively acts as a cheap overflow check. However, as we mentioned before, ***this is done as a uint256 comparison, so it will always be false in our scenario***.
    - finally, even though the `roles` variable is casted to `uint8` before being stored, the overflow will have already happened at that point, meaning that ***the value `256 modulo type(uint8).max` will result in a zero-value bitmask***.

- `hasRole()` view function allows checking if a specific villager has a specific role. It performs a bitwise AND operation with the desidered role bitmask to determine whether the villager possesses that role or not.

The goal at this point is clear: by passing exactly `255` as `_contribution` (i.e. 255 wei as `msg.value`) and the passphrase, we can authenticate as a villager with a zero-value bitmask, thus becoming an authenticated user without any roles assigned. This will satisfy the `checkUsurper()` condition.

# Exploitation

This will be the pseudocode of what just described:

```py
csend(target_addr, "enter(bytes4)", "0xdeadfade", value=255)
assert ccall(setup_addr, "isSolved()(bool)").strip() == "true"
```

see the full exploitation script [here](./htb/solver.py).

---
> `HTB{unkn0wn_1ntrud3r_1nsid3_Eld0r1a_gates}`
