#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    from scapy.all import *
    load_layer("tls")
except ImportError:
    print("Error: Scapy library not found. Please install it: pip install scapy", file=sys.stderr)
    sys.exit(1)

import binascii
import hmac
import hashlib
import math
import sys

# --- Cryptographic Helper Functions ---

# TLS 1.2 P_hash function (HMAC-based key expansion)
def p_hash(secret, seed, hash_alg, output_len):
    hmac_func = lambda key, data: hmac.new(key, data, hash_alg).digest()
    hash_len = hash_alg().digest_size
    num_iterations = math.ceil(output_len / hash_len)
    output = b''
    A_i = seed
    for i in range(1, num_iterations + 1):
        A_i = hmac_func(secret, A_i)
        output += hmac_func(secret, A_i + seed)
    return output[:output_len]

# TLS 1.2 Pseudo-Random Function
def prf_tls12(secret, label, seed, hash_alg, output_len):
    label_seed = label + seed
    return p_hash(secret, label_seed, hash_alg, output_len)

# Constructs the PSK Pre-Master Secret for TLS 1.2
def construct_psk_pms(psk_bytes):
    psk_len = len(psk_bytes)
    psk_len_bytes = psk_len.to_bytes(2, 'big')
    zero_bytes = b'\x00' * psk_len
    pms = psk_len_bytes + zero_bytes + psk_len_bytes + psk_bytes
    return pms

# --- Cipher Suite Parameters ---

# Defines key/MAC/IV lengths and algorithms for supported suites
CIPHER_SUITES = {
    "TLS_PSK_WITH_AES_128_CBC_SHA256": {
        "hash_alg": hashlib.sha256, "prf_hash_alg": hashlib.sha256,
        "mac_len": 32, "key_len": 16, "iv_len": 16, "is_aead": False,
    },
    "TLS_PSK_WITH_AES_256_CBC_SHA256": {
        "hash_alg": hashlib.sha256, "prf_hash_alg": hashlib.sha256,
        "mac_len": 32, "key_len": 32, "iv_len": 16, "is_aead": False,
    },
     "TLS_PSK_WITH_AES_128_GCM_SHA256": {
        "hash_alg": hashlib.sha256, "prf_hash_alg": hashlib.sha256,
        "mac_len": 0, "key_len": 16, "iv_len": 4, "is_aead": True, # iv_len is explicit nonce part
    },
    "TLS_PSK_WITH_AES_256_GCM_SHA384": {
        "hash_alg": hashlib.sha384, "prf_hash_alg": hashlib.sha384,
        "mac_len": 0, "key_len": 32, "iv_len": 4, "is_aead": True, # iv_len is explicit nonce part
    },
}

# --- Core Key Derivation Logic ---

# Derives TLS 1.2 PSK session keys from inputs
def derive_tls12_psk_keys(psk_hex, client_random_hex, server_random_hex, cipher_suite_name):
    if cipher_suite_name not in CIPHER_SUITES:
        raise ValueError(f"Cipher suite {cipher_suite_name} not defined.")

    params = CIPHER_SUITES[cipher_suite_name]
    prf_hash_alg = params["prf_hash_alg"]
    mac_len = params["mac_len"]
    key_len = params["key_len"]
    iv_len = params["iv_len"]
    is_aead = params["is_aead"]

    try:
        psk = binascii.unhexlify(psk_hex)
        client_random = binascii.unhexlify(client_random_hex)
        server_random = binascii.unhexlify(server_random_hex)
    except binascii.Error as e:
        raise ValueError(f"Invalid hexadecimal input: {e}")

    if len(client_random) != 32 or len(server_random) != 32:
        raise ValueError("Client/Server randoms must be 32 bytes.")

    pre_master_secret = construct_psk_pms(psk)
    master_secret_seed = client_random + server_random
    master_secret = prf_tls12(pre_master_secret, b"master secret", master_secret_seed, prf_hash_alg, 48)

    key_expansion_seed = server_random + client_random
    required_key_block_len = (mac_len * 2) + (key_len * 2) + (iv_len * 2)
    key_block = prf_tls12(master_secret, b"key expansion", key_expansion_seed, prf_hash_alg, required_key_block_len)

    keys = {}
    offset = 0
    if not is_aead:
        keys["client_write_MAC_key"] = key_block[offset:offset + mac_len]; offset += mac_len
        keys["server_write_MAC_key"] = key_block[offset:offset + mac_len]; offset += mac_len
    else:
        keys["client_write_MAC_key"] = None; keys["server_write_MAC_key"] = None

    keys["client_write_key"] = key_block[offset:offset + key_len]; offset += key_len
    keys["server_write_key"] = key_block[offset:offset + key_len]; offset += key_len
    keys["client_write_IV"] = key_block[offset:offset + iv_len]; offset += iv_len
    keys["server_write_IV"] = key_block[offset:offset + iv_len]; offset += iv_len

    result = {
        "pre_master_secret": pre_master_secret, "master_secret": master_secret,
        "key_block": key_block, "keys": keys
    }
    return result

# --- Cipher Suite ID Mapping ---

# Maps Scapy's numeric TLS Cipher Suite IDs to names used in this script
CIPHER_SUITE_IDS = {
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA256",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
}

# --- Main Scapy Pcap Processing Function ---

# Processes a single pcap file with a given PSK to find and derive keys
def process_pcap_for_psk_keys(pcap_file, psk_hex, target_stream=None):
    stream_contexts = {}
    stream_id_counter = 0
    last_successful_derivation = None

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: Pcap file not found: {pcap_file}", file=sys.stderr)
        return None
    except Scapy_Exception as e:
         print(f"Error reading pcap file '{pcap_file}': {e}", file=sys.stderr)
         return None

    print(f"Processing {len(packets)} packets from {pcap_file}...")

    for i, pkt in enumerate(packets):
        stream_key = None
        if IP in pkt and TCP in pkt:
            stream_key = tuple(sorted(((pkt[IP].src, pkt[TCP].sport), (pkt[IP].dst, pkt[TCP].dport))))
            if stream_key not in stream_contexts:
                 stream_id_counter += 1
                 stream_contexts[stream_key] = {
                     "id": stream_id_counter, "client_random": None,
                     "server_random": None, "cipher_suite_id": None,
                     "derived_keys": None
                 }
                 print(f"\n--- Analyzing Potential Stream #{stream_contexts[stream_key]['id']} ({stream_key}) ---")

            ctx = stream_contexts[stream_key]
            current_stream_id = ctx["id"]

        if TLS in pkt and stream_key:
            ctx = stream_contexts[stream_key]
            current_stream_id = ctx["id"]

            if ctx["derived_keys"] is None: # Only process if keys not already found for this stream
                try:
                    for record in pkt[TLS].records:
                        if hasattr(record, 'content_type') and record.content_type == 22: # Handshake
                            if hasattr(record, 'msg') and record.msg:
                                msg_content = record.msg[0]
                                if isinstance(msg_content, TLSClientHello) and ctx["client_random"] is None:
                                    ctx["client_random"] = msg_content.random_bytes
                                    print(f"Stream {current_stream_id}: Found Client Hello Random")
                                elif isinstance(msg_content, TLSServerHello) and ctx["server_random"] is None:
                                    ctx["server_random"] = msg_content.random_bytes
                                    ctx["cipher_suite_id"] = msg_content.cipher_suite
                                    print(f"Stream {current_stream_id}: Found Server Hello Random and Cipher Suite ID: {ctx['cipher_suite_id']} (0x{ctx['cipher_suite_id']:04X})")
                except Exception as e:
                    print(f"Stream {current_stream_id}: Warning - Error parsing TLS record in packet {i+1}: {e}", file=sys.stderr)

                # Try deriving keys if we have needed info
                if ctx["client_random"] and ctx["server_random"] and ctx["cipher_suite_id"] and ctx["derived_keys"] is None:
                    cipher_suite_name = CIPHER_SUITE_IDS.get(ctx["cipher_suite_id"])
                    if cipher_suite_name:
                        print(f"Stream {current_stream_id}: Attempting key derivation for {cipher_suite_name}...")
                        try:
                            derived_data = derive_tls12_psk_keys(
                                psk_hex,
                                binascii.hexlify(ctx["client_random"]).decode(),
                                binascii.hexlify(ctx["server_random"]).decode(),
                                cipher_suite_name
                            )
                            ctx["derived_keys"] = derived_data
                            last_successful_derivation = derived_data
                            print(f"Stream {current_stream_id}: Successfully derived keys.")
                            # Print details on success
                            print("-" * 30)
                            print("Derived Secrets and Keys:")
                            print(f"  Pre-Master Secret (hex): {binascii.hexlify(derived_data['pre_master_secret']).decode()}")
                            print(f"  Master Secret (hex):     {binascii.hexlify(derived_data['master_secret']).decode()}")
                            print(f"  Key Block (hex):         {binascii.hexlify(derived_data['key_block']).decode()}")
                            print("  Session Keys:")
                            for key_name, key_value in derived_data["keys"].items():
                                if key_value is not None:
                                    print(f"    {key_name:<24}: {binascii.hexlify(key_value).decode()}")
                                else:
                                    print(f"    {key_name:<24}: N/A (Likely AEAD Cipher)")
                            print("-" * 30)

                        except ValueError as e:
                            print(f"Stream {current_stream_id}: Key derivation failed: {e}", file=sys.stderr)
                        except Exception as e:
                            print(f"Stream {current_stream_id}: Unexpected error during key derivation: {e}", file=sys.stderr)
                    else:
                        print(f"Stream {current_stream_id}: Cipher suite ID {ctx['cipher_suite_id']} (0x{ctx['cipher_suite_id']:04X}) is not a PSK suite supported.")

            # Look for App Data if keys were derived
            if ctx["derived_keys"]:
                 try:
                     for record in pkt[TLS].records:
                         if hasattr(record, 'content_type') and record.content_type == 23: # Application Data
                            print(f"Stream {current_stream_id}: Found encrypted Application Data (Packet ~{i+1})")
                            # Decryption logic placeholder
                 except Exception as e:
                     print(f"Stream {current_stream_id}: Warning - Error parsing TLS App Data record in packet {i+1}: {e}", file=sys.stderr)

    return last_successful_derivation

# --- Main Execution Block ---

if __name__ == "__main__":
    # --- USER CONFIGURATION ---

    pcap_files = [
        "your_capture1.pcap",          # <<< REPLACE with your first pcap file path
        "/path/to/your_capture2.pcapng", # <<< REPLACE with your second pcap file path
    ]

    psk_hex_list = [
        "aabbccddeeff0123456789abcdef",       # <<< REPLACE with your first PSK hex string
        "11223344556677889900aabbccddeeff",   # <<< REPLACE with your second PSK hex string
    ]

    # --- END USER CONFIGURATION ---

    print("Starting batch processing...")
    print(f"Files to process: {len(pcap_files)}")
    print(f"PSKs to try per file: {len(psk_hex_list)}")

    successful_combinations = []

    for pcap_file in pcap_files:
        for i, psk_hex in enumerate(psk_hex_list):
            psk_identifier = f"{psk_hex[:8]}..." if len(psk_hex) > 8 else psk_hex
            print(f"\n{'='*70}")
            print(f"== Attempting File: '{pcap_file}' with PSK #{i+1} ('{psk_identifier}') ==")
            print(f"{'='*70}")

            try:
                derived_keys_info = process_pcap_for_psk_keys(
                    pcap_file, psk_hex, target_stream=None
                )

                if derived_keys_info and 'master_secret' in derived_keys_info:
                    print(f"\n>>> SUCCESS: Key derivation successful for File '{pcap_file}' with PSK #{i+1} ('{psk_identifier}') <<<")
                    successful_combinations.append({
                        "file": pcap_file, "psk_index": i+1,
                        "psk_identifier": psk_identifier,
                        "master_secret": binascii.hexlify(derived_keys_info['master_secret']).decode()
                    })
                else:
                    print(f"\nINFO: No keys derived for File '{pcap_file}' with PSK #{i+1} ('{psk_identifier}').")

            except Exception as e:
                print(f"\nERROR: Unexpected error during processing of File '{pcap_file}' with PSK #{i+1}: {e}", file=sys.stderr)

            print(f"{'-'*70}")

    # Batch Summary
    print("\n\n" + "="*70)
    print(" Batch Processing Summary")
    print("="*70)
    if successful_combinations:
        print(f"Found {len(successful_combinations)} successful derivation(s):")
        for success in successful_combinations:
            print(f"  - File: '{success['file']}', PSK Index: {success['psk_index']} ('{success['psk_identifier']}'), Master Secret starts with: {success['master_secret'][:16]}...")
    else:
        print("No successful key derivations found.")
    print("="*70)
    print("Script finished.")
