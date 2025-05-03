import threading
import requests
import random
import json

# 定义项目的基础 URL
BASE_URL = "http://localhost:8080"

# 模拟对称加密模块的调用
def call_symmetric_aes_module():
    url = f"{BASE_URL}/aes"
    data = {
  "mode": "CBC",
  "key": "2b7e151628aed2a6abf7158809cf4f3c",
  "keylength": 128,
  "keyFormat": "Hex",
  "iv": "000102030405060708090A0B0C0D0E0F",
  "ivFormat": "Hex",
  "inputFormat": "Raw",
  "outputFormat": "Hex",
  "text": "6bc1bee22e409f96e93d7e117393172a",
  "action": "encrypt"
}
    response = requests.post(url, data=data)
    print(f"Symmetric Module Response: {response.status_code}, {response.text}")

# 模拟哈希算法模块的调用
def call_hash_PBKDF2_module():
    url = f"{BASE_URL}/sha"
    data = {
  "text": "EddieMurphy",
  "salt": "eddie",
  "key": 128,
  "hash": "SHA256",
  "iterations": 10
}
    response = requests.post(url, data=data)
    print(f"Hash Module Response: {response.status_code}, {response.text}")


# 模拟编码算法模块的调用
def call_encoding_hex4base64_module():
    url = f"{BASE_URL}/hex4base64"
    data = {"text": "RWRkaWVNdXJwaHk=", "action": "base642hex"}
    response = requests.post(url, data=data)
    print(f"Encoding Module Response: {response.status_code}, {response.text}")


# 模拟公钥加密模块签名的调用
def call_publickey_ECDSA_signal_module():
    url = f"{BASE_URL}/ecdsa"
    response_data = json.loads(call_publickey_pair_ECDSA_module())

    # 提取 privateKeyBase64 和 publicKeyBase64
    private_key = response_data["privateKeyBase64"]
    public_key = response_data["publicKeyBase64"]

    data = {
  "curve": "P224",
  "action": "sign",
  "publicKey": "",
  "privateKey": f"{private_key}",
  "signature": "",
  "text": "EddieMurphy"
}
    response = requests.post(url, data=data)
    print(f"Public Key ECDSA Signature Module Response: {response.status_code}, {response.text}")
    return public_key, response.text


# 模拟公钥加密模块验签的调用
def call_publickey_ECDSA_verify_module():
    url = f"{BASE_URL}/ecdsa"
    public_key, response_data = call_publickey_ECDSA_signal_module()
    response_data = json.loads(response_data)

    message = response_data["message"]
    signature = response_data["signature"]

    data = {
  "curve": "P224",
  "action": "verify",
  "publicKey": f"{public_key}",
  "signature": f"{signature}",
  "text": "EddieMurphy"
}
    response = requests.post(url, data=data)
    print(f"Public Key ECDSA Verify Module Response: {response.status_code}, {response.text}")


# 模拟公钥加密算法生成密钥对的调用
def call_publickey_pair_RSA1024_module():
    url = f"{BASE_URL}/generate_rsa"
    response = requests.post(url)
    print(f"Public Key Pair_RSA1024 Module Response: {response.status_code}, {response.text}")


def call_publickey_pair_ECDSA_module():
    url = f"{BASE_URL}/generate_ecdsa"
    data = {"curve": "P224"}
    response = requests.post(url=url, data=data)
    return response.text


# 多线程模拟高并发
def simulate_concurrent_requests():
    threads = []
    functions = [call_symmetric_aes_module, call_hash_PBKDF2_module, call_encoding_hex4base64_module, call_publickey_pair_RSA1024_module, call_publickey_pair_ECDSA_module, call_publickey_ECDSA_verify_module]

    # 创建 10000 个线程，随机调用四个模块
    for _ in range(10000):
        func = random.choice(functions)
        thread = threading.Thread(target=func)
        threads.append(thread)
        thread.start()

    # 等待所有线程完成
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    simulate_concurrent_requests()