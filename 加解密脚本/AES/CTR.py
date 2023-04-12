# python 3.9 cryptography==38.0.1

# 用于 Base64 编码和解码
import base64
# 用于生成随机数
import secrets
import json
import time

# 用于加密和解密
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# token = secrets.token_urlsafe(32)
token = "c09DIVI93_b9hkBT6aZrDjZj5dzuh8PqB4v7wpN1HAs"
# 随机16味唯一整数
counter_start = 4404103332002249


class AESCTREncrypt:
    # 定义一个块大小常量
    BLOCK_SIZE = 16

    # 传入加密密钥和计数器起始值
    def __init__(self, key: bytes, counter_start: int = 0):
        self.key = key
        self.counter_start = counter_start

    def encrypt(self, raw_text: bytes) -> str:
        # 生成初始化向量
        iv = self._generate_iv()
        cipher_text = self._process(raw_text, iv)
        # 拼接初始化向量和密文并使用base64编码
        return base64.b64encode(iv + cipher_text).decode()

    def decrypt(self, cipher_text: str) -> bytes:
        cipher_text = base64.b64decode(cipher_text)
        # 分离初始化向量和密文
        iv = cipher_text[:self.BLOCK_SIZE]
        cipher_text = cipher_text[self.BLOCK_SIZE:]
        raw_text = self._process(cipher_text, iv)
        return raw_text

    def _generate_iv(self) -> bytes:
        # 将计数器转换为二进制格式
        counter = self.counter_start.to_bytes(self.BLOCK_SIZE // 2, byteorder='big')
        # 将计数器和零字节填充组成初始化向量
        return counter + b"\x00" * (self.BLOCK_SIZE - self.BLOCK_SIZE // 2)

    def _process(self, data: bytes, iv: bytes) -> bytes:
        # 创建一个 AES-CTR 加密器，使用指定的加密算法、初始化向量和默认后端 进行加解密
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        try:
            return encryptor.update(data)
        finally:
            encryptor.finalize()


if __name__ == "__main__":
    key_bytes = base64.urlsafe_b64decode(token + '==')
    print(token)
    print(key_bytes)

    aes = AESCTREncrypt(key_bytes, counter_start=counter_start)

    data = {"xxx": "111111", "aa": "7777777", "timestamp": int(time.time())}
    text = json.dumps(data, separators=(',', ':')).encode()

    cipher_str = aes.encrypt(text)
    decrypted_raw_text = aes.decrypt(cipher_str)

    print(f"原始内容: {data}")
    print(f"加密内容: {cipher_str}")
    print(f"解密内容: {decrypted_raw_text}")
