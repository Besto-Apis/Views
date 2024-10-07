from flask import Flask, jsonify, Response
import requests,os,time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor
import requests
import base64
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

class ApiClient:
    username = "Besto-Apis"
    repo = "Views"
    file_path = "ses.txt"
    token = "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"
    KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
    HEADERS = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB46',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo5MjgwODkyMDE4LCJuaWNrbmFtZSI6IkJZVEV2R3QwIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6ImYzNGQyMjg0ZWJkYmFkNTkzNWJjOGI1NTZjMjY0ZmMwIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIxLjEwNS41IiwiZW11bGF0b3Jfc2NvcmUiOjAsImlzX2VtdWxhdG9yIjpmYWxzZSwiY291bnRyeV9jb2RlIjoiRUciLCJleHRlcm5hbF91aWQiOjMyMzQ1NDE1OTEsInJlZ19hdmF0YXIiOjEwMjAwMDAwNSwic291cmNlIjoyLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzE0NjYyMzcyLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6ImlvcyIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNDUiLCJleHAiOjE3MjIwNTkxMjF9.yYQZX0GeBMeBtMLhyCjSV0Q3e0jAqhnMZd3XOs6Ldk4',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.common.ggbluefox.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    def __init__(self, token, user_id, md5):
        self.token = token
        self.user_id = user_id
        self.md5 = md5
    @staticmethod
    def get_github_file():
        try:
        	url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        	headers = {"Accept": "application/vnd.github.v3+json"}
        	response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, token))
        	if response.status_code == 200:
        		return response.json()
        	else:
        		return None
        except Exception as e:
        	return None
    @staticmethod        	
    def create_github_file(initial_content):
        	try:
        		encoded_content = base64.b64encode(initial_content.encode()).decode()
        		data = {
            "message": "إنشاء ملف جديد",
            "content": encoded_content
        }
        		url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        		headers = {"Accept": "application/vnd.github.v3+json"}
        		response = requests.put(url, json=data, headers=headers, auth=HTTPBasicAuth(username, token))
        		print(response.status_code)
        	except Exception as e:
        		return False
    @staticmethod
    def delete_github_file():
        try:
        	file_content = get_github_file()
        	if not file_content:
        		return False
        	sha = file_content['sha']
        	data = {
            "message": "حذف الملف",
            "sha": sha
            }
        	url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        	headers = {"Accept": "application/vnd.github.v3+json"}
        	response = requests.delete(url, json=data, headers=headers, auth=HTTPBasicAuth(username, token))
        	return response.status_code == 200
        except Exception as e:
        	return False

    @staticmethod
    def encrypt_api(plain_text):
        plain_text = bytes.fromhex(plain_text)
        cipher = AES.new(ApiClient.KEY, AES.MODE_CBC, ApiClient.IV)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()

    @staticmethod
    def convert_to_hex(payload):
        return ''.join([f'{byte:02x}' for byte in payload])

    @staticmethod
    def convert_to_bytes(payload):
        return bytes.fromhex(payload)

    def bes_token(self):
        old_access_token = "92c3a25e10e0b2c14e995e62f6a2754a1c9bb17cbeb0b10c7075287a5ee678b0"
        old_open_id = "f241ec77cd76824a8cd48011489d64cc"
        time.sleep(0.2)
        data = bytes.fromhex('1a13323032342d30392d30342030373a35383a3436220966726565206669726528013a07312e3130362e32423c416e64726f6964204f5320372e312e32202f204150492d32352028514b51312e3139303832352e3030322f31372e303234302e323030342e392d30294a0848616e6468656c645206524f474552535a045749464960800f68b80872033234307a1b41524d7637205646507633204e454f4e207c2032303030207c20348001d71b8a010f416472656e6f2028544d292035343092010d4f70656e474c20455320332e309a012b476f6f676c657c64333031303831302d383639392d346234612d393734332d393362363832343231646364a2010d34312e3233352e34372e313130aa0102656eb201206632343165633737636437363832346138636434383031313438396436346363ba010134c2010848616e6468656c64ca010f6173757320415355535f5a30315144ea014039326333613235653130653062326331346539393565363266366132373534613163396262313763626562306231306337303735323837613565653637386230f00101ca0206524f47455253d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003f6ee07e803e59207f003fe3df803e63080048fc6078804f6ee0790048fc6079804f6ee07c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044831643964626263353561613435646434396631333133343562613832353332627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313137363833b205094f70656e474c455332b805ff7fc00504ca05251354164553550a034a000f4758594c0b146d0c050c5d0d200911046b1502520a4768590166d20505436169726fda050143e0058831ea0507616e64726f6964f2055c4b717348547746642b3437327575355a4d7975464b4a6e7551332b31486b62517771587a76665a506f4b4f6c733334505179426a4a2b45487958626f6c39634d306d31534b436a387779416b53426a5345626b5031617a6e626a673df805fbe406880601')
        data = data.replace(old_open_id.encode(), self.user_id.encode())
        data = data.replace(old_access_token.encode(), self.token.encode())
        encrypted_data = self.encrypt_api(data.hex())
        final_payload = bytes.fromhex(encrypted_data)
        response = requests.post(self.URL, headers=self.HEADERS, data=final_payload, verify=False)
        if response.status_code == 200:
            if len(response.text) < 10:
                return False
            base64_token = response.text[response.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
            second_dot_index = base64_token.find(".", base64_token.find(".") + 1)

            time.sleep(0.2)
            base64_token = base64_token[:second_dot_index + 44]
            print(' - Jwt Token : ', base64_token)
            create_github_file(initial_content=base64_token)
if __name__ == "__main__":
    TOKEN = 'f34ddba131b8751fd430f87f11c60ff6a22a4431c7b5a0f1a919856ca65caacb'
    USER_ID = '965997b0153c5558db1bb799ae2bc4c7'
    MD5 = '7428b253defc164018c604a1ebbfebdf'

    client = ApiClient(TOKEN, USER_ID, MD5)
    try:open('sex.txt','r').read()
    except FileNotFoundError:
    	client.bes_token()


username = "Besto-Apis"
repo = "Views"
file_path = "sex.txt"
token = "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"

def get_github_file():
    try:
        url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, token))
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        return None

def create_github_file(initial_content="مرحبا"):
    try:
        encoded_content = base64.b64encode(initial_content.encode()).decode()

        data = {
            "message": "إنشاء ملف جديد",
            "content": encoded_content
        }

        url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        response = requests.put(url, json=data, headers=headers, auth=HTTPBasicAuth(username, token))

        print(response.status_code)
    except Exception as e:
        return False

def update_github_file(updated_content):
    try:
        file_content = get_github_file()
        if not file_content:
            return False

        sha = file_content['sha']
        encoded_content = base64.b64encode(updated_content.encode()).decode()

        data = {
            "message": "تحديث الملف",
            "content": encoded_content,
            "sha": sha
        }

        url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        response = requests.put(url, json=data, headers=headers, auth=HTTPBasicAuth(username, token))

        return response.status_code == 200
    except Exception as e:
        return False

def delete_github_file():
    try:
        file_content = get_github_file()
        if not file_content:
            return False

        sha = file_content['sha']

        data = {
            "message": "حذف الملف",
            "sha": sha
        }

        url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        response = requests.delete(url, json=data, headers=headers, auth=HTTPBasicAuth(username, token))

        return response.status_code == 200
    except Exception as e:
        return False
        

DEC = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', 
       '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 
       'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 
       'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 
       'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 
       'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 
       'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 
       'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
XXX = ['1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', 
       '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', 
       '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', 
       '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', 
       '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', 
       '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', 
       '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', 
       '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']

def encrypt_id(x):
    x = int(x)
    x = x / 128 
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return DEC[int(m)] + DEC[int(n)] + DEC[int(z)] + DEC[int(y)] + XXX[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return DEC[int(n)] + DEC[int(z)] + DEC[int(y)] + XXX[int(x)]
    return DEC[int(x)]
    
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def like(token, id):
    url = 'https://202.81.99.18/LikeProfile'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB46',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    data = bytes.fromhex(encrypt_api(f'08{encrypt_id(id)}12024d45'))
    
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code == 200:
    	print(' - Good Sends Likes ')
    else:
         print()
         
def name(tt,id):
	    url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
	    headers = {
	        'X-Unity-Version': '2018.4.11f1',
	        'ReleaseVersion': 'OB46',
	        'Content-Type': 'application/x-www-form-urlencoded',
	        'X-GA': 'v1 1',
	        'Authorization': f'Bearer {tt}',
	        'Content-Length': '16',
	        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
	        'Host': 'clientbp.ggblueshark.com',
	        'Connection': 'Keep-Alive',
	        'Accept-Encoding': 'gzip'
	    }
	    data = bytes.fromhex(encrypt_api(f'08{encrypt_id(id)}12024d45'))
	    response = requests.post(url, headers=headers, data=data, verify=False)
	    if response.status_code == 200:
	    	os.system('clear')
	    	print('')
	    	print(' - Done Send View Of The Owner Bot ; Good Response !')
	    	print(' - Devloper : Besto | @BestoPy')
	    	print('')
	    else:
	    	os.system('clear')
	    	print()
	    	print(' - Remove Last Jwt Token Done √')
	    	delete_github_file()	    	
	    	print(' - Bad Token')
	    	client.bes_token()
	    	print(' - Done Get New Jwt Token Of C4 Team Bot !')
	    	
def get(id):
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("Erorr!")
    except:
        return("No Name!")	   
	    	
@app.route('/Besto/<id>')

@app.route('/Besto/<id>/Key=C4-LIKE-6KI9')
def send_number(id):
    print(f" - Likes Send To Id : {id}")  # Log received ID
    try:
        with open('sex.txt', 'r') as token_file:
            tt = token_file.readline().strip()

        with open('Jwt_Token.txt', 'r') as token_file:
            tokens = token_file.read().splitlines()

        results = []
        with ThreadPoolExecutor(max_workers=500) as executor:
            results = list(executor.map(lambda token: like(token, id), tokens))
        success_count = sum(1 for result in results if result == 200)
        response_message = []
        if success_count > 0:
            response_message.append(' - Status : Good | Online !')
            response_message.append(f" - Done Send Likes To Id : {id}")
            print(tt)
            name(tt, id)
            namee = get(id)
            import subprocess
            response_message.append(f' - Name : {namee}')
            response_message.append(" - Dev : Besto | @BestoPy")
        else:
            return Response(" - Bad Tokens ! Wait For Token Update It!", status=403)  
            

        return Response("\n".join(response_message), mimetype='text/plain')
    
    except Exception as e:
        return Response(f" - Error : {str(e)}", status=500)

if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0')
    
    
    
    
    
    
    
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
# By Besto !
