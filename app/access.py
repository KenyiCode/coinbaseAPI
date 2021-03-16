import json, hmac, hashlib, time, base64, requests
from config import *
from requests.auth import AuthBase

# Custom Authentication for Exchange
class CoinbaseExchangeAuth(AuthBase):
    def __init__(self, API_KEY, API_SECRETKEY, API_PASSPHRASE):
        self.api_key = API_KEY
        self.secret_key = API_SECRETKEY
        self.passphrase = API_PASSPHRASE
    
    def __call__(self, request):
        timestamp = str(time.time())
        message = timestamp + request.method + request.path_url + (request.body or b'').decode()
        hmac_key = base64.b64decode(self.secret_key)
        signature = hmac.new(hmac_key, message.encode(), hashlib.sha256)
        signature_b64 = base64.b64encode(signature.digest()).decode()

        request.headers.update({
            'CB-ACCESS-SIGN': signature_b64,
            'CB-ACCESS-TIMESTAMP': timestamp,
            'CB-ACCESS-KEY': self.api_key,
            'CB-ACCESS-PASSPHRASE': self.passphrase,
            'Content-Type': 'application/json'
        })

        return request 

api_url = API_URL

auth = CoinbaseExchangeAuth(API_KEY, API_SECRETKEY, API_PASSPHRASE)

r = requests.get(api_url + 'accounts/' + "d8e91252-87d7-48ea-ac5b-71c4cbffe070" + "/ledger" , auth=auth)

print(json.dumps(r.json(), indent=2))