import requests
import json

# Credentials from user
email = "coderstring9253@gmail.com"
password = "*****"  # User's actual password

resp = requests.post(
    "https://api.yeswehack.com/login",
    json={"email": email, "password": password},
    timeout=30
)
print(resp.status_code)
print(resp.text)
with open("/tmp/ywh_login2.json", "w") as f:
    json.dump(resp.json(), f)
