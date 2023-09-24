# twoPartyChat
A end-to-end encrypted two party chat (not for production!!)
## IMPORTANT
DO NOT USE FOR PRODUCTION
* Local private keys are not password protected
* Certificates are self signed

## Demonstration
https://youtu.be/G0JeT6CnNsM

## Usage
1. Create a venv and activate it

Unix:
```
python3 -m venv venv
source venv/bin/activate
```
Windows PowerShell:  
```
python -m venv venv
venv\Scripts\activate
```
2. Install requirements:  
`pip install -r requirements.txt`
3. Start host  
`python3 host.py`
4. Start client
`python3 client.py`
5. Enter the address of the server
6. Close with ^C
