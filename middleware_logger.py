# API to records & serve logs from sniffer

# API libs
import json
from fastapi import Body, FastAPI
from fastapi.responses import FileResponse
from uvicorn import run

# Object Serialization
from pydantic import BaseModel

# Database Lib
from redis import Redis
# Fake hash generation
import string
import random

import sys

class Log(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    timestamp : float
    pkt       : str
    info      : dict

i_log     : int       = 0  #log counter
stack_log : list[Log] = [] #temp packet's stack send if (i_log == 64)

#fastapi init
app : FastAPI = FastAPI()

# Deliver logs to json format for client
@app.get("/logs")
async def serve_logs():
    logs : dict[int,Log] = db.json().jsonmget(["logs:0"])
    return {"logs":logs}


# Get 64 (or more) packets from logger
@app.post("/rlog")
async def download_logs(payload: dict = Body(...)):
    data_list   : list[str]  = payload["logs_stack"]
    shards_list : list[dict] = []

    for value in data_list:
        shards_list.append(json.loads(value))

    chars = string.ascii_uppercase + string.digits

    db.json().set(name="shard:%s"%(''.join(random.choices(chars, k=26))), path='$', obj={"shard":shards_list})

    return {"API":"added %s elements"%(payload.__len__())}

if __name__ == "__main__":
    db = Redis(host='localhost', port=6379, db=1)

    #redis join test
    try: db.ping()
    except: print("REDIS CAN'T BE JOINED !"); sys.exit(1)

    run(app=app,host="localhost",port=8080)