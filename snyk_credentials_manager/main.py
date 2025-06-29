from fastapi import FastAPI
from api.v1 import endpoints

app: FastAPI = FastAPI()

app.include_router(endpoints.router)
