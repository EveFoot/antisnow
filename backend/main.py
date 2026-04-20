from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware  # ВОТ ЭТОЙ СТРОКИ НЕ ХВАТАЛО
from sqlalchemy import Column, Integer, String, Float, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Antisnow Backend is Running!"}

@app.get("/health")
def health_check():
    return {"status": "ok"}