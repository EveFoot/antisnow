from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Antisnow Backend is Running!"}

@app.get("/health")
def health_check():
    return {"status": "ok"}