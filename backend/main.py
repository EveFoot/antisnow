from fastapi import FastAPI

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # В идеале здесь должен быть твой IP, но для теста ставим "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Antisnow Backend is Running!"}

@app.get("/health")
def health_check():
    return {"status": "ok"}