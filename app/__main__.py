"""Run the API locally: python -m app"""
import uvicorn

if __name__ == "__main__":
    # 127.0.0.1 keeps the service on this machine only.
    uvicorn.run("app.main:create_app", factory=True, host="127.0.0.1", port=8000)
