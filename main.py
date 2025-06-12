from fastapi import FastAPI
from models import Learner
from queue_manager import add_to_queue
from match_worker import start_worker

app = FastAPI()

@app.on_event("startup")
def startup_event():
    start_worker()

@app.post("/join-queue/")
def join_queue(learner: Learner):
    add_to_queue(learner)
    return {"message": f"{learner.name} added to the {learner.match_type} queue"}