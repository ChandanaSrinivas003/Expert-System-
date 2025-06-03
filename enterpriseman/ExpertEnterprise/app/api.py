# app/api.py

from fastapi import FastAPI
from fastapi import FastAPI, Body
from fastapi import FastAPI, Body, Depends

from app.model import PostSchema, UserSchema, UserLoginSchema
from app.auth.auth_bearer import JWTBearer
from app.auth.auth_handler import signJWT
from app.model import PostSchema, UserSchema, UserLoginSchema
from app.auth.auth_handler import signJWT
from app.model import PostSchema, HeartDiseasModel
from app.TrainigSystem import start_training,start_testing

posts = [
    {
        "id": 1,
        "title": "Enterprice SYstem",
        "content": "he development of artificial intelligence affects people's lives and all walks of life, while promoting the improvement of productivity. With the deepening of artificial intelligence technology, the impact on enterprise management theory and practice began to highlight, therefore, enterprise management and decision makers need to correct understanding of artificial intelligence, rationalize the use of decentralized management structure, conform to the trend of the times management thinking, to ensure that artificial intelligence can promote the improvement of enterprise efficiency. This paper studies the influence and impact of artificial intelligence on enterprise management theory, and puts forward practical countermeasures in combination with some problems faced ..."
    }
]

users = []

app = FastAPI()


@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to your Expert SYstems!."}


@app.get("/posts", tags=["posts"])
async def get_posts() -> dict:
    return { "data": posts }


@app.get("/posts/{id}", tags=["posts"],dependencies=[Depends(JWTBearer())])
async def get_single_post(id: int) -> dict:
    if id > len(posts):
        return {
            "error": "No such post with the supplied ID."
        }

    for post in posts:
        if post["id"] == id:
            return {
                "data": post
            }
# app/api.py

@app.post("/posts", tags=["posts"])
async def add_post(post: PostSchema) -> dict:
    post.id = len(posts) + 1
    posts.append(post.dict())
    return {
        "data": "post added."
    }

@app.post("/user/signup", tags=["Expert systems"])
async def create_user(user: UserSchema = Body(...)):
    users.append(user) # replace with db call, making sure to hash the password first
    return signJWT(user.email)


def check_user(data: UserLoginSchema):
    for user in users:
        if user.email == data.email and user.password == data.password:
            return True
    return False

@app.post("/user/login", tags=["Expert systems"])
async def user_login(user: UserLoginSchema = Body(...)):
    if check_user(user):
        return signJWT(user.email)
    return {
        "error": "Wrong login details!"
    }        




@app.post("/posts", dependencies=[Depends(JWTBearer())], tags=["posts"])
async def add_post(post: PostSchema) -> dict:
    post.id = len(posts) + 1
    posts.append(post.dict())
    return {
        "data": "post added."
    }

@app.get('/training',dependencies=[Depends(JWTBearer())], tags=["Expert systems"])
async def training_system()->dict:
    result = await start_training()
    return result

@app.post('/expertResult',dependencies=[Depends(JWTBearer())],tags=["Expert systems"])
async def expertAnalysis(headtDiseas: HeartDiseasModel)->dict:
    data = headtDiseas.dict()
    test_data = list(data.values())
    print(test_data, type(test_data))
    result = await start_testing(test_data)
    print(result)
    return result