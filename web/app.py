from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
from keras.applications import InceptionV3
from keras.applications.inception_v3 import preprocess_input
from tensorflow.keras.applications import imagenet_utils
from tensorflow.keras.preprocessing.image import img_to_array
import requests
from io import BytesIO
from PIL import Image
import numpy as np

app=Flask(__name__)
api=Api(app)
client=MongoClient("mongodb://db:27017")
db=client.Similarity
users=db["Users"]
pretrained_model = InceptionV3(weights="imagenet")

def gen_ret_dict(status, msg):
    retJson={
        "status":status,
        "msg":msg
    }
    return retJson

def verify_credentials(username,password):
    if not userExist(username):
        return gen_ret_dict(301, "Invalid Username"), True

    if not verifyPw(username,password):
        return gen_ret_dict(302, "Invalid password"), True

    return None, False

def userExist(username):
    if users.count_documents({"Username":username})==0:
        return False
    else:
        return True

def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens

def verifyPw(username,password):
    hashed_pw=users.find({
        "Username":username
    })[0]["Password"]
    return bcrypt.checkpw(password.encode('utf8'),hashed_pw)

class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData['username']
        password = postedData['password']

        if userExist(username):
            return jsonify(gen_ret_dict(301,"Invalid Username"))

        hashed_pw=bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())

        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 6
        })
        return jsonify(gen_ret_dict(200,"You've successfully signed up to API"))


class Classify(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData['username']
        password = postedData['password']
        url = postedData['url']

        retJson, error = verify_credentials(username,password)
        if error:
            return jsonify(retJson)

        if countTokens(username)<=1:
            return jsonify(gen_ret_dict(303,"You are out of tokens, please refill"))

        if not url:
            return jsonify(({"error":"No url provided"}),400)

        response=requests.get(url)
        img=Image.open(BytesIO(response.content))

        img=img.resize((299,299))
        img_array=img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)

        prediction=pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top=5)

        retJson={}

        for pred in actual_prediction[0]:
            retJson[pred[1]]=float(pred[2]*100)

        current_tokens = countTokens(username)
        users.update_one({
            "username": username
        }, {
            "$set": {
                "Tokens": current_tokens - 1
            }
        })

        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData['username']
        password = postedData['password']
        refill_amount = postedData['refill']
        admin_pass='abc123'

        if not userExist(username):
           return jsonify(gen_ret_dict(301,"Invalid Username"))

        if admin_pass!=password:
            return jsonify(gen_ret_dict(304,"Invalid admin password"))

        users.update_one({
            "Username": username
        },{
            "$set":{
                "Tokens": refill_amount
            }
        })
        return jsonify(gen_ret_dict(200,"refilled successfully"))




api.add_resource(Register,"/register")
api.add_resource(Classify,"/classify")
api.add_resource(Refill,"/refill")

@app.route('/')
def hello_world():
    return "Hello World!"



if __name__=="__main__":
    app.run(host="0.0.0.0",debug=True)
