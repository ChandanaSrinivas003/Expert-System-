import requests

# headers = {
#     'accept': 'application/json',
#     'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibHgxNjBjbUBnbWFpbC5jb20iLCJleHBpcmVzIjoxNjc1MDU4Mjc1LjQ4NTI5MDV9.mS1RPwEqG9hAClU20SW7l2YqPtI2ESy_wvd6xYhMG5c',
# }

# data = requests.get('http://localhost:8081/posts/1', headers=headers)

# print(data.json())

def model_training():
    headers = {
        'accept': 'application/json',
        'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibHgxNjBjbUBnbWFpbC5jb20iLCJleHBpcmVzIjoxNjc1MDU5NTMzLjYxMzU2MTZ9.vtVpHPVG7rBVzfyhyg1FA6RqAh6jYrw7WEXWNq9NIXA',
    }

    response = requests.get('http://localhost:8081/training', headers=headers)
    print(response.json())

# model_training()


def client_pred(): 

    headers = {
        'accept': 'application/json',
        'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibHgxNjBjbUBnbWFpbC5jb20iLCJleHBpcmVzIjoxNjc1MDYxOTc4LjY2OTI3NDZ9.p1O_EGfdIicl2ftu0h-1CNBwoZeS2clkzu_tUw-U3zo',
        'Content-Type': 'application/json',
    }

    json_data = {
        'age': 'ff',
        'sex': 0,
        'cp': 1,
        'trestbps': 128,
        'chol': 233,
        'fbs': 0,
        'restecg': 1,
        'thalach': 150,
        'exang': 0,
        'oldpeak': 2.5,
        'slope': 0,
        'ca': 0,
        'thal': 3,
    }

    response = requests.post('http://localhost:8081/expertResult', headers=headers, json=json_data)
    print(response.json())

client_pred()