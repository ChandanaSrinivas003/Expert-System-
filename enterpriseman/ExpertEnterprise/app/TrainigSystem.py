import pandas as pd   
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier 
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
import numpy as np

async def start_training()->dict:    
    df = pd.read_csv('app/heart.csv')   
    X = df.iloc[:,:-1].values # indipendent variable
    y = df.iloc[:,-1].values # Dependent variable    
    X_train,X_test,y_train,y_test = train_test_split(X,y,train_size = 0.80,random_state=0)       
    model = RandomForestClassifier()    
    model.fit(X_train,y_train) # Trained wih 80% Data
    y_pred = model.predict(X_test)      
    accuracy = accuracy_score(y_test,y_pred)       
    precision = precision_score(y_test,y_pred)    
    recall = recall_score (y_test,y_pred)    
    f1score = f1_score(y_test,y_pred)
    return {'accuracy': accuracy, 'precision': precision,'recall': recall,'f1score': f1score}    




async def start_testing(test_data):    
    df = pd.read_csv('app/heart.csv')   
    X = df.iloc[:,:-1].values # indipendent variable
    y = df.iloc[:,-1].values # Dependent variable    
    X_train,X_test,y_train,y_test = train_test_split(X,y,train_size = 0.80,random_state=0)       
    model = RandomForestClassifier()    
    model.fit(X_train,y_train) # Trained wih 80% Data
    # test_data = [60,0,128,190,1,0,180,2,1,3.5,0,0,1]
    pred = model.predict([test_data])
    prob = model.predict_proba([test_data])
    prob = np.max(prob)
    if pred[0]==0:
        msg= "safe"
    else:
        msg = "not safe"
    return {'result': msg, 'prob': prob}
  

