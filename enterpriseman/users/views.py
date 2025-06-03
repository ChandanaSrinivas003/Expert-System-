from django.shortcuts import render
from django.http import HttpResponse
from django.contrib import messages
from .forms import UserRegistrationForm
#from .forms import makeappointmentform
from .models import UserRegistrationModel, UserAppointmentModel
import requests

# import os
# from django.conf import settings
# import pandas as pd

'''
Api call for expert system
Base URl is http://127.0.0.1:8084/
'''
BASEURL = 'http://127.0.0.1:8084/'


# Create your views here.
def home(request):
    return render(request, 'base.html')


def user_register_action(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            print('Data is Valid')
            form.save()
            messages.success(request, 'You have been successfully registered')
            form = UserRegistrationForm()
            return render(request, 'register.html', {'form': form})
        else:
            messages.success(request, 'Email or Mobile Already Existed')
            print("Invalid form")

    else:
        form = UserRegistrationForm()
    return render(request, 'register.html', {'form': form})


def user_login_check(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('password')
        print("Login ID = ", loginid, ' Password = ', pswd)
        try:
            check = UserRegistrationModel.objects.get(
                loginid=loginid, password=pswd)
            status = check.status
            print('Status is = ', status)
            if status == "activated":
                request.session['id'] = check.id
                request.session['loggeduser'] = check.name
                request.session['loginid'] = loginid
                request.session['email'] = check.email
                response = requests.post(BASEURL + "user/signup", json={
                    "fullname": check.name,
                    "email": check.email,
                    "password": pswd
                })
                resp = response.json()
                access_token = resp.get('access_token')
                request.session['access_token'] = access_token
                print("Toekn is:", access_token)
                print("User id At", check.id, status)
                return render(request, 'users/user_home.html', {})
            else:
                messages.success(
                    request, 'Your Account has not been activated by the Admin🛑🤚')
                return render(request, 'user_login.html')
        except Exception as e:
            print('Exception is ', str(e))
            pass
        messages.success(request, 'Invalid Login id and password')
    return render(request, 'user_login.html', {})


def user_home(request):
    return render(request, 'users/user_home.html')


def callExpertAPI(request):
    if request.method == 'POST':
        age = int(request.POST.get('age'))
        sex = int(request.POST.get('sex'))
        cp = int(request.POST.get('cp'))
        trestbps = int(request.POST.get('trestbps'))
        chol = int(request.POST.get('chol'))
        fbs = int(request.POST.get('fbs'))
        restecg = int(request.POST.get('restecg'))
        thalach = int(request.POST.get('thalach'))
        exang = int(request.POST.get('exang'))
        oldpeak = float(request.POST.get('oldpeak'))
        slope = int(request.POST.get('slope'))
        ca = int(request.POST.get('ca'))
        thal = int(request.POST.get('thal'))
        test_set = [age, sex, cp, trestbps, chol, fbs,
                    restecg, thalach, exang, oldpeak, slope, ca, thal]
        json_data = {
            'age': age,
            'sex': sex,
            'cp': cp,
            'trestbps': trestbps,
            'chol': chol,
            'fbs': fbs,
            'restecg': restecg,
            'thalach': thalach,
            'exang': exang,
            'oldpeak': oldpeak,
            'slope': slope,
            'ca': ca,
            'thal': thal,
        }
        access_token = request.session['access_token']
        print('Token:', access_token)
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
        }
        response = requests.post(
            BASEURL+'expertResult', headers=headers, json=json_data)
        resp = response.json()
        return render(request, 'users/expertResultResponse.html', {'status': resp.get('result'), 'prob': resp.get('prob')})

    else:
        return render(request, 'users/expertCall.html', {})


def makeappointment(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        date = request.POST.get('date')
        doctor = request.POST.get('doctor')
        disease = request.POST.get('disease')
        suggestion= "waiting"# request.POST.get('suggestion')
        print("Name is:",name)
        UserAppointmentModel.objects.create(name=name,email=email,phone=phone,date=date,doctor=doctor,disease=disease,suggestion=suggestion)
        return render(request, 'users/appointmentsuccess.html')
    else:
        #form = makeappointmentform()
        return render(request, 'users/appointment.html')
    #return render(request,'users/appointment.html')


   
def expertresponse(request):
    data = UserAppointmentModel.objects.all()
    return render(request,'users/expertresponse.html', {'data': data})    
