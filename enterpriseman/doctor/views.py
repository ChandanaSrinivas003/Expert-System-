# Create your views here.
from django.shortcuts import render
from django.contrib import messages
from users.models import UserAppointmentModel
# Create your views here.


def doctor_login_check(request):
    if request.method == 'POST':
        usrid = request.POST.get('loginid')
        pswd = request.POST.get('password')
        print("User ID is = ", usrid)
        if usrid == 'doctor' and pswd == 'doctor':
            return render(request, 'doctor/doctor_home.html')
        elif usrid == 'doctor' and pswd == 'doctor':
            return render(request, 'doctor/doctor_home.html')
        else:
            messages.success(request, 'Please Check Your Login Details')
    return render(request, 'doctor_login.html', {})


def doctor_home(request):
    return render(request, 'doctor/doctor_home.html')


def view_appointment_users(request):
    data = UserAppointmentModel.objects.filter(status='waiting')
    return render(request, 'doctor/view_appointment_users.html', {'data': data})


def AddingSuggestions(request):
    id = request.GET.get('id')
    data = UserAppointmentModel.objects.get(id=id)
    return render(request, 'doctor/addingsuggestions.html', {'data': data})

def suggestionsucess(request):
    if request.method=="POST":
        id = request.POST.get('id')
        info = request.POST.get('AddPrecaution')
        UserAppointmentModel.objects.filter(id=id).update(suggestion=info,status='updated')
        return render(request,'doctor/suggestionsucess.html')
    
         
# def AdminActivaUsers(request):
#     if request.method == 'GET':
#         id = request.GET.get('uid')
#         status = 'activated'
#         print("PID = ", id, status)
#         UserRegistrationModel.objects.filter(id=id).update(status=status)
#         data = UserRegistrationModel.objects.all()
#         return render(request, 'admins/view_registered_users.html', {'data': data})


# Create your views here.
