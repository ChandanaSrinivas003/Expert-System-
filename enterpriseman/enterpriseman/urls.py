"""enterpriseman URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from enterpriseman import views
from users import views as users_views
from admins import views as admins_views

from doctor import views as doctor_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('register/', views.register, name='register'),
    path('admin_login/', views.admin_login, name='admin_login'),
    path('user_login/', views.user_login, name='user_login'),
    path('doctor_login/', views.doctor_login, name='doctor_login'),

    # User side url
    path('user_register_action/', users_views.user_register_action,
         name='user_register_action'),
    path("user_login_check/", users_views.user_login_check, name="user_login_check"),
    path("user_home/", users_views.user_home, name="user_home"),
    path("callExpertAPI/", users_views.callExpertAPI, name="callExpertAPI"),
    path('makeappointment/',users_views.makeappointment,name='makeappointment'),
    # path("machine_learning/", users_views.machine_learning, name="machine_learning"),
    # path("edaAnalysis/", users_views.edaAnalysis, name="edaAnalysis"),
    path('expertresponse/',users_views.expertresponse,name="expertresponse"),
         

    # Admins side url
    path('admin_login_check/', admins_views.admin_login_check,
         name='admin_login_check'),

    path('admin_home/', admins_views.admin_home, name='admin_home'),

    path('view_registered_users/', admins_views.view_registered_users,
         name='view_registered_users'),

    path("AdminActivaUsers/", admins_views.AdminActivaUsers,
         name="AdminActivaUsers"),
    
    
    
    
    
    #doctor side url
    path('doctor_login_check/', doctor_views.doctor_login_check,
         name='doctor_login_check'),

    path('doctor_home/', doctor_views.doctor_home, name='doctor_home'),

    path('view_appointment_users/', doctor_views.view_appointment_users,
         name='view_appointment_users'),

    path("AddingSuggestions/", doctor_views.AddingSuggestions,
         name="AddingSuggestions"),
    
    path('suggestionsucess/',doctor_views.suggestionsucess,
         name="suggestionsucess"),
    
    
    

]
