from django.urls import path, include
#from django.conf.urls import url
from . import views
from theApp import views #from the second vid
from .views import enroll_course, LoginView, enroll_in_course, courses_api, register_event, register_user, remove_user_from_event, remove_user_from_course, delete_event, delete_course, get_user_profile, delete_user
from .views import create_user, create_course, create_event, password_reset, reset_password, calendar_api, SettingsViewSet
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.http import JsonResponse



urlpatterns = [
    path('calendar/', calendar_api, name='calendar'),
    path('reset-password/<str:token>/', reset_password, name='reset-password'),
    path('password-reset/', password_reset, name='password_reset'),
    path('create_event/', create_event, name='create_event'),
    path('create_course/', create_course, name='create_course'),
    path('create_user/', create_user, name='create_user'),
    path('delete_user/<int:user_id>/', delete_user, name='delete_user'),
    path('user/', get_user_profile, name='user_profile'),
    path('delete_course/<int:course_id>/', delete_course, name='delete_course'),
    path('delete_event/<int:event_id>/', delete_event, name='delete_event'),
    path('remove_user_from_course/<int:course_id>/<int:user_id>/', remove_user_from_course, name='remove_user_from_course'),
    path('remove_user_from_event/<int:event_id>/<int:user_id>/', remove_user_from_event, name='remove_user_from_event'),
    path('calendar/', views.calendar_events, name='calendar_events'),
    #path('settings/', views.settings_view, name='settings'),
    path('delete_course/<int:course_id>/', views.delete_course, name='delete_course'),
    path('delete_event/<int:event_id>/', views.delete_event, name='delete_event'),
    path('', views.index, name='index'),
    path('', views.index2, name='index2'),#it should just call whichever comes first if the '' at the beging is identical
    path('register/', register_user, name='register'), #this will path to the sign up page (account creation)
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path('logout/', views.logoutView, name='logout'),
    path('courses/', courses_api, name='courses'),
    path('enroll/', enroll_in_course, name='enroll'),
    path('register_event/<int:event_id>/', register_event, name= 'register_event'),
    path('events/', views.events_api, name='events'),
    #path('settings/', views.settings_page, name='settings'),
   
    
]