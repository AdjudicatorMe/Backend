from django.db.models import Q
import calendar
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import login, logout #idk if this should be signup
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .forms import SignUpForm, EventForm
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.models import User, auth
from django.contrib import messages
from .models import Feature, Course, Event
from .forms import CourseForm, EventForm
from datetime import date, datetime, timedelta
from django.views import generic
from django.utils.safestring import mark_safe
from .models import *
from .utils import Calendar
from django.utils.timezone import now
from rest_framework.decorators import api_view, permission_classes, authentication_classes, action
from rest_framework.response import Response
from .serializers import CourseSerializer, LoginSerializer, RegisterSerializer, EventSerializer, CalendarEventSerializer, UserSerializer
from rest_framework.views import APIView
from rest_framework import status, generics, viewsets
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly, IsAuthenticated, IsAdminUser
from django.contrib.auth import authenticate, get_user_model, password_validation
from rest_framework.authtoken.models import Token
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.core.mail import send_mail
import logging

logger = logging.getLogger(__name__)


class UserViewSet(viewsets.ModelViewSet):
    """
    Admin-only viewset for creating, listing, updating, and deleting users.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

class SettingsViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        user = request.user
        return Response({
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'enrolled_courses': [
                {'id': c.id, 'title': c.title, 'instructor': c.instructor}
                for c in user.enrolled_courses.all()
            ],
            'registered_events': [
                {'id': e.id, 'title': e.title, 'start_time': e.start_time}
                for e in user.registered_events.all()
            ],
            'is_admin': user.is_staff
        })

    @action(detail=False, methods=['post'])
    def update_profile(self, request):
        user = request.user
        for field in ('first_name','last_name','username'):
            if field in request.data:
                setattr(user, field, request.data[field])
        user.save()
        return Response({'message':'Profile updated'})

    @action(detail=False, methods=['post'])
    def change_password(self, request):
        user = request.user
        cur = request.data.get('current_password')
        new = request.data.get('new_password')
        if not user.check_password(cur):
            return Response({'error':'Wrong current password'}, status=400)
        user.set_password(new); user.save()
        return Response({'message':'Password changed'})

    @action(detail=False, methods=['delete'])
    def delete_account(self, request):
        request.user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def calendar_api(request):
    """
    If only year/month provided: return months' items the user is in.
    If also day: filter down to that day.
    """
    user = request.user
    year = int(request.query_params.get('year'))
    month = int(request.query_params.get('month'))
    day = request.query_params.get('day')

    # base querysets: only those the user is enrolled/registered for
    courses_qs = Course.objects.filter(
        enrolled_users=user,
        start_time__year=year,
        start_time__month=month
    )
    events_qs = Event.objects.filter(
        registered_users=user,
        start_time__year=year,
        start_time__month=month
    )

    if day:
        day = int(day)
        courses_qs = courses_qs.filter(start_time__day=day)
        events_qs = events_qs.filter(start_time__day=day)

    courses_data = CourseSerializer(courses_qs, many=True).data
    events_data = EventSerializer(events_qs, many=True).data

    return Response({
        'courses': courses_data,
        'events': events_data,
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request, token):
    """
    Expect payload: { "password": "newpass123" }
    URL: /api/reset-password/<token>/
    """
    new_password = request.data.get('password')
    if not new_password:
        return JsonResponse({'error': 'Password is required.'}, status=400)

    # Find the user by scanning all users for a valid token
    for user in User.objects.all():
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return JsonResponse({'message': 'Password reset successful.'})

    return JsonResponse({'error': 'Invalid or expired token.'}, status=400)

@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset(request):
    email = request.data.get('email')  # Fetch email directly

    if not email:
        return JsonResponse({"error": "Email is required"}, status=400)

    # Find all users with the provided email
    users = User.objects.filter(email=email)
    if not users.exists():
        # Return a generic message to avoid disclosing if email exists or not
        return JsonResponse({"message": "If this email exists, a password reset link has been sent."}, status=200)

    for user in users:
        try:
            # Create a password reset token for each user
            token = default_token_generator.make_token(user)

            # Create the reset link
            reset_link = f'{settings.FRONTEND_URL}/reset-password/{token}/'

            # Send the reset email
            send_mail(
                'Password Reset',
                f'Click the following link to reset your password: {reset_link}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
            )

            # Log successful sending
            logger.info(f"Password reset email sent to {user.email}")

        except Exception as e:
            # Log the exception and return an internal server error with a message
            logger.error(f"Error during password reset process for {email}: {str(e)}")
            return JsonResponse({"error": "An error occurred while processing your request. Please try again later."}, status=500)

    # Return success if the email exists and the emails are sent
    return JsonResponse({"message": "If this email exists, a password reset link has been sent."}, status=200)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def create_event(request):
    if request.method == 'POST':
        title = request.data.get('title')
        date = request.data.get('date')
        location = request.data.get('location')
        
        event = Event.objects.create(
            title=title,
            date=date,
            location=location
        )
        event.save()

        return Response({'message': 'Event created successfully!'}, status=status.HTTP_201_CREATED)
    return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def create_course(request):
    if request.method == 'POST':
        title = request.data.get('title')
        instructor = request.data.get('instructor')
        description = request.data.get('description')
        start_time = request.data.get('start_time')
        end_time = request.data.get('end_time')
        
        # Assuming you have a Course model
        course = Course.objects.create(
            title=title,
            instructor=instructor,
            description=description,
            start_time=start_time,
            end_time=end_time
        )
        course.save()

        return Response({'message': 'Course created successfully!'}, status=status.HTTP_201_CREATED)
    return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def create_user(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        
        user = User.objects.create_user(username=username, password=password, email=email, first_name=first_name, last_name=last_name)
        user.save()
        
        return Response({'message': 'User created successfully!'}, status=status.HTTP_201_CREATED)
    return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_user(request, user_id):
    try:
        # Get the user object based on the provided user_id
        user = User.objects.get(id=user_id)
        
        # Delete the user
        user.delete()
        
        return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Ensure the user is authenticated
@authentication_classes([TokenAuthentication])  # Use token authentication
def get_user_profile(request):
    user = request.user  # Get the currently authenticated user
    return Response({
        'username': user.username,
        'email': user.email,
        
      
    })

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_course(request, course_id):
    try:
        course = Course.objects.get(id=course_id)
        course.delete()
        return Response({'message': 'Course deleted successfully.'}, status=status.HTTP_200_OK)
    
    except Course.DoesNotExist:
        return Response({'message': 'Course not found.'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_event(request, event_id):
    try:
        event = Event.objects.get(id=event_id)
        event.delete()
        return Response({'message': 'Event deleted successfully.'}, status=status.HTTP_200_OK)
    
    except Event.DoesNotExist:
        return Response({'message': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_user_from_course(request, course_id, user_id):
    if not request.user.is_staff:
        return Response({'message': 'You are not authorized to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        course = Course.objects.get(id=course_id)
        user = User.objects.get(id=user_id)
        
        if user in course.enrolled_users.all():
            course.enrolled_users.remove(user)
            course.save()
            return Response({'message': 'User removed from course successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'User not enrolled in this course.'}, status=status.HTTP_400_BAD_REQUEST)
    
    except Course.DoesNotExist:
        return Response({'message': 'Course not found.'}, status=status.HTTP_404_NOT_FOUND)
    except User.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_user_from_event(request, event_id, user_id):
    if not request.user.is_staff:
        return Response({'message': 'You are not authorized to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        event = Event.objects.get(id=event_id)
        user = User.objects.get(id=user_id)
        
        if user in event.registered_users.all():
            event.registered_users.remove(user)
            event.save()
            return Response({'message': 'User removed from event successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'User not enrolled in this event.'}, status=status.HTTP_400_BAD_REQUEST)
    
    except Event.DoesNotExist:
        return Response({'message': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)
    except User.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)



@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def calendar_events(request):
    if request.method == 'GET':
        events = CalendarEvent.objects.all()
        serializer = CalendarEventSerializer(events, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = CalendarEventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_course(request, course_id):
    try:
        course = Course.objects.get(id=course_id)
        course.enrolled_users.remove(request.user)
        return Response({'message': 'Unenrolled successfully.'})
    except Course.DoesNotExist:
        return Response({'error': 'Course not found.'}, status=404)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_event(request, event_id):
    try:
        event = Event.objects.get(id=event_id)
        event.registered_users.remove(request.user)
        return Response({'message': 'Unregistered successfully.'})
    except Event.DoesNotExist:
        return Response({'error': 'Event not found.'}, status=404)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def settings_view(request):
    user = request.user
    enrolled_courses = user.enrolled_courses.all()
    registered_events = user.registered_events.all()
    is_admin = user.is_staff

    courses_data = [
        {
            'id': course.id,
            'title': course.title,
            'instructor': course.instructor
        } for course in enrolled_courses
    ]

    events_data = [
        {
            'id': event.id,
            'title': event.title,
            'start_time': event.start_time,
        } for event in registered_events
    ]

    return Response({
        'enrolled_courses': courses_data,
        'registered_events': events_data,
        'is_admin': is_admin
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_event(request, event_id):
    print("Auth header:", request.headers.get('Authorization'))
    print("User:", request.user)
    print("Authenticated:", request.user.is_authenticated)

    try:
        event = Event.objects.get(id=event_id)
        event.registered_users.add(request.user)
        return Response({'message': 'Registered successfully'})
    except Event.DoesNotExist:
        return Response({'error': 'Event not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def events_api(request):
    if request.method == 'GET':
        events = Event.objects.all()
        out = []
        for ev in events:
            out.append({
                'id': ev.id,
                'title': ev.title,
                'description': ev.description,
                'location': ev.location,
                'start_time': ev.start_time,
                'end_time': ev.end_time,
                # include the list of user IDs registered
                'registered_users': list(ev.registered_users.values_list('id', flat=True)),
            })
        return Response(out)
    
    elif request.method == 'POST':
        serializer = EventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enroll_in_course(request):
    print("User making request:", request.user)
    course_id = request.data.get('course_id')
    try:
        course = Course.objects.get(id=course_id)
        course.enrolled_users.add(request.user)
        return Response({'message': 'Enrolled successfully'})
    except Course.DoesNotExist:
        return Response({'error': 'Course not found'}, status=404)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def courses_api(request):
    if request.method == 'GET':
        search_query = request.GET.get('search', '')
        instructor_filter = request.GET.get('instructor', '')

        # Build the filter based on available parameters
        filters = Q(title__icontains=search_query) | Q(description__icontains=search_query)

        if instructor_filter:
            filters &= Q(instructor__icontains=instructor_filter)

        courses = Course.objects.filter(filters)

        serializer = CourseSerializer(courses, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = CourseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

User = get_user_model()

class LoginView(APIView):
    def post(self, request):
       

        username = request.data.get('username')
        password = request.data.get('password')

        if username is None or password is None:
            return Response({'error': 'Please provide both username and password.'},
                            status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)

        if not user:
            return Response({'error': 'Invalid username or password.'},
                            status=status.HTTP_401_UNAUTHORIZED)

        return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        
    
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
  
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')

        if not username or not password or not email:
            return Response({"error": "Username, password, and email are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, password=password, email=email)

        token, created = Token.objects.get_or_create(user=user)

        return Response(
            {
                "username": user.username,
                "email": user.email,
                "token": token.key
            },
            status=status.HTTP_201_CREATED
        )


# Create your views here.
@ensure_csrf_cookie
def index(request):
    features = Feature.objects.all()
    return render(request, 'index.html', {'features': features})

def index2(request):
    return render(request, 'index2.html')#idk

def signup(request):#Sign up page
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        if password == password2:
            if User.objects.filter(email=email).exists():
                messages.info(request, 'Email Already in Use')
                return redirect('signup')#sends them back to the begining of the signup process
            elif User.objects.filter(username=username).exists():#send them back to the begining of the signup process
                #if the username is already being used but I don't think we have user names (i guess regular names is the same thing)
                messages.info(request, 'Username Already in Use')
                return redirect('signup')
            else:
                user = User.objects.create_user(username=username, email=email, password=password)#this might differ
                #depending on our database
                user.save()
                return redirect('login')
        else:
            messages.info(request, 'Passwords do not Match')
            return redirect('signup')
    else:
        return render(request, 'signup.html')#so this will need to be typescript

def loginView(request):#login page
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect('/')
        else:
            messages.info(request, 'Credentials invalid')
            return redirect ('login')
    else:
        return render(request, 'login.html')


def logoutView(request):#not hooked up to anything since I don't think we've speciefed needing one.
    #Still, this should be the logic
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('index')

@login_required(login_url='/login/')
def courses(request):#displays the available courses- Functions are Enroll, Filter(i'd like to remove this), and Search
    query = request.GET.get('q', '')  # Get the search query
    if query:
        courses_list = Course.objects.filter(title__icontains=query)
    else:
        courses_list = Course.objects.all()
    
    return render(request, 'courses.html', {'courses': courses_list, 'query': query})


@login_required(login_url='/login/')
def enroll_course(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    
    if request.user in course.enrolled_users.all():
        messages.info(request, "You are already enrolled in this course.")
    else:
        course.enrolled_users.add(request.user)  # Add user to enrolled_users
        course.students_enrolled += 1
        course.save()
        messages.success(request, f"Successfully enrolled in {course.title}!")

    return redirect('courses')

@login_required(login_url='/login/')
def events(request):#displays events- Allows admins to create events (students can make meetings? I maybe missremembering)
    #and allows Registration for events
        events = Event.objects.filter(start_time__gte=now()).order_by('start_time')
        return render(request, "events.html", {"events": events})




@login_required(login_url='/login/')
def settings_page(request):#The admin dashboard- Allows Users, Courses, and Events to be added(removed as well?)

    if not request.user.is_staff:#can't I just use this for login?
        messages.error(request, "You do not have permission for this page, sorry.")
        return redirect('login')#sends them back to the landing page
    
    users = User.objects.all()
    courses = Course.objects.all()
    events = Event.objects.all()
    course_form = CourseForm()
    event_form = EventForm()

    if request.method == 'POST' and 'add_course' in request.POST:
        course_form = CourseForm(request.POST)
        if course_form.is_valid():
            course_form.save()
            messages.success(request, f'Course added successfully.')
            return redirect('settings')
        
    if request.method == 'POST' and 'add_event' in request.POST:
        event_form = EventForm(request.POST)
        if event_form.is_valid():
            event_form.save()
            messages.success(request, f'Event added successfully.')
            return redirect('settings')

    return render(request, 'settings.html', {
        'users' : users,
        'courses' : courses,
        'course_form' : course_form,
        'events' : events,
        'event_form' : event_form
    })




class CalendarView(generic.ListView):
    model = Event
    template_name = 'cal/calendar.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        
        # use today's date for the calendar
        d = get_date(self.request.GET.get('month', None))

        # Instantiate our calendar class with today's year and date
        cal = Calendar(d.year, d.month)

        # Call the formatmonth method, which returns our calendar as a table
        html_cal = cal.formatmonth(withyear=True)
        context['calendar'] = mark_safe(html_cal)
        context['prev_month'] = prev_month(d)
        context['next_month'] = next_month(d)
        return context
    
def prev_month(d):
    first = d.replace(day=1)
    prev_month = first - timedelta(days=1)
    month = 'month=' + str(prev_month.year) + '-' + str(prev_month.month)
    return month

def next_month(d):
    days_in_month = calendar.monthrange(d.year, d.month)[1]
    last = d.replace(day=days_in_month)
    next_month = last + timedelta(days=1)
    month = 'month=' + str(next_month.year) + '-' + str(next_month.month)
    return month

def get_date(req_day):
    if req_day:
        year, month = (int(x) for x in req_day.split('-'))
        return date(year, month, day=1)
    return datetime.today()


