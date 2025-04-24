from rest_framework import serializers
from .models import Course, Event, CalendarEvent
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username','email','first_name','last_name','is_staff']



class CourseSerializer(serializers.ModelSerializer):
    enrolled_users = UserSerializer(many=True, read_only=True)
    students_enrolled = serializers.ReadOnlyField()

    class Meta:
        model = Course
        fields = [
            'id',
            'title',
            'instructor',
            'description',
            'start_time',
            'end_time',
            'students_enrolled',
            'enrolled_users',
        ]
        
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only = True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid username or password")

        data["user"] = user
        return data

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email'),
            password=validated_data['password']
        )
        
class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = ['id', 'title', 'description', 'location', 'start_time', 'end_time', 'registered_users']
        read_only_fields = ['registered_users']


class CalendarEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = CalendarEvent
        fields = ['id', 'title', 'description', 'start_time', 'end_time', 'created_by', 'enrolled_users']