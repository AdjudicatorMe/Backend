import datetime
from datetime import date, time, datetime
from django.db import models
from django.contrib.auth.models import User, Group, AbstractUser, Permission



# Create your models here.
class Feature(models.Model):#example model
    name = models.CharField(max_length=100)
    deatails = models.CharField(max_length=500)

class Course(models.Model):
    title = models.CharField(max_length=200)
    instructor = models.CharField(max_length=200)
    description = models.TextField()
    start_time = models.DateTimeField(default = datetime.now, null = True, blank = True)
    end_time = models.DateTimeField(default = datetime.now, null = True, blank = True)
    enrolled_users = models.ManyToManyField(User, related_name='enrolled_courses', blank=True)

    @property
    def students_enrolled(self):
        return self.enrolled_users.count()

    def __str__(self):
        return self.title

    
class Event(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    location = models.CharField(max_length=200, default="Virtual")
    registered_users = models.ManyToManyField(User, related_name="registered_events", blank=True)

    def __str__(self):
        return self.title
    
class CalendarEvent(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    created_by = models.ForeignKey(User, related_name='created_events', on_delete=models.CASCADE)
    enrolled_users = models.ManyToManyField(User, related_name='enrolled_events', blank=True)

    def __str__(self):
        return self.title


    