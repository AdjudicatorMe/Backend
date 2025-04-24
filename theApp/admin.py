from django.contrib import admin
from django import forms
from .models import Course, Event
from django.contrib.auth.models import User

# Custom Course form to avoid auto-assigning users



class CourseAdminForm(forms.ModelForm):
    class Meta:
        model = Course
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Show only the users actually enrolled in this course
        if self.instance and self.instance.pk:
            self.fields['enrolled_users'].initial = self.instance.enrolled_users.all()
        else:
            self.fields['enrolled_users'].initial = []






# Optional: Event admin customization (if needed)
class EventAdmin(admin.ModelAdmin):
    list_display = ('title', 'start_time', 'end_time')
    search_fields = ('title',)

# Register both models
admin.site.register(Course)
admin.site.register(Event, EventAdmin)
