from datetime import datetime, timedelta
from calendar import HTMLCalendar
from .models import  Event, Course

class Calendar(HTMLCalendar):
	def __init__(self, year=None, month=None):
		self.year = year
		self.month = month
		super(Calendar, self).__init__()

	# formats a day as a td
	# filter events by day
	def formatday(self, day, events, courses):
		events_per_day = events.filter(start_time__day=day)
		courses_per_day = courses.filter(start_time__day=day)
		d = ''
		for event in events_per_day:
			d += f'<li><span style="color: blue;">Event: {event.title} </li>'
		
		for course in courses_per_day:
			d+= f'<li><span style="color: green;">Course: {course.title}</li>'

		if day != 0:
			return f"<td><span class='date'>{day}</span><ul> {d} </ul></td>"
		return '<td></td>'

	# formats a week as a tr 
	def formatweek(self, theweek, events, courses):
		week = ''
		for d, weekday in theweek:
			week += self.formatday(d, events, courses)
		return f'<tr> {week} </tr>'

	# formats a month as a table
	# filter events by year and month
	def formatmonth(self, withyear=True):
		events = Event.objects.filter(start_time__year=self.year, start_time__month=self.month)
		courses = Course.objects.filter(start_time__year=self.year, start_time__month=self.month)

		cal = f'<table border="0" cellpadding="0" cellspacing="0" class="calendar">\n'
		cal += f'{self.formatmonthname(self.year, self.month, withyear=withyear)}\n'
		cal += f'{self.formatweekheader()}\n'
		for week in self.monthdays2calendar(self.year, self.month):
			cal += f'{self.formatweek(week, events, courses)}\n'
		return cal