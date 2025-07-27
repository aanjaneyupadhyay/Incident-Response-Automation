from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
			path("Register.html", views.Register, name="Register"),
			path("RegisterAction", views.RegisterAction, name="RegisterAction"),	    	
			path("UserLogin.html", views.UserLogin, name="UserLogin"),
			path("UserLoginAction", views.UserLoginAction, name="UserLoginAction"),
			path("DetectionAnalysis.html", views.DetectionAnalysis, name="DetectionAnalysis"),
			path("AnalyzeTrafficAction", views.AnalyzeTrafficAction, name="AnalyzeTrafficAction"),
			path("AlertAnalysis", views.AlertAnalysis, name="AlertAnalysis"),
]