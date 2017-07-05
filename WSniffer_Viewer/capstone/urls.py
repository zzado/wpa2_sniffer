"""capstone URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from WSniffer import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', views.main, name="main"),
    url(r'^team/', views.team, name="team"),
    url(r'^add_info/', views.add_request_info, name="add_request_info"),
    url(r'^message/(?P<StaNo>\w+)/$', views.message, name="message"), 
    url(r'^sta/(?P<ApNo>\w+)/$', views.sta, name="sta"), 
    url(r'^reset/', views.reset, name="reset"), 
    url(r'^sess_hj/(?P<StaNo>\w+)/$', views.sess_hj, name="sess_hj"), 
    url(r'^check_sess/(?P<StaNo>\w+)/$', views.check_sess, name="check_sess"), 

]
