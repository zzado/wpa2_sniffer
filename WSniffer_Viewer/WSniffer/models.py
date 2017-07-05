# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.

class WSniffer(models.Model):
    ApMac = models.CharField(max_length=100)
    ApSsid = models.CharField(max_length=100)
    StaMac = models.CharField(max_length=100)
    Date = models.DateTimeField(auto_now_add=True)
    HttpRequestHeader = models.TextField(max_length=5000)
    NatIp = models.CharField(max_length=100)
    NatPort = models.CharField(max_length=100)
    def get_to_list(self) :
        ret_list = [self.ApMac, self.ApSsid, self.StaMac, self.HttpRequestHeader, self.NatIp, self.NatPort, self.Date]
        
        return ret_list
