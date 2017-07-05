# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.views.decorators.csrf import csrf_exempt

from django.shortcuts import render, redirect
from models import WSniffer
from django.db.models import Q
# Create your views here.



class Message :
	def __init__(self, HttpRequestMessage, NatIp, Date, index):
                self.HttpRequestMessage = HttpRequestMessage
		self.NatIp = NatIp
		self.Date = Date
		self.Cookie_list = []
		self.Cookie_str = ""
		self.findCookie()
		self.index = index
		self.CookieFlag = 0
		self.Host = ""
		self.findHost()
		self.Path = ""
		self.findPath()
		self.Json = ""
		self.Json_list = []
		self.makeJson()
		self.IsCookie()
	
	def findHost(self) :
		for header in self.findHeader() :
                        isHostHeader = header.find("Host:")
                        if( isHostHeader != -1) :
                                self.Host = header[6:]

	def findPath(self) :
		self.Path = self.findHeader()[0].split(" ")[1]
		
	def findHeader(self) :
		return self.HttpRequestMessage.split("\r\n")
	
	def findCookie(self) :
		for header in self.findHeader() :
                        isCookieHeader = header.find("Cookie:")
                        if( isCookieHeader != -1) :
                                self.Cookie_str = header[8:]
				self.Cookie_list = header[8:].split("; ")

	def makeJson(self) : 
		for cookie in self.Cookie_list :
                        loc = cookie.find("=")
                        if(loc != -1) :
                                # Generate Json Data
                                json = CookieJson( self.Host, cookie[:loc], "/", cookie[loc+1:])
                                self.Json_list.append( json.Json() )

                self.Json = "[" + " , ".join(self.Json_list) + "]"

	def IsCookie(self) :
		if(self.Json != "[]") :
			self.CookieFlag = 1

class CookieJson :
	def __init__(self, Domain, Name, Path, Value):
		self.Domain = Domain
		self.Name = Name
		self.Path = Path
		self.Value = Value
	
	def Json(self) :
		return  "{{ \"domain\" : \".{}\" ,  \"name\": \"{}\" ,  \"path\": \"{}\" , \"value\": \"{}\" }}".format(self.Domain, self.Name, self.Path, self.Value)

	

def main(request) :
	
	temp_list = list()
	all_obj = WSniffer.objects.all()
	for obj in all_obj :
		temp_list.append( obj.ApMac )

	temp_list = list(set(temp_list))	

	obj_list = list()
	for x in temp_list :
		obj_list.append(WSniffer.objects.filter(ApMac = x)[0])
	
	return render(request, 'main.html', {
				"obj_list": obj_list})


def reset(request) :

	WSniffer.objects.all().delete()
	return redirect('/')


@csrf_exempt
def add_request_info(request) :
	if(request.method == "GET") :
		return render(request, 'add_info.html')
	else :
		data = request.POST
		WSniffer.objects.create(
                        ApMac = data['ApMac'],
                        ApSsid = data['ApSsid'] ,
                        StaMac = data['StaMac'],
                        NatIp = data['NatIp'],
                        NatPort = data['Natport'],
                	HttpRequestHeader = data['Request']
        	)
		return redirect('/add_info')

def sta(request, ApNo) :

	Temp_list = []
	Ap = WSniffer.objects.get(id=ApNo)
	Obj_list = WSniffer.objects.filter(ApMac = Ap.ApMac)
	
	for obj in Obj_list :
		Temp_list.append( obj.StaMac )

	Temp_list = list(set(Temp_list))	

	Obj_list = list()
	for obj in Temp_list :
		Obj_list.append(WSniffer.objects.filter(StaMac = obj)[0])
	
	return render(request, 'sta.html', {
				"ApNo":ApNo,
				"Ap":Ap,
				"obj_list": Obj_list})


def message(request, StaNo) :
	
	Sta = WSniffer.objects.get(id=StaNo)	
	Sta_list = WSniffer.objects.filter(StaMac = Sta.StaMac)
	
	Message_list = []

	index = 0	
	for obj in Sta_list :
		MessageObject = Message( obj.HttpRequestHeader, obj.NatIp, obj.Date, index )	
		Message_list.append( MessageObject )
		print "====================================="
		print MessageObject.HttpRequestMessage
		print "====================================="		
		index += 1
	return render(request, 'message.html', {"StaNo":StaNo, "Ap": Sta, "Message_list":Message_list})	


def sess_hj(request, StaNo) :

        Sta = WSniffer.objects.get(id=StaNo)
        Sta_list = WSniffer.objects.filter(StaMac = Sta.StaMac)

        Message_list = []

        index = 0
        for obj in Sta_list :
                MessageObject = Message( obj.HttpRequestHeader, obj.NatIp, obj.Date, index )
                if MessageObject.CookieFlag == 1 :
			Message_list.append( MessageObject )
			index += 1

	#print test
	#tt = Message(test, Sta.NatIp, Sta.Date, index)
	#Message_list.append(tt)
	return render(request, 'session.html', {"StaNo":StaNo, "Ap": Sta, "Message_list":Message_list})


def check_sess(request, StaNo) :

	Sta = WSniffer.objects.get(id=StaNo)
	Sta_list = WSniffer.objects.filter(ApMac = Sta.ApMac)

	Sta_set = []	
	for sta in Sta_list :
		Sta_set.append(sta.StaMac)
		Sta_set = list(set(Sta_set))
	
	index = 0

	res_list = []
	for sta in Sta_set :
		Sta_list = []
		not_list = []
		temp_list = []
		temp2_list = []
		Sta_list = WSniffer.objects.filter(StaMac = sta)
                not_list = WSniffer.objects.filter(~Q(StaMac = sta), ApMac = Sta.ApMac)
		Message_list = []
		for obj in Sta_list :
			MessageObject = Message( obj.HttpRequestHeader, obj.NatIp, obj.Date, index )
                	if MessageObject.CookieFlag == 1 :
				temp_list.append(MessageObject.Cookie_str)
				temp_list = list(set(temp_list))
				index += 1

		index = 0
		for obj in not_list :
			MessageObject = Message(obj.HttpRequestHeader, obj.NatIp, obj.Date, index)
			if MessageObject.CookieFlag == 1 :	
				temp2_list.append([ MessageObject.NatIp, MessageObject.Cookie_str ])
				index +=1	
	
	#	print "--------"	
	#	print temp_list;
	#	print "========"
	#	print temp2_list;
	#	print "--------"
		for m1 in temp_list :
			for m2 in temp2_list :
				if(m1 == m2[1]) :
					res_list.append(m2[0])
		
		if res_list :
			Object = WSniffer.objects.filter(StaMac = sta)
			res_list.append(Object[0].NatIp)
			
			
	res_list = list(set(res_list))
	print res_list		
	return render(request, 'check_sess.html',{"res_list":res_list, "Ap":Sta })

def team(request) :

	return render(request, 'team.html' )
