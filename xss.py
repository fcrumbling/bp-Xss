#!/usr/bin/env python     
#coding:utf-8
import re
import urllib

from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from burp import IContextMenuFactory
from javax.swing import JMenu
from javax.swing import JMenuItem
import urllib
import json

 
 
class BurpExtender(IBurpExtender, IHttpListener,IContextMenuFactory):
 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Xss")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.issueAlert("Loaded Successfull.")
 
    def createMenuItems(self, invocation):
        self.menus = []
        self.mainMenu = JMenu("Xss")
        self.menus.append(self.mainMenu)
        self.invocation = invocation
        menuItem = ['post fuzz',
        'get fuzz']
        for tool in menuItem:
            if tool.startswith('post fuzz'):
                menu = JMenuItem(tool,None,actionPerformed=lambda x:self.postXss(x))
                self.mainMenu.add(menu)
            elif tool.startswith('get fuzz'):
                menu = JMenuItem(tool,None,actionPerformed=lambda x:self.getXss(x)) 
                self.mainMenu.add(menu)
        return self.menus if self.menus else None
    def postXss(self,x):#post请求下直接将payload放入body中
        if x.getSource().text.startswith('post fuzz'):
            # 获取payload
            self.payload = self.getpayload()
            currentRequest = self.invocation.getSelectedMessages()[0]
            requestInfo = self._helpers.analyzeRequest(currentRequest)
            self.headers = list(requestInfo.getHeaders())
            bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
            self.body = self._helpers.bytesToString(bodyBytes)
            #解码请求体，并更新其中的内容
            source, result = self.update_body(urllib.unquote(self.body))
            self.body = self.body.replace(source, result)
            newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
            currentRequest.setRequest(newMessage)
    def getXss(self,x):#get请求下需要在参数中插入payload
        if x.getSource().text.startswith('get fuzz'):
            # 获取payload
            self.payload = self.getpayload()
            currentRequest = self.invocation.getSelectedMessages()[0] 
            bodyBytes = currentRequest.getRequest() 
            requestInfo = self._helpers.analyzeRequest(currentRequest) 
            paraList = requestInfo.getParameters()#获取参数列表
            new_requestInfo = bodyBytes
            white_action = ['action','sign']#白名单
            for para in paraList:#筛选掉白名单内容并对参数添加payload
                if para.getType() == 0 and not self.Filter(white_action,para.getName()):
                    value = para.getValue()+self.payload 
                    key = para.getName()
                    newPara = self._helpers.buildParameter(key, value, para.getType())
                    new_requestInfo = self._helpers.updateParameter(new_requestInfo,newPara)
                    
            currentRequest.setRequest(new_requestInfo)
    def Filter(self,white_action,key):
        #模糊匹配
        return True if([True for i in white_action if i in key.lower()]) else False
    def update_body(self,body=""):
        try:
            source = body
            white_action = ['submit','token','code']#白名单
            #检查请求体是否为json格式
            for item in self.headers:
                if (item.startswith('Content-Type:') and 'application/json' in item) or body.startswith('{"'):
                    json_type = 1
                    break
                else:
                    json_type = 0
            if json_type ==0:
                params = source.split('&')#取参数
                for i in range(len(params)):
                    if self.Filter(white_action,params[i].split("=")[0]):#跳过白名单内容
                        continue
                    params[i]=params[i]+self.payload
                result='&'.join(params)#重新拼接
            if json_type == 1:
                data = json.loads(source)
                for item in data:
                    if self.Filter(white_action,item):
                        continue
                    data[item]=data[item]+self.payload
                result=json.dumps(data)
            return source,result
        except Exception as e:
            return e
    #TODO 整个payload表，轮流使用全部payload
    def getpayload(self):
        return "x'\"><rivirtest></script><img+src=0+onerror=alert(1)>"
    #TODO 去response中check回显

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # determine what tool we would like to pass though our extension:
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32: #if tool is Proxy Tab or repeater
            # determine if request or response:
            if not messageIsRequest:#only handle responses
                response = messageInfo.getResponse()
                 #get Response from IHttpRequestResponse instance
                analyzedResponse = self._helpers.analyzeResponse(response) # returns IResponseInfo
                headers = analyzedResponse.getHeaders()
                #替换iso8859-1
                # iterate though list of headers
                new_headers = []
                for header in headers:
                    # Look for Content-Type Header)
                    if header.startswith("Content-Type:"):
                        # Look for HTML response
                        # header.replace('iso-8859-1', 'utf-8')
                        # print header
                        new_headers.append(header.replace('iso-8859-1', 'utf-8'))
                    else:
                        new_headers.append(header)

                #print new_headers

                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                #print body_string
                u_char_escape = re.search( r'(?:\\u[\d\w]{4})+', body_string)
                if u_char_escape:
                    # print u_char_escape.group()
                    u_char = u_char_escape.group().decode('unicode_escape').encode('utf8')
                    new_body_string = body_string.replace(u_char_escape.group(),'--'+u_char+'--')
                    new_body = self._helpers.bytesToString(new_body_string)
                    # print new_body_string
                    messageInfo.setResponse(self._helpers.buildHttpMessage(new_headers, new_body))