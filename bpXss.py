#!/usr/bin/env python     
#coding:utf-8

from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from burp import IContextMenuFactory
from javax.swing import JMenu
from javax.swing import JMenuItem
import urllib
import json
import re
version=1.1
class BurpExtender(IBurpExtender, IHttpListener,IContextMenuFactory):
 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Xss")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self._pattern = r'<[i|b|a|s|f|l|p|m|e|o|d|v].*?>'
        self.payloads = self.load_payloads("payload.txt")
        callbacks.issueAlert("Loaded Successfull.")
        print(f'version={version}')
    def load_payloads(self, filepath):
        try:
            with open(filepath, 'r') as file:
                return file.read().splitlines()
        except Exception as e:
            print(f"Error loading payloads: {e}")
            return []
    def createMenuItems(self, invocation):
        self.menus = []
        self.mainMenu = JMenu("Xss")
        self.menus.append(self.mainMenu)
        self.invocation = invocation
        menuItem = ['post fuzz',
        'get fuzz','XFF']
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
            #解码请求体，更新内容，check回显
            for payload in self.payloads:
                source, result = self.update_body(urllib.unquote(self.body), payload)
                self.body = self.body.replace(source, result)
                newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
                currentRequest.setRequest(newMessage)
                #check
                response = self._callbacks.makeHttpRequest(currentRequest.getHttpService(), newMessage)
                self.processHttpMessage(32, False, response)
    def getXss(self,x):#get请求下需要在参数中插入payload
        if x.getSource().text.startswith('get fuzz'):
            # 获取payload
            self.payload = self.getpayload()
            currentRequest = self.invocation.getSelectedMessages()[0] 
            bodyBytes = currentRequest.getRequest() 
            requestInfo = self._helpers.analyzeRequest(currentRequest) 
            paraList = requestInfo.getParameters()#获取参数列表
            new_requestInfo = bodyBytes
            white_action = ['action', 'sign']
            for payload in self.payloads:
                for para in paraList:
                    if para.getType() == 0 and not self.Filter(white_action, para.getName()):
                        value = para.getValue() + payload
                        key = para.getName()
                        newPara = self._helpers.buildParameter(key, value, para.getType())
                        new_requestInfo = self._helpers.updateParameter(new_requestInfo, newPara)
                currentRequest.setRequest(new_requestInfo)
                #check
                response = self._callbacks.makeHttpRequest(currentRequest.getHttpService(), new_requestInfo)
                self.processHttpMessage(32, False, response)
                    
            currentRequest.setRequest(new_requestInfo)
    def Filter(self, white_action, key):
        return any(action in key.lower() for action in white_action)
    
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
            print(f"Error updating body: {e}")
            return body,body
    # def getpayload(self):
    #     return "x'\"><rivirtest></script><img+src=0+onerror=alert(1)>"

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag in {32}:#可选
           if not messageIsRequest:
                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(request)
                reqParaList = analyzedRequest.getParameters()
                reqUrl = analyzedRequest.getUrl()
                Allparams = {}
                for para in reqParaList:
                    if para.getType() != para.PARAM_COOKIE:
                        Allparams[para.getName()] = para.getValue()
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                body = response[analyzedResponse.getBodyOffset():]
                response_body = body.tostring()
                tags = re.findall(self._pattern, response_body.encode('utf-8'))
                self.ChecktheSame(Allparams, tags, reqUrl)
                #加入日志
                self.logRequestResponse(request, response, tags)
                
    def ChecktheSame(self, Allparams, tags, reqUrl):
        for param_key in Allparams:
            if Allparams[param_key]:
                for tag in tags:
                    if tag.find(Allparams[param_key]) != -1:
                        self.stdout.println(f"Param is \"{param_key}\" , that is : {reqUrl}")

    def logRequestResponse(self, request, response, tags):
        request_str = self._helpers.bytesToString(request)
        response_str = self._helpers.bytesToString(response)
        log_entry = {
            "request": request_str,
            "response": response_str,
            "tags": tags
        }
        with open("xss_log.txt", "a") as log_file:
            log_file.write(json.dumps(log_entry, indent=4) + "\n")