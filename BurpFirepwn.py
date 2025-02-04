# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from javax.swing import (JPanel, JTextField, JButton, JLabel, JTextArea, JScrollPane,
                         JTabbedPane, JPasswordField, JComboBox, JOptionPane, SwingUtilities)
from javax.swing import BoxLayout, BorderFactory
from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension
from javax.swing.border import TitledBorder, EmptyBorder
from java.lang import Runnable
from threading import Thread, Lock
import json
import urllib2
import urllib
import re
import time
import math
import ssl
from datetime import datetime
from urlparse import urlparse

class RunnableWrapper(Runnable):
    def __init__(self, func):
        self.func = func
    def run(self):
        self.func()

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpFirepwn")
        self.lock = Lock()

        self.mainPanel = JPanel(BorderLayout())
        self.mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self.tabbedPane = JTabbedPane()

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        https_handler = urllib2.HTTPSHandler(context=ssl_context)
        self.opener = urllib2.build_opener(https_handler)
        urllib2.install_opener(self.opener)

        self.initComponents()
        self.mainPanel.add(self.tabbedPane, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)

        self.id_token = None
        self.refresh_token = None
        self.token_expires_in = None
        self.firebase_config = None


        Thread(target=self.tokenExpirationUpdater).start()

    def initComponents(self):
        configPanel = JPanel(GridLayout(0, 2, 8, 8))
        configPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        configPanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Firebase Configuration"))
        configPanel.add(JLabel("API Key:"))
        self.apiKeyField = JTextField(15)
        self.apiKeyField.setPreferredSize(Dimension(150, 25))
        self.apiKeyField.setToolTipText("Your Firebase API key")
        configPanel.add(self.apiKeyField)
        configPanel.add(JLabel("Auth Domain:"))
        self.authDomainField = JTextField(15)
        self.authDomainField.setPreferredSize(Dimension(150, 25))
        self.authDomainField.setToolTipText("e.g. yourapp.firebaseapp.com")
        configPanel.add(self.authDomainField)
        configPanel.add(JLabel("Database URL:"))
        self.databaseURLField = JTextField(15)
        self.databaseURLField.setPreferredSize(Dimension(150, 25))
        self.databaseURLField.setToolTipText("Your Firebase Database URL")
        configPanel.add(self.databaseURLField)
        configPanel.add(JLabel("Project ID:"))
        self.projectIdField = JTextField(15)
        self.projectIdField.setPreferredSize(Dimension(150, 25))
        self.projectIdField.setToolTipText("Your Firebase project ID")
        configPanel.add(self.projectIdField)
        initButton = JButton("Initialize Firebase", actionPerformed=self.initFirebase)
        initButton.setPreferredSize(Dimension(150, 30))
        buttonPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        buttonPanel.add(initButton)
        configContainer = JPanel(BorderLayout(5, 5))
        configContainer.setBorder(EmptyBorder(5, 5, 5, 5))
        configContainer.add(configPanel, BorderLayout.CENTER)
        configContainer.add(buttonPanel, BorderLayout.SOUTH)
        self.tabbedPane.addTab("Config", configContainer)

        authPanel = JPanel()
        authPanel.setLayout(BoxLayout(authPanel, BoxLayout.Y_AXIS))
        authPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        authPanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Authentication"))

        statusPanel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        self.authStatusLabel = JLabel("Not logged in")
        statusPanel.add(self.authStatusLabel)
        refreshStatusButton = JButton("Refresh Status", actionPerformed=self.manualAuthRefresh)
        refreshStatusButton.setPreferredSize(Dimension(140, 30))
        statusPanel.add(refreshStatusButton)
        authPanel.add(statusPanel)

        signinPanel = JPanel(GridLayout(0, 2, 5, 5))
        signinPanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Sign In"))
        signinPanel.add(JLabel("Email:"))
        self.signinEmailField = JTextField(15)
        self.signinEmailField.setPreferredSize(Dimension(150, 25))
        signinPanel.add(self.signinEmailField)
        signinPanel.add(JLabel("Password:"))
        self.signinPasswordField = JPasswordField(15)
        self.signinPasswordField.setPreferredSize(Dimension(150, 25))
        signinPanel.add(self.signinPasswordField)
        signinButton = JButton("Sign In", actionPerformed=self.signIn)
        signinButton.setPreferredSize(Dimension(120, 30))
        signinButtonPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        signinButtonPanel.add(signinButton)
        signinContainer = JPanel()
        signinContainer.setLayout(BoxLayout(signinContainer, BoxLayout.Y_AXIS))
        signinContainer.add(signinPanel)
        signinContainer.add(signinButtonPanel)
        authPanel.add(signinContainer)

        signupPanel = JPanel(GridLayout(0, 2, 5, 5))
        signupPanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Sign Up"))
        signupPanel.add(JLabel("Email:"))
        self.signupEmailField = JTextField(15)
        self.signupEmailField.setPreferredSize(Dimension(150, 25))
        signupPanel.add(self.signupEmailField)
        signupPanel.add(JLabel("Password:"))
        self.signupPasswordField = JPasswordField(15)
        self.signupPasswordField.setPreferredSize(Dimension(150, 25))
        signupPanel.add(self.signupPasswordField)
        signupButton = JButton("Sign Up", actionPerformed=self.signUp)
        signupButton.setPreferredSize(Dimension(120, 30))
        signupButtonPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        signupButtonPanel.add(signupButton)
        signupContainer = JPanel()
        signupContainer.setLayout(BoxLayout(signupContainer, BoxLayout.Y_AXIS))
        signupContainer.add(signupPanel)
        signupContainer.add(signupButtonPanel)
        authPanel.add(signupContainer)
        self.tabbedPane.addTab("Auth", authPanel)

        firestorePanel = JPanel(BorderLayout(5, 5))
        firestorePanel.setBorder(EmptyBorder(10, 10, 10, 10))
        firestorePanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Firestore DB Explorer"))
        fsTopPanel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        fsTopPanel.add(JLabel("Collection:"))
        self.collectionField = JTextField(10)
        self.collectionField.setPreferredSize(Dimension(120, 25))
        self.collectionField.setToolTipText("Enter collection name or path")
        fsTopPanel.add(self.collectionField)
        fsTopPanel.add(JLabel("Doc ID (opt):"))
        self.docIdField = JTextField(8)
        self.docIdField.setPreferredSize(Dimension(100, 25))
        fsTopPanel.add(self.docIdField)
        fsTopPanel.add(JLabel("Action:"))
        self.fsOpCombo = JComboBox(["get", "set", "update", "delete"])
        fsTopPanel.add(self.fsOpCombo)
        fsTopPanel.add(JLabel("Query Filter:"))
        self.fsQueryField = JTextField(10)
        self.fsQueryField.setPreferredSize(Dimension(120, 25))
        self.fsQueryField.setToolTipText("e.g. field==value (not implemented)")
        fsTopPanel.add(self.fsQueryField)
        self.fsJsonArea = JTextArea(5, 40)
        self.fsJsonArea.setText('{\n  "someField": "fire",\n  "anotherOne": "pwn"\n}')
        self.fsJsonScroll = JScrollPane(self.fsJsonArea)
        fsButton = JButton("Execute", actionPerformed=self.executeFirestoreFromUI)
        fsButton.setPreferredSize(Dimension(120, 30))
        fsContainer = JPanel(BorderLayout(5, 5))
        fsContainer.add(fsTopPanel, BorderLayout.NORTH)
        fsContainer.add(self.fsJsonScroll, BorderLayout.CENTER)
        fsContainer.add(fsButton, BorderLayout.SOUTH)
        firestorePanel.add(fsContainer, BorderLayout.CENTER)
        self.tabbedPane.addTab("Firestore", firestorePanel)

        functionsPanel = JPanel(BorderLayout(5, 5))
        functionsPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        functionsPanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Cloud Functions"))
        funcInputPanel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        funcInputPanel.add(JLabel("Function Command:"))
        self.cfCommandField = JTextField(30)
        self.cfCommandField.setPreferredSize(Dimension(200, 25))
        self.cfCommandField.setToolTipText("e.g. makeAdmin({\"email\":\"test@pwn.com\", \"isAdmin\":true})")
        funcInputPanel.add(self.cfCommandField)
        functionsPanel.add(funcInputPanel, BorderLayout.NORTH)
        cfButtonPanel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 5))
        cfInvokeButton = JButton("Invoke", actionPerformed=self.invokeCloudFunction)
        cfInvokeButton.setPreferredSize(Dimension(120, 30))
        cfButtonPanel.add(cfInvokeButton)
        listFunctionsButton = JButton("List Functions", actionPerformed=self.listCloudFunctions)
        listFunctionsButton.setToolTipText("Not yet implemented")
        listFunctionsButton.setPreferredSize(Dimension(140, 30))
        cfButtonPanel.add(listFunctionsButton)
        functionsPanel.add(cfButtonPanel, BorderLayout.SOUTH)
        self.tabbedPane.addTab("Cloud Functions", functionsPanel)

        appInfoPanel = JPanel(GridLayout(0, 2, 10, 10))
        appInfoPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        appInfoPanel.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "App Information"))
        appInfoPanel.add(JLabel("App ID:"))
        self.appIdField = JTextField(15)
        self.appIdField.setPreferredSize(Dimension(150, 25))
        self.appIdField.setEditable(False)
        appInfoPanel.add(self.appIdField)
        appInfoPanel.add(JLabel("Message ID:"))
        self.messageIdField = JTextField(15)
        self.messageIdField.setPreferredSize(Dimension(150, 25))
        self.messageIdField.setEditable(False)
        appInfoPanel.add(self.messageIdField)
        fetchAppInfoButton = JButton("Fetch App Info", actionPerformed=self.fetchAppInfo)
        fetchAppInfoButton.setPreferredSize(Dimension(140, 30))
        appInfoButtonPanel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 5))
        appInfoButtonPanel.add(fetchAppInfoButton)
        appInfoContainer = JPanel(BorderLayout(5, 5))
        appInfoContainer.setBorder(EmptyBorder(5, 5, 5, 5))
        appInfoContainer.add(appInfoPanel, BorderLayout.CENTER)
        appInfoContainer.add(appInfoButtonPanel, BorderLayout.SOUTH)
        self.tabbedPane.addTab("App Info", appInfoContainer)

        logsPanel = JPanel(BorderLayout(5, 5))
        logsPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        self.logTextArea = JTextArea(15, 60)
        self.logTextArea.setEditable(False)
        logScrollPane = JScrollPane(self.logTextArea)
        logScrollPane.setBorder(TitledBorder(BorderFactory.createEtchedBorder(), "Log Output"))
        logsPanel.add(logScrollPane, BorderLayout.CENTER)
        clearLogsButton = JButton("Clear Logs", actionPerformed=self.clearLogs)
        clearLogsButton.setPreferredSize(Dimension(120, 30))
        logsButtonPanel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 5))
        logsButtonPanel.add(clearLogsButton)
        logsPanel.add(logsButtonPanel, BorderLayout.SOUTH)
        self.tabbedPane.addTab("Logs", logsPanel)

    def initFirebase(self, event):
        with self.lock:
            try:
                apiKey = self.apiKeyField.getText().strip()
                authDomain = self.authDomainField.getText().strip()
                databaseURL = self.databaseURLField.getText().strip()
                projectId = self.projectIdField.getText().strip()
                if not (apiKey and authDomain and databaseURL and projectId):
                    raise ValueError("All fields are required.")
                self.firebase_config = {
                    "apiKey": apiKey,
                    "authDomain": authDomain,
                    "databaseURL": databaseURL,
                    "projectId": projectId
                }
                self.logOutput("Firebase initialized successfully.")
            except Exception as e:
                self.showErrorDialog(str(e))
                self.logOutput("Initialization error: " + str(e), is_error=True)

    def signIn(self, event):
        try:
            if not self.firebase_config:
                raise ValueError("Firebase not initialized.")
            email = self.signinEmailField.getText().strip()
            password = "".join(self.signinPasswordField.getPassword()).strip()
            if not email or not password:
                raise ValueError("Email and password are required.")
            url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={0}".format(self.firebase_config["apiKey"])
            data = json.dumps({
                "email": email,
                "password": password,
                "returnSecureToken": True
            })
            req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
            res = self.opener.open(req)
            response = json.loads(res.read())
            SwingUtilities.invokeLater(RunnableWrapper(lambda: self.updateAuthState(response)))
            self.logOutput("Sign in successful.")
        except urllib2.HTTPError as e:
            err = json.loads(e.read())['error']['message']
            self.logOutput("Sign in failed (HTTP {0}): {1}".format(e.code, self.formatFirebaseError(err)), is_error=True)
        except Exception as e:
            self.logOutput("Sign in error: " + str(e), is_error=True)

    def signUp(self, event):
        try:
            if not self.firebase_config:
                raise ValueError("Firebase not initialized.")
            email = self.signupEmailField.getText().strip()
            password = "".join(self.signupPasswordField.getPassword()).strip()
            if not email or not password:
                raise ValueError("Email and password are required.")
            url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={0}".format(self.firebase_config["apiKey"])
            data = json.dumps({
                "email": email,
                "password": password,
                "returnSecureToken": True
            })
            req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
            res = self.opener.open(req)
            response = json.loads(res.read())
            SwingUtilities.invokeLater(RunnableWrapper(lambda: self.updateAuthState(response)))
            self.logOutput("Sign up successful.")
        except urllib2.HTTPError as e:
            err = json.loads(e.read())['error']['message']
            self.logOutput("Sign up failed (HTTP {0}): {1}".format(e.code, self.formatFirebaseError(err)), is_error=True)
        except Exception as e:
            self.logOutput("Sign up error: " + str(e), is_error=True)

    def updateAuthState(self, response):
        self.id_token = response.get("idToken")
        self.refresh_token = response.get("refreshToken")
        self.token_expires_in = response.get("expiresIn")  # typically in seconds
        user_email = response.get("email", "unknown")
        status_text = "Logged in as: {0}".format(user_email)
        if self.token_expires_in:
            try:
                expiry_minutes = int(self.token_expires_in) // 60
                status_text += " (Token expires in ~{0} min)".format(expiry_minutes)
            except:
                pass
        SwingUtilities.invokeLater(RunnableWrapper(lambda: self.authStatusLabel.setText(status_text)))
        Thread(target=self.tokenRefreshDaemon).start()

    def manualAuthRefresh(self, event):
        self.logOutput("Manual auth status refresh requested.")
        SwingUtilities.invokeLater(RunnableWrapper(lambda: self.authStatusLabel.setText("Refreshing...")))
        def check_refresh():
            time.sleep(3)
            if not self.id_token:
                SwingUtilities.invokeLater(RunnableWrapper(lambda: self.authStatusLabel.setText("Not logged in")))
        Thread(target=check_refresh).start()

    def tokenRefreshDaemon(self):
        while self.refresh_token:
            try:
                time.sleep(3000)  # ~50 minutes
                url = "https://securetoken.googleapis.com/v1/token?key={0}".format(self.firebase_config["apiKey"])
                data = "grant_type=refresh_token&refresh_token={0}".format(self.refresh_token)
                req = urllib2.Request(url, data)
                res = self.opener.open(req)
                tokens = json.loads(res.read())
                with self.lock:
                    self.id_token = tokens.get("id_token")
                    self.refresh_token = tokens.get("refresh_token")
                    self.token_expires_in = tokens.get("expires_in")
                self.logOutput("Token refreshed successfully.")
            except Exception as e:
                self.logOutput("Token refresh failed: " + str(e) + " (No automatic retry)", is_error=True)
                break

    def tokenExpirationUpdater(self):
        while True:
            if self.token_expires_in:
                try:
                    expiry_minutes = int(self.token_expires_in) // 60
                    current_status = self.authStatusLabel.getText().split(" (")[0]
                    new_status = "{0} (Token expires in ~{1} min)".format(current_status, expiry_minutes)
                    SwingUtilities.invokeLater(RunnableWrapper(lambda: self.authStatusLabel.setText(new_status)))
                except:
                    pass
            time.sleep(60)
            
    def executeFirestoreFromUI(self, event):
        try:
            collection = self.collectionField.getText().strip()
            doc_id = self.docIdField.getText().strip()
            op = self.fsOpCombo.getSelectedItem()
            data = self.fsJsonArea.getText().strip()
            query_filter = self.fsQueryField.getText().strip()
            if query_filter:
                self.logOutput("Query filter provided but not implemented: " + query_filter)
            self.executeFirestoreOp(op, collection, doc_id, data)
        except Exception as e:
            self.logOutput("Firestore operation error: " + str(e), is_error=True)

    def executeFirestoreOp(self, operation, collection, doc_id, data):
        try:
            if not self.firebase_config:
                raise ValueError("Firebase not initialized.")
            if not re.match(r"^[a-zA-Z0-9_\/]+$", collection):
                raise ValueError("Invalid collection path")
            base_url = "https://firestore.googleapis.com/v1/projects/{0}/databases/(default)/documents/".format(self.firebase_config["projectId"])
            url = base_url + urllib.quote(collection.strip('/'), safe='')
            if doc_id:
                if not re.match(r"^[a-zA-Z0-9_-]+$", doc_id):
                    raise ValueError("Invalid document ID")
                url += "/" + doc_id
            headers = {}
            if self.id_token:
                headers["Authorization"] = "Bearer {0}".format(self.id_token)
            if operation in ["set", "update"]:
                data_json = json.loads(data)
                firestore_data = self._convert_to_firestore_format(data_json)
            if operation == "get":
                req = urllib2.Request(url, headers=headers)
                res = self.opener.open(req)
                self.logOutput("Response:\n" + self._format_response(res))
            elif operation == "set":
                method = "POST" if not doc_id else "PATCH"
                params = "?currentDocument.exists=false" if method == "POST" else ""
                req = urllib2.Request(url + params, json.dumps({"fields": firestore_data}), headers)
                req.get_method = lambda: method
                res = self.opener.open(req)
                self.logOutput("Document written:\n" + self._format_response(res))
            elif operation == "update":
                req = urllib2.Request(url, json.dumps({
                    "fields": firestore_data,
                    "mask": {"fieldPaths": list(data_json.keys())}
                }), headers)
                req.get_method = lambda: "PATCH"
                res = self.opener.open(req)
                self.logOutput("Document updated:\n" + self._format_response(res))
            elif operation == "delete":
                req = urllib2.Request(url, headers=headers)
                req.get_method = lambda: "DELETE"
                res = self.opener.open(req)
                self.logOutput("Document deleted:\n" + self._format_response(res))
        except urllib2.HTTPError as e:
            err = json.loads(e.read())['error']['message']
            self.logOutput("Firestore Error [HTTP {0}]: {1}".format(e.code, self.formatFirebaseError(err)), is_error=True)
        except Exception as e:
            self.logOutput("Firestore Error: " + self.formatFirebaseError(str(e)), is_error=True)

    def _convert_to_firestore_format(self, data):
        TYPE_MAPPING = {
            bool: ("booleanValue", lambda x: x),
            int: ("integerValue", lambda x: str(x)),
            float: ("doubleValue", lambda x: x if not math.isnan(x) else "NaN"),
            str: ("stringValue", lambda x: x),
            type(None): ("nullValue", lambda x: None),
            dict: ("mapValue", lambda x: {"fields": {k: self._convert_to_firestore_format(v) for k, v in x.items()}}),
            list: ("arrayValue", lambda x: {"values": [self._convert_to_firestore_format(v) for v in x]})
        }
        def convert(value):
            for type_class, (type_name, converter) in TYPE_MAPPING.items():
                if isinstance(value, type_class):
                    return {type_name: converter(value)}
            try:
                if isinstance(value, long):
                    return {"integerValue": str(value)}
            except NameError:
                pass
            raise ValueError("Unsupported type: " + str(type(value)))
        return {k: convert(v) for k, v in data.items()}

    def _format_response(self, response):
        try:
            return json.dumps(json.loads(response.read()), indent=2)
        except Exception:
            return "Non-JSON response"

    def invokeCloudFunction(self, event):
        try:
            if not self.firebase_config:
                raise ValueError("Firebase not initialized.")
            cmd = self.cfCommandField.getText().strip()
            m = re.match(r"^([a-zA-Z][a-zA-Z0-9-_]*)\((.*)\)$", cmd)
            if not m:
                raise ValueError("Invalid command syntax. Use: functionName({...})")
            func_name = m.group(1)
            params_str = m.group(2)
            data = json.loads(params_str) if params_str.strip() else {}
            region = self.firebase_config.get("region", "us-central1")
            url = "https://{0}-{1}.cloudfunctions.net/{2}".format(region, self.firebase_config["projectId"], func_name)
            headers = {'Content-Type': 'application/json'}
            if self.id_token:
                headers["Authorization"] = "Bearer {0}".format(self.id_token)
            req = urllib2.Request(url, json.dumps(data), headers)
            res = self.opener.open(req)
            self.logOutput("Function Response:\n" + self._format_response(res))
        except urllib2.HTTPError as e:
            err = json.loads(e.read())['error']
            self.logOutput("Function Error [HTTP {0}]: {1}".format(e.code, err), is_error=True)
        except Exception as e:
            self.logOutput("Function Error: " + self.formatFirebaseError(str(e)), is_error=True)

    def listCloudFunctions(self, event):
        self.logOutput("List Functions feature is not implemented yet.", is_error=True)

    def fetchAppInfo(self, event):
        try:
            if not self.firebase_config:
                raise ValueError("Firebase not initialized.")
            if not self.id_token:
                raise ValueError("Not authenticated. Please sign in first.")
            appid_url = "https://{0}/v1/projects/{1}/appInfo?key={2}".format(
                self.firebase_config["authDomain"],
                self.firebase_config["projectId"],
                self.firebase_config["apiKey"]
            )
            msgid_url = "https://{0}/v1/projects/{1}/messageInfo?key={2}".format(
                self.firebase_config["authDomain"],
                self.firebase_config["projectId"],
                self.firebase_config["apiKey"]
            )
            req_app = urllib2.Request(appid_url)
            req_app.add_header("Authorization", "Bearer {0}".format(self.id_token))
            res_app = self.opener.open(req_app)
            app_info = json.loads(res_app.read())
            app_id = app_info.get("appId", "N/A")
            req_msg = urllib2.Request(msgid_url)
            req_msg.add_header("Authorization", "Bearer {0}".format(self.id_token))
            res_msg = self.opener.open(req_msg)
            msg_info = json.loads(res_msg.read())
            message_id = msg_info.get("messageId", "N/A")
            SwingUtilities.invokeLater(RunnableWrapper(lambda: self.appIdField.setText(app_id)))
            SwingUtilities.invokeLater(RunnableWrapper(lambda: self.messageIdField.setText(message_id)))
            self.logOutput("Fetched App Info successfully.")
        except urllib2.HTTPError as e:
            err = json.loads(e.read()).get("error", "Unknown error")
            self.logOutput("Fetch App Info HTTP Error: " + str(err), is_error=True)
        except Exception as e:
            self.logOutput("Fetch App Info error: " + str(e), is_error=True)

    def clearLogs(self, event):
        SwingUtilities.invokeLater(RunnableWrapper(lambda: self.logTextArea.setText("")))

    def formatFirebaseError(self, error):
        ERROR_MAP = {
            "INVALID_LOGIN_CREDENTIALS": "Invalid email or password",
            "EMAIL_NOT_FOUND": "Email not registered",
            "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts – try again later",
            "MISSING_REQUIRED_FIELD": "Missing required field",
            "PERMISSION_DENIED": "Permission denied – check security rules"
        }
        try:
            key = error.split(':')[-1].strip()
        except:
            key = error
        return ERROR_MAP.get(key, error)

    def showErrorDialog(self, message):
        SwingUtilities.invokeLater(RunnableWrapper(lambda:
            JOptionPane.showMessageDialog(self.mainPanel, message, "Error", JOptionPane.ERROR_MESSAGE)
        ))

    def logOutput(self, message, is_error=False):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = "[ERROR] " if is_error else "[INFO] "
        full_message = "{0}{1}: {2}\n".format(prefix, timestamp, message)
        def appendLog():
            self.logTextArea.append(full_message)
            self.logTextArea.setCaretPosition(self.logTextArea.getDocument().getLength())
        SwingUtilities.invokeLater(RunnableWrapper(appendLog))

    def getTabCaption(self):
        return "BurpFirepwn"

    def getUiComponent(self):
        return self.mainPanel

from threading import Thread
if not hasattr(Thread, 'daemon'):
    Thread.daemon = property(lambda self: self.isDaemon(),
                               lambda self, daemon: self.setDaemon(daemon))

SwingUtilities.invokeLater(RunnableWrapper(lambda: None))