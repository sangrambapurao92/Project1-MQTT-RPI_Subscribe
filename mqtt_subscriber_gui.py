import json
import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from awscrt import mqtt
from awsiot import mqtt_connection_builder
from datetime import datetime

class MQTTSubscriberGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MQTT Subscriber - Receive Data")
        self.root.geometry("700x800")
        self.root.resizable(True, True)
        
        # MQTT Configuration
        self.config = {
            "endpoint": "a2kymckba2gab5-ats.iot.ap-northeast-1.amazonaws.com",
            "client_id": "RaspberryPI_AWS_Subscriber",
            "cert_path": "/home/nippoh/Mqtt_Subscriber/428dde17b36a2bf42d45f4da4d8038b852800d4df017b9e7f635d246c2be28e2-certificate.pem.crt",
            "key_path": "/home/nippoh/Mqtt_Subscriber/428dde17b36a2bf42d45f4da4d8038b852800d4df017b9e7f635d246c2be28e2-private.pem.key",
            "root_ca_path": "/home/nippoh/Mqtt_Subscriber/AmazonRootCA1.pem"
        }
        
        self.mqtt_connection = None
        self.is_connected = False
        self.message_count = 0
        self.subscribed_topics = []
        
        self.setup_gui()
        
    def setup_gui(self):
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="MQTT Data Subscriber", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Connection status frame
        status_frame = ttk.LabelFrame(main_frame, text="Connection Status", padding="10")
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar(value="🔄 Connecting...")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                     font=("Arial", 10, "bold"))
        self.status_label.grid(row=0, column=0, padx=5)
        
        # Message count display
        self.count_var = tk.StringVar(value="Messages Received: 0")
        count_label = ttk.Label(status_frame, textvariable=self.count_var)
        count_label.grid(row=1, column=0, pady=(5, 0))
        
        # Subscription management frame
        sub_frame = ttk.LabelFrame(main_frame, text="Topic Subscription", padding="10")
        sub_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        sub_frame.columnconfigure(1, weight=1)
        
        # Add subscription
        ttk.Label(sub_frame, text="Subscribe to Topic:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.topic_var = tk.StringVar(value="test/dc/#")
        self.topic_entry = ttk.Entry(sub_frame, textvariable=self.topic_var, width=30)
        self.topic_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.subscribe_btn = ttk.Button(sub_frame, text="📥 Subscribe", 
                                       command=self.subscribe_to_topic, state="disabled")
        self.subscribe_btn.grid(row=0, column=2)
        
        # Active subscriptions list
        ttk.Label(sub_frame, text="Active Subscriptions:").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        
        # Listbox for subscriptions with scrollbar
        list_frame = ttk.Frame(sub_frame)
        list_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
        list_frame.columnconfigure(0, weight=1)
        
        self.subscriptions_listbox = tk.Listbox(list_frame, height=3)
        self.subscriptions_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        sub_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.subscriptions_listbox.yview)
        sub_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.subscriptions_listbox.configure(yscrollcommand=sub_scrollbar.set)
        
        self.unsubscribe_btn = ttk.Button(sub_frame, text="🗑️ Unsubscribe Selected", 
                                         command=self.unsubscribe_from_topic, state="disabled")
        self.unsubscribe_btn.grid(row=3, column=0, columnspan=3, pady=(5, 0))
        
        # Publishing frame (for sending responses)
        pub_frame = ttk.LabelFrame(main_frame, text="Send Response Message", padding="10")
        pub_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        pub_frame.columnconfigure(1, weight=1)
        
        ttk.Label(pub_frame, text="Publish to:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.publish_topic_var = tk.StringVar(value="test/my/pubtopic")
        pub_topic_entry = ttk.Entry(pub_frame, textvariable=self.publish_topic_var, width=30)
        pub_topic_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.publish_btn = ttk.Button(pub_frame, text="📤 Send Response", 
                                     command=self.publish_response, state="disabled")
        self.publish_btn.grid(row=0, column=2)
        
        # Response message text area
        ttk.Label(pub_frame, text="Response Message:").grid(row=1, column=0, sticky=tk.NW, padx=(0, 10), pady=(5, 0))
        self.response_text = scrolledtext.ScrolledText(pub_frame, height=3, width=40, font=("Consolas", 10))
        self.response_text.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Set default response message
        default_response = {
            "timestamp": int(time.time()),
            "message": "Response from Subscriber",
            "client_id": self.config["client_id"],
            "status": "received"
        }
        self.response_text.insert(1.0, json.dumps(default_response, indent=2))
        
        # Message display options frame
        options_frame = ttk.LabelFrame(main_frame, text="Display Options", padding="10")
        options_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Display format options
        format_frame = ttk.Frame(options_frame)
        format_frame.grid(row=0, column=0, sticky=tk.W)
        
        ttk.Label(format_frame, text="Display Format:").grid(row=0, column=0, padx=(0, 10))
        self.display_format = tk.StringVar(value="Pretty JSON")
        ttk.Radiobutton(format_frame, text="Pretty JSON", variable=self.display_format, 
                       value="Pretty JSON").grid(row=0, column=1, padx=5)
        ttk.Radiobutton(format_frame, text="Raw Text", variable=self.display_format, 
                       value="Raw Text").grid(row=0, column=2, padx=5)
        
        # Auto-scroll option
        self.auto_scroll_var = tk.BooleanVar(value=True)
        auto_scroll_check = ttk.Checkbutton(options_frame, text="Auto-scroll to latest message", 
                                           variable=self.auto_scroll_var)
        auto_scroll_check.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Clear messages button
        clear_btn = ttk.Button(options_frame, text="🗑️ Clear Messages", 
                              command=self.clear_messages)
        clear_btn.grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        
        # Save messages button
        save_btn = ttk.Button(options_frame, text="💾 Save Messages", 
                             command=self.save_messages)
        save_btn.grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=(5, 0))
        
        # Received messages frame
        msg_frame = ttk.LabelFrame(main_frame, text="Received Messages", padding="10")
        msg_frame.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        msg_frame.columnconfigure(0, weight=1)
        msg_frame.rowconfigure(0, weight=1)
        
        self.messages_text = scrolledtext.ScrolledText(msg_frame, height=15, width=60, 
                                                      wrap=tk.WORD, font=("Consolas", 10))
        self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Activity log frame
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, width=60, 
                                                 font=("Arial", 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure main frame row weights
        main_frame.rowconfigure(5, weight=3)  # Messages display
        main_frame.rowconfigure(6, weight=1)  # Activity log
        
        self.log_message("🚀 MQTT Subscriber GUI started")
        
        # Auto-connect and subscribe after GUI is ready
        self.root.after(1000, self.auto_connect)
        
    def log_message(self, message):
        """Add message to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def auto_connect(self):
        """Auto-connect to AWS IoT on startup and subscribe to default topic"""
        threading.Thread(target=self._auto_connect_worker, daemon=True).start()
    
    def _auto_connect_worker(self):
        """Auto-connect worker that connects and subscribes"""
        if self.connect():
            # Auto-subscribe to default topic
            self._subscribe_to_topic("test/dc/#")
    
    def on_message_received(self, topic, payload, dup, qos, retain, **kwargs):
        """Handle received MQTT messages"""
        self.message_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Try to parse as JSON
            message_data = json.loads(payload.decode('utf-8'))
            is_json = True
        except:
            # If not JSON, treat as plain text
            message_data = payload.decode('utf-8')
            is_json = False
        
        # Format message for display
        separator = "="*80 + "\n"
        header = f"📨 Message #{self.message_count} | Topic: {topic} | Time: {timestamp}\n"
        
        if self.display_format.get() == "Pretty JSON" and is_json:
            formatted_content = json.dumps(message_data, indent=2, ensure_ascii=False)
        else:
            formatted_content = str(message_data)
        
        full_message = separator + header + separator + formatted_content + "\n\n"
        
        # Update GUI in main thread
        self.root.after(0, self._update_message_display, full_message)
        self.root.after(0, self._update_message_count)
    
    def _update_message_display(self, message):
        """Update message display (called from main thread)"""
        self.messages_text.insert(tk.END, message)
        
        if self.auto_scroll_var.get():
            self.messages_text.see(tk.END)
    
    def _update_message_count(self):
        """Update message count display"""
        self.count_var.set(f"Messages Received: {self.message_count}")
    
    def update_connection_status(self):
        """Update connection status display"""
        if self.is_connected:
            self.status_var.set("✅ Connected")
            self.subscribe_btn.config(state="normal")
            self.publish_btn.config(state="normal")
            if self.subscribed_topics:
                self.unsubscribe_btn.config(state="normal")
        else:
            self.status_var.set("❌ Disconnected")
            self.subscribe_btn.config(state="disabled")
            self.publish_btn.config(state="disabled")
            self.unsubscribe_btn.config(state="disabled")
    
    def connect(self):
        """Connect to AWS IoT MQTT"""
        try:
            self.log_message("🔄 Connecting to AWS IoT...")
            
            self.mqtt_connection = mqtt_connection_builder.mtls_from_path(
                endpoint=self.config["endpoint"],
                cert_filepath=self.config["cert_path"],
                pri_key_filepath=self.config["key_path"],
                client_id=self.config["client_id"],
                clean_session=True,
                keep_alive_secs=30)
            
            connect_future = self.mqtt_connection.connect()
            connect_future.result()
            
            self.is_connected = True
            self.log_message("✅ Successfully connected to AWS IoT!")
            self.root.after(0, self.update_connection_status)
            
        except Exception as e:
            self.log_message(f"❌ Connection failed: {e}")
            self.root.after(0, self.update_connection_status)
    
    def disconnect(self):
        """Disconnect from AWS IoT MQTT"""
        try:
            if self.mqtt_connection and self.is_connected:
                self.log_message("🔄 Disconnecting...")
                disconnect_future = self.mqtt_connection.disconnect()
                disconnect_future.result()
                
            self.is_connected = False
            self.subscribed_topics.clear()
            self.subscriptions_listbox.delete(0, tk.END)
            self.log_message("✅ Disconnected from AWS IoT")
            self.update_connection_status()
            
        except Exception as e:
            self.log_message(f"❌ Disconnect error: {e}")
    
    def publish_response(self):
        """Publish a response message"""
        if not self.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to AWS IoT first")
            return
        
        threading.Thread(target=self._publish_response, daemon=True).start()
    
    def _publish_response(self):
        """Internal method to publish response message"""
        try:
            topic = self.publish_topic_var.get().strip()
            message_content = self.response_text.get(1.0, tk.END).strip()
            
            if not topic:
                self.log_message("❌ Topic cannot be empty")
                return
            
            if not message_content:
                self.log_message("❌ Message cannot be empty")
                return
            
            # Validate JSON
            try:
                json.loads(message_content)
            except json.JSONDecodeError as e:
                self.log_message(f"❌ Invalid JSON: {e}")
                return
            
            self.mqtt_connection.publish(
                topic=topic,
                payload=message_content,
                qos=mqtt.QoS.AT_LEAST_ONCE)
            
            self.log_message(f"📤 Published response to '{topic}': {message_content[:50]}{'...' if len(message_content) > 50 else ''}")
            
        except Exception as e:
            self.log_message(f"❌ Publish failed: {e}")
    
    def subscribe_to_topic(self):
        """Subscribe to a new topic"""
        if not self.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to AWS IoT first")
            return
        
        topic = self.topic_var.get().strip()
        if not topic:
            messagebox.showwarning("Invalid Topic", "Please enter a topic name")
            return
        
        if topic in self.subscribed_topics:
            messagebox.showinfo("Already Subscribed", f"Already subscribed to '{topic}'")
            return
        
        threading.Thread(target=self._subscribe_to_topic, args=(topic,), daemon=True).start()
    
    def _subscribe_to_topic(self, topic):
        """Internal method to subscribe to topic"""
        try:
            self.log_message(f"🔄 Subscribing to topic: {topic}")
            
            subscribe_future, packet_id = self.mqtt_connection.subscribe(
                topic=topic,
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=self.on_message_received)
            
            subscribe_result = subscribe_future.result()
            
            self.subscribed_topics.append(topic)
            self.root.after(0, self._update_subscriptions_list)
            self.log_message(f"✅ Subscribed to '{topic}' with QoS: {subscribe_result['qos']}")
            
        except Exception as e:
            self.log_message(f"❌ Subscription failed for '{topic}': {e}")
    
    def _update_subscriptions_list(self):
        """Update the subscriptions listbox"""
        self.subscriptions_listbox.delete(0, tk.END)
        for topic in self.subscribed_topics:
            self.subscriptions_listbox.insert(tk.END, topic)
        
        if self.subscribed_topics and self.is_connected:
            self.unsubscribe_btn.config(state="normal")
        else:
            self.unsubscribe_btn.config(state="disabled")
    
    def unsubscribe_from_topic(self):
        """Unsubscribe from selected topic"""
        selection = self.subscriptions_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a topic to unsubscribe from")
            return
        
        topic = self.subscriptions_listbox.get(selection[0])
        threading.Thread(target=self._unsubscribe_from_topic, args=(topic,), daemon=True).start()
    
    def _unsubscribe_from_topic(self, topic):
        """Internal method to unsubscribe from topic"""
        try:
            self.log_message(f"🔄 Unsubscribing from topic: {topic}")
            
            unsubscribe_future, packet_id = self.mqtt_connection.unsubscribe(topic=topic)
            unsubscribe_future.result()
            
            if topic in self.subscribed_topics:
                self.subscribed_topics.remove(topic)
            
            self.root.after(0, self._update_subscriptions_list)
            self.log_message(f"✅ Unsubscribed from '{topic}'")
            
        except Exception as e:
            self.log_message(f"❌ Unsubscribe failed for '{topic}': {e}")
    
    def clear_messages(self):
        """Clear the messages display"""
        self.messages_text.delete(1.0, tk.END)
        self.message_count = 0
        self._update_message_count()
        self.log_message("🗑️ Messages cleared")
    
    def save_messages(self):
        """Save messages to file"""
        try:
            from tkinter import filedialog
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Messages"
            )
            
            if filename:
                content = self.messages_text.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log_message(f"💾 Messages saved to: {filename}")
                
        except Exception as e:
            self.log_message(f"❌ Save failed: {e}")
            messagebox.showerror("Save Error", f"Failed to save messages: {e}")
    
    def on_closing(self):
        """Handle window closing"""
        if self.is_connected:
            self.disconnect()
        
        self.root.destroy()
    
    def run(self):
        """Start the GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

if __name__ == "__main__":
    app = MQTTSubscriberGUI()
    app.run()
