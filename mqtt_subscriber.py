import json
import time
from awscrt import mqtt
from awsiot import mqtt_connection_builder

class SimpleMQTTSubscriber:
    def __init__(self, endpoint, client_id, cert_path, key_path, root_ca_path):
        self.endpoint = endpoint
        self.client_id = client_id
        self.cert_path = cert_path
        self.key_path = key_path
        self.root_ca_path = root_ca_path
        self.mqtt_connection = None
        self.message_count = 0
        
    def on_message_received(self, topic, payload, dup, qos, retain, **kwargs):
        self.message_count += 1
        try:
            message = json.loads(payload.decode('utf-8'))
            print(f"📨 Received message #{self.message_count} on topic '{topic}':")
            print(json.dumps(message, indent=2))
            print("-" * 40)
        except:
            print(f"📨 Received message #{self.message_count} on topic '{topic}': {payload.decode('utf-8')}")

    def connect(self):
        try:
            self.mqtt_connection = mqtt_connection_builder.mtls_from_path(
                endpoint=self.endpoint,
                cert_filepath=self.cert_path,
                pri_key_filepath=self.key_path,
                client_id=self.client_id,
                clean_session=True,
                keep_alive_secs=30)
            
            print(f"Connecting to {self.endpoint} with client ID {self.client_id}...")
            connect_future = self.mqtt_connection.connect()
            connect_future.result()
            print("✅ Successfully connected to AWS IoT!")
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False

    def subscribe(self, topic):
        try:
            print(f"Subscribing to topic: {topic}")
            subscribe_future, packet_id = self.mqtt_connection.subscribe(
                topic=topic,
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=self.on_message_received)
            
            subscribe_result = subscribe_future.result()
            print(f"✅ Subscribed to {topic} with QoS: {subscribe_result['qos']}")
            return True
            
        except Exception as e:
            print(f"❌ Subscription failed: {e}")
            return False

    def disconnect(self):
        if self.mqtt_connection:
            print("Disconnecting...")
            disconnect_future = self.mqtt_connection.disconnect()
            disconnect_future.result()
            print(f"✅ Disconnected. Total messages received: {self.message_count}")

def run_simple_subscriber():
    config = {
        "endpoint": "a2kymckba2gab5-ats.iot.ap-northeast-1.amazonaws.com",
        "client_id": "RaspberryPI_AWS_Subscriber",  # Or use your test client ID
        "cert_path": "/home/nippoh/Mqtt_Subscriber/428dde17b36a2bf42d45f4da4d8038b852800d4df017b9e7f635d246c2be28e2-certificate.pem.crt",
        "key_path": "/home/nippoh/Mqtt_Subscriber/428dde17b36a2bf42d45f4da4d8038b852800d4df017b9e7f635d246c2be28e2-private.pem.key",
        "root_ca_path": "/home/nippoh/Mqtt_Subscriber/AmazonRootCA1.pem"
    }
    
    subscriber = SimpleMQTTSubscriber(**config)
    
    try:
        if subscriber.connect():
            subscriber.subscribe("test/dc/#")
            
            print("\n" + "="*50)
            print("👂 MQTT Subscriber Started")
            print("="*50)
            print("Listening for messages... Press Ctrl+C to exit\n")
            
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        subscriber.disconnect()

if __name__ == "__main__":
    run_simple_subscriber()
