# HoneyBee Node Examples

This document provides practical examples for common use cases.

## Table of Contents

- [Basic Configuration](#basic-configuration)
- [TLS Setup](#tls-setup)
- [TOTP Authentication](#totp-authentication)
- [Deployment Scenarios](#deployment-scenarios)
- [Monitoring and Logging](#monitoring-and-logging)

## Basic Configuration

### Minimal Configuration

```yaml
node:
  name: "basic-node"
  type: "Agent"

server:
  address: "127.0.0.1:9001"

tls:
  enabled: false  # Not recommended for production!

auth:
  totp_enabled: false  # Not recommended for production!

log:
  level: "info"
  format: "text"
```

### Production Configuration

```yaml
node:
  name: "prod-honeypot-01"
  type: "Full"
  address: "10.0.1.100"
  port: 8080

server:
  address: "manager.internal:9001"
  heartbeat_interval: 30
  reconnect_delay: 5
  connection_timeout: 10

tls:
  enabled: true
  cert_file: "/etc/honeybee/certs/client.crt"
  key_file: "/etc/honeybee/certs/client.key"
  ca_file: "/etc/honeybee/certs/ca.crt"
  insecure_skip_verify: false
  server_name: "honeybee-manager"

auth:
  totp_enabled: true
  totp_secret_dir: "/var/lib/honeybee/secrets"

log:
  level: "info"
  format: "json"
  file: "/var/log/honeybee/node.log"
```

## TLS Setup

### Self-Signed Certificates (Development)

```bash
#!/bin/bash
# generate-certs.sh

# Create certs directory
mkdir -p certs

# Generate CA
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -days 365 -key certs/ca.key -out certs/ca.crt \
  -subj "/C=US/ST=State/L=City/O=HoneyBee/CN=HoneyBee CA"

# Generate Server Certificate
openssl genrsa -out certs/server.key 4096
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/C=US/ST=State/L=City/O=HoneyBee/CN=honeybee-manager"
openssl x509 -req -days 365 -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt

# Generate Client Certificate
openssl genrsa -out certs/client.key 4096
openssl req -new -key certs/client.key -out certs/client.csr \
  -subj "/C=US/ST=State/L=City/O=HoneyBee/CN=honeybee-node"
openssl x509 -req -days 365 -in certs/client.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/client.crt

# Verify certificates
openssl verify -CAfile certs/ca.crt certs/server.crt
openssl verify -CAfile certs/ca.crt certs/client.crt

echo "Certificates generated successfully!"
```

### Test TLS Connection

```bash
# Test server TLS
openssl s_client -connect 127.0.0.1:9001 \
  -CAfile certs/ca.crt \
  -cert certs/client.crt \
  -key certs/client.key
```

## TOTP Authentication

### Manual TOTP Setup

```bash
# 1. Run node for first time (generates secret)
./honeybee-node -config configs/config.yaml

# 2. Check the generated secret
cat ~/.config/honeybee/.honeybee_totp_secret

# 3. Import into authenticator app (optional)
# Use QR code generator with the secret
```

### Reset TOTP Secret

```bash
#!/bin/bash
# reset-totp.sh

# Backup existing secret
if [ -f ~/.config/honeybee/.honeybee_totp_secret ]; then
    cp ~/.config/honeybee/.honeybee_totp_secret \
       ~/.config/honeybee/.honeybee_totp_secret.backup
fi

# Remove secret
rm -f ~/.config/honeybee/.honeybee_totp_secret

# Next connection will generate new secret
echo "TOTP secret reset. Restart the node to generate a new one."
```

## Deployment Scenarios

### Scenario 1: Single Node Deployment

```bash
# 1. Build the node
make build

# 2. Create configuration
./build/honeybee-node -gen-config

# 3. Edit configuration
vim configs/config.yaml

# 4. Run the node
./build/honeybee-node -config configs/config.yaml
```

### Scenario 2: Multi-Node Deployment with Ansible

```yaml
# playbook.yml
---
- hosts: honeypot_nodes
  become: yes
  tasks:
    - name: Create honeybee user
      user:
        name: honeybee
        system: yes
        shell: /bin/false

    - name: Copy binary
      copy:
        src: build/honeybee-node
        dest: /usr/local/bin/honeybee-node
        mode: '0755'
        owner: honeybee

    - name: Create directories
      file:
        path: "{{ item }}"
        state: directory
        owner: honeybee
        group: honeybee
        mode: '0755'
      loop:
        - /etc/honeybee
        - /etc/honeybee/certs
        - /var/log/honeybee

    - name: Copy configuration
      template:
        src: config.yaml.j2
        dest: /etc/honeybee/config.yaml
        owner: honeybee
        group: honeybee
        mode: '0644'

    - name: Copy certificates
      copy:
        src: "{{ item.src }}"
        dest: "{{ item.dest }}"
        owner: honeybee
        group: honeybee
        mode: '0600'
      loop:
        - { src: 'certs/client.crt', dest: '/etc/honeybee/certs/client.crt' }
        - { src: 'certs/client.key', dest: '/etc/honeybee/certs/client.key' }
        - { src: 'certs/ca.crt', dest: '/etc/honeybee/certs/ca.crt' }

    - name: Install systemd service
      copy:
        src: honeybee-node.service
        dest: /etc/systemd/system/honeybee-node.service
        mode: '0644'

    - name: Enable and start service
      systemd:
        name: honeybee-node
        enabled: yes
        state: started
        daemon_reload: yes
```

### Scenario 3: Docker Deployment

```bash
# docker-compose.yml
version: '3.8'

services:
  honeybee-node:
    image: honeybee-node:latest
    container_name: honeybee-node
    restart: unless-stopped
    volumes:
      - ./configs/config.yaml:/app/configs/config.yaml:ro
      - ./certs:/app/certs:ro
      - ./logs:/app/logs
      - totp-secrets:/home/honeybee/.config/honeybee
    environment:
      - TZ=UTC
    networks:
      - honeybee-net
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  totp-secrets:

networks:
  honeybee-net:
    driver: bridge
```

### Scenario 4: Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: honeybee-node-config
data:
  config.yaml: |
    node:
      name: k8s-node
      type: Agent
    server:
      address: honeybee-manager.default.svc.cluster.local:9001
    tls:
      enabled: true
      insecure_skip_verify: false
    log:
      level: info
      format: json

---
apiVersion: v1
kind: Secret
metadata:
  name: honeybee-tls
type: Opaque
data:
  client.crt: <base64-encoded-cert>
  client.key: <base64-encoded-key>
  ca.crt: <base64-encoded-ca>

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: honeybee-node
spec:
  replicas: 3
  selector:
    matchLabels:
      app: honeybee-node
  template:
    metadata:
      labels:
        app: honeybee-node
    spec:
      containers:
      - name: honeybee-node
        image: honeybee-node:1.0.0
        volumeMounts:
        - name: config
          mountPath: /app/configs
        - name: tls
          mountPath: /app/certs
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
      volumes:
      - name: config
        configMap:
          name: honeybee-node-config
      - name: tls
        secret:
          secretName: honeybee-tls
```

## Monitoring and Logging

### Centralized Logging with Fluentd

```yaml
# fluentd.conf
<source>
  @type tail
  path /var/log/honeybee/node.log
  pos_file /var/log/honeybee/node.log.pos
  tag honeybee.node
  <parse>
    @type json
    time_key time
    time_format %Y-%m-%dT%H:%M:%S.%NZ
  </parse>
</source>

<match honeybee.node>
  @type elasticsearch
  host elasticsearch.example.com
  port 9200
  logstash_format true
  logstash_prefix honeybee
</match>
```

### Log Rotation

```bash
# /etc/logrotate.d/honeybee-node
/var/log/honeybee/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 honeybee honeybee
    postrotate
        systemctl reload honeybee-node
    endscript
}
```

### Health Check Script

```bash
#!/bin/bash
# health-check.sh

# Check if process is running
if ! pgrep -x "honeybee-node" > /dev/null; then
    echo "ERROR: honeybee-node is not running"
    exit 1
fi

# Check recent logs for errors
if tail -n 100 /var/log/honeybee/node.log | grep -q "ERROR"; then
    echo "WARNING: Recent errors found in logs"
    exit 1
fi

echo "OK: honeybee-node is healthy"
exit 0
```

### Prometheus Metrics (Future Feature)

```go
// metrics.go - Example for future implementation
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    messagesReceived = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "honeybee_messages_received_total",
            Help: "Total number of messages received",
        },
        []string{"type"},
    )
    
    connectionStatus = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "honeybee_connection_status",
            Help: "Current connection status (1=connected, 0=disconnected)",
        },
    )
)
```

## Troubleshooting Examples

### Debug Mode

```yaml
log:
  level: "debug"
  format: "text"
  file: "/tmp/honeybee-debug.log"
```

### Network Troubleshooting

```bash
# Test connectivity
nc -zv manager.example.com 9001

# Test TLS
openssl s_client -connect manager.example.com:9001

# Check firewall
sudo iptables -L -n | grep 9001

# Check DNS resolution
nslookup manager.example.com

# Test with curl (if manager has HTTP endpoint)
curl -v https://manager.example.com:9001
```

### Performance Testing

```bash
# Monitor resource usage
watch -n 1 'ps aux | grep honeybee-node'

# Network statistics
watch -n 1 'netstat -an | grep 9001'

# System resources
htop -p $(pgrep honeybee-node)
```

## Integration Examples

### With Syslog

```yaml
log:
  level: "info"
  format: "json"
  # Send to syslog instead of file
```

### With Logstash

```json
{
  "input": {
    "file": {
      "path": "/var/log/honeybee/node.log",
      "codec": "json"
    }
  },
  "filter": {
    "json": {
      "source": "message"
    }
  },
  "output": {
    "elasticsearch": {
      "hosts": ["localhost:9200"],
      "index": "honeybee-%{+YYYY.MM.dd}"
    }
  }
}
```

## Best Practices

1. **Always use TLS in production**
2. **Enable TOTP authentication**
3. **Run as non-root user**
4. **Use systemd for process management**
5. **Implement log rotation**
6. **Monitor health checks**
7. **Keep certificates up to date**
8. **Regular security audits**
9. **Backup TOTP secrets**
10. **Use configuration management tools**

## Next Steps

- Review [README.md](../README.md) for general usage
- Check [SECURITY.md](../SECURITY.md) for security guidelines
- See [CONTRIBUTING.md](../CONTRIBUTING.md) for development

