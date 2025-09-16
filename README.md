# Redis Installation Guide

Redis is a free and open-source in-memory data structure store, used as a database, cache, message broker, and streaming engine. Originally developed by Salvatore Sanfilippo, Redis stands for "Remote Dictionary Server" and provides data structures such as strings, hashes, lists, sets, sorted sets with range queries, bitmaps, hyperloglogs, and geospatial indexes. It serves as a FOSS alternative to commercial solutions like Amazon ElastiCache, Azure Cache for Redis, or proprietary in-memory databases, offering comparable performance with features like persistence, replication, Lua scripting, and transactions.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for production)
  - RAM: 1GB minimum (8GB+ recommended for production workloads)
  - Storage: 512MB for installation (SSD recommended for persistence)
  - Network: Low latency network for cluster deployments
- **Operating System**: Linux, BSD, macOS, or Windows (via WSL2)
- **Network Requirements**:
  - Port 6379 (default Redis port)
  - Port 16379 (cluster bus port, if using cluster mode)
  - Additional ports for replicas and sentinel
- **Dependencies**:
  - GCC compiler and libc (for building from source)
  - TCL 8.5+ (for running tests)
  - systemd or init system (for service management)
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# RHEL/CentOS 7
# Enable EPEL repository
sudo yum install -y epel-release

# Install Redis
sudo yum install -y redis

# Enable and start service
sudo systemctl enable --now redis

# RHEL/CentOS/Rocky/AlmaLinux 8+
# Enable EPEL repository
sudo dnf install -y epel-release

# Install Redis
sudo dnf install -y redis

# Enable and start service
sudo systemctl enable --now redis

# Install latest Redis from Remi repository (recommended)
sudo dnf install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm
sudo dnf module enable redis:remi-7.2
sudo dnf install -y redis
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install Redis
sudo apt install -y redis-server

# The service should start automatically
sudo systemctl status redis-server

# For latest version, use official Redis repository
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt update
sudo apt install -y redis
```

### Arch Linux

```bash
# Install Redis from official repositories
sudo pacman -S redis

# Optional: Install Redis tools
sudo pacman -S redis-tools

# Enable and start service
sudo systemctl enable --now redis

# For development headers
sudo pacman -S hiredis

# For Redis modules from AUR
yay -S redis-mod-redisgraph
yay -S redis-mod-redisearch
```

### Alpine Linux

```bash
# Install Redis
apk add --no-cache redis

# Install additional tools
apk add --no-cache redis-cli redis-benchmark

# Create redis user if not exists
adduser -D -H -s /sbin/nologin -g redis redis

# Create necessary directories
mkdir -p /var/lib/redis /var/log/redis /var/run/redis
chown redis:redis /var/lib/redis /var/log/redis /var/run/redis

# Enable and start service
rc-update add redis default
rc-service redis start
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y redis

# Start and enable service
sudo systemctl enable --now redis@default

# For cluster setup
sudo zypper install -y redis-sentinel

# SLES 15
# May need to enable additional modules
sudo SUSEConnect -p sle-module-server-applications/15.5/x86_64
sudo zypper install -y redis6

# Alternative: use Open Build Service
sudo zypper addrepo https://download.opensuse.org/repositories/server:database/openSUSE_Leap_15.5/server:database.repo
sudo zypper refresh
sudo zypper install -y redis
```

### macOS

```bash
# Using Homebrew
brew install redis

# Start Redis service
brew services start redis

# Or run manually
redis-server /usr/local/etc/redis.conf

# For development
brew install hiredis

# Alternative: Using MacPorts
sudo port install redis
sudo port load redis
```

### FreeBSD

```bash
# Install Redis
pkg install redis

# Or from ports
cd /usr/ports/databases/redis
make install clean

# Enable Redis
echo 'redis_enable="YES"' >> /etc/rc.conf

# Start Redis
service redis start

# For development
pkg install hiredis
```

### Windows

```powershell
# Method 1: Using WSL2 (Recommended)
wsl --install
# Then follow Linux instructions inside WSL2

# Method 2: Using Chocolatey
choco install redis-64

# Method 3: Using Memurai (Redis-compatible for Windows)
# Download from https://www.memurai.com/

# Method 4: Using official Redis on Windows archive
# Download from https://github.com/microsoftarchive/redis/releases
# Extract to C:\Redis
# Run redis-server.exe

# Add to PATH
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Redis", "Machine")

# Create Windows service
redis-server --service-install redis.windows.conf --loglevel verbose
redis-server --service-start
```

## Initial Configuration

### First-Run Setup

1. **Create Redis user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/redis -s /sbin/nologin -c "Redis Database Server" redis
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/redis.conf` or `/etc/redis/redis.conf`
- Debian/Ubuntu: `/etc/redis/redis.conf`
- Arch Linux: `/etc/redis/redis.conf`
- Alpine Linux: `/etc/redis.conf`
- openSUSE/SLES: `/etc/redis/default.conf`
- macOS: `/usr/local/etc/redis.conf`
- FreeBSD: `/usr/local/etc/redis.conf`
- Windows: `C:\Redis\redis.windows.conf`

3. **Essential settings to change**:

```bash
# Edit Redis configuration
sudo vi /etc/redis/redis.conf

# Critical settings to modify:

# Bind to specific interfaces (default is localhost only)
bind 127.0.0.1 ::1
# For network access (be careful!):
# bind 0.0.0.0

# Require password for connections
requirepass YourStrongPasswordHere123!

# Set memory limit
maxmemory 2gb
maxmemory-policy allkeys-lru

# Enable persistence
save 900 1      # Save after 900 sec if at least 1 key changed
save 300 10     # Save after 300 sec if at least 10 keys changed  
save 60 10000   # Save after 60 sec if at least 10000 keys changed

# Set working directory
dir /var/lib/redis

# Set log file
logfile /var/log/redis/redis.log
loglevel notice

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG "CONFIG_y7d9s3k4"
```

### Testing Initial Setup

```bash
# Test Redis is running
redis-cli ping
# Should return: PONG

# Test with authentication
redis-cli -a YourStrongPasswordHere123! ping

# Set and get a test key
redis-cli -a YourStrongPasswordHere123! SET test "Hello Redis"
redis-cli -a YourStrongPasswordHere123! GET test

# Check Redis info
redis-cli -a YourStrongPasswordHere123! INFO server
```

**WARNING:** Never expose Redis to the public internet without proper authentication and SSL/TLS encryption!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable Redis to start on boot
sudo systemctl enable redis
# Or on some systems:
sudo systemctl enable redis-server

# Start Redis
sudo systemctl start redis

# Stop Redis
sudo systemctl stop redis

# Restart Redis
sudo systemctl restart redis

# Reload configuration without restart
sudo systemctl reload redis

# Check status
sudo systemctl status redis

# View logs
sudo journalctl -u redis -f
```

### OpenRC (Alpine Linux)

```bash
# Enable Redis to start on boot
rc-update add redis default

# Start Redis
rc-service redis start

# Stop Redis
rc-service redis stop

# Restart Redis
rc-service redis restart

# Check status
rc-service redis status

# View logs
tail -f /var/log/redis/redis.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'redis_enable="YES"' >> /etc/rc.conf

# Start Redis
service redis start

# Stop Redis
service redis stop

# Restart Redis
service redis restart

# Check status
service redis status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start redis
brew services stop redis
brew services restart redis

# Check status
brew services list | grep redis

# Manual control
redis-server /usr/local/etc/redis.conf
# Stop with Ctrl+C or:
redis-cli shutdown
```

### Windows Service Manager

```powershell
# Start Redis service
redis-server --service-start

# Stop Redis service  
redis-server --service-stop

# Using net commands
net start Redis
net stop Redis

# Using PowerShell
Start-Service -Name Redis
Stop-Service -Name Redis
Restart-Service -Name Redis

# Check status
Get-Service -Name Redis
```

## Advanced Configuration

### Memory Optimization

```bash
# /etc/redis/redis.conf

# Memory management
maxmemory 4gb
maxmemory-policy allkeys-lru
# Policies: volatile-lru, allkeys-lru, volatile-lfu, allkeys-lfu,
#           volatile-random, allkeys-random, volatile-ttl, noeviction

# Memory optimization
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64

# Enable memory defragmentation (Redis 4.0+)
activedefrag yes
active-defrag-ignore-bytes 100mb
active-defrag-threshold-lower 10
active-defrag-threshold-upper 100
```

### Persistence Configuration

```bash
# RDB (Redis Database) snapshots
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis

# AOF (Append Only File) persistence
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec  # Options: always, everysec, no
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble yes
```

### Replication Setup

```bash
# On replica server, add to redis.conf:
replicaof master_ip 6379
masterauth YourStrongPasswordHere123!
replica-read-only yes
replica-serve-stale-data yes

# Replication settings
repl-diskless-sync no
repl-diskless-sync-delay 5
repl-ping-replica-period 10
repl-timeout 60
repl-disable-tcp-nodelay no
repl-backlog-size 1mb
repl-backlog-ttl 3600
```

### Redis Sentinel (High Availability)

```bash
# /etc/redis/sentinel.conf
port 26379
bind 127.0.0.1
protected-mode yes
sentinel monitor mymaster 127.0.0.1 6379 2
sentinel auth-pass mymaster YourStrongPasswordHere123!
sentinel down-after-milliseconds mymaster 5000
sentinel parallel-syncs mymaster 1
sentinel failover-timeout mymaster 10000

# Start sentinel
redis-sentinel /etc/redis/sentinel.conf
```

## Reverse Proxy Setup

While Redis doesn't use HTTP reverse proxies, you can use TCP proxies for load balancing.

### HAProxy Configuration

```nginx
# /etc/haproxy/haproxy.cfg
global
    maxconn 4096
    daemon

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

listen redis
    bind *:6379
    balance roundrobin
    option tcp-check
    tcp-check connect
    tcp-check send AUTH\ YourStrongPasswordHere123!\r\n
    tcp-check expect string +OK
    tcp-check send PING\r\n
    tcp-check expect string +PONG
    tcp-check send QUIT\r\n
    tcp-check expect string +OK
    server redis1 192.168.1.10:6379 check inter 1s
    server redis2 192.168.1.11:6379 check inter 1s
```

### nginx Stream Module

```nginx
# /etc/nginx/nginx.conf
stream {
    upstream redis_backend {
        server 192.168.1.10:6379 max_fails=3 fail_timeout=30s;
        server 192.168.1.11:6379 max_fails=3 fail_timeout=30s;
    }
    
    server {
        listen 6379;
        proxy_pass redis_backend;
        proxy_connect_timeout 1s;
        proxy_timeout 3s;
    }
}
```

## Security Configuration

### Authentication and ACL

```bash
# Basic authentication (redis.conf)
requirepass YourStrongPasswordHere123!

# ACL configuration (Redis 6.0+)
aclfile /etc/redis/users.acl

# Create ACL users
# In redis-cli:
ACL SETUSER alice on >alice_password ~cached:* &* +get +set +del
ACL SETUSER bob on >bob_password ~* &* +@read
ACL SETUSER admin on >admin_password ~* &* +@all

# Disable default user
ACL SETUSER default on nopass ~* &* -@all
```

### SSL/TLS Configuration

```bash
# Build Redis with TLS support
make BUILD_TLS=yes

# Configure TLS in redis.conf
port 0
tls-port 6379
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
tls-dh-params-file /etc/redis/tls/redis.dh

# TLS settings
tls-protocols "TLSv1.2 TLSv1.3"
tls-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
tls-prefer-server-ciphers yes

# Require TLS for replication
tls-replication yes
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 6379
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=redis
sudo firewall-cmd --permanent --zone=redis --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=redis --add-port=6379/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 6379 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 6379 -j DROP
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port 6379
block in on $ext_if proto tcp to any port 6379

# Windows Firewall
New-NetFirewallRule -DisplayName "Redis" -Direction Inbound -Protocol TCP -LocalPort 6379 -RemoteAddress 192.168.1.0/24 -Action Allow
```

### Security Best Practices

```bash
# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command KEYS ""
rename-command CONFIG "CONFIG_y7d9s3k4"
rename-command SHUTDOWN ""

# Enable protected mode
protected-mode yes

# Set client connection limits
tcp-keepalive 300
timeout 300
tcp-backlog 511

# Limit client output buffer
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
```

## Database Setup

Redis doesn't require traditional database setup, but here's how to organize data:

### Keyspace Design

```bash
# Use namespacing for keys
SET user:1000:name "John Doe"
SET user:1000:email "john@example.com"
HSET user:1000 name "John Doe" email "john@example.com"

# Use expiration for cache
SET cache:user:1000 "{...json...}" EX 3600

# Database selection (0-15 by default)
SELECT 0  # Default database
SELECT 1  # Switch to database 1

# Configure number of databases
databases 16
```

### Data Types Examples

```bash
# Strings
SET key "value"
GET key
INCR counter
DECR counter

# Lists
LPUSH queue item1 item2
RPOP queue
LRANGE queue 0 -1

# Sets
SADD tags redis nosql cache
SMEMBERS tags
SINTER tags:post1 tags:post2

# Sorted Sets
ZADD leaderboard 100 player1 200 player2
ZRANGE leaderboard 0 -1 WITHSCORES

# Hashes
HSET user:1000 name "John" age 30
HGETALL user:1000

# Streams (Redis 5.0+)
XADD mystream * sensor-id 1234 temperature 19.8
XREAD COUNT 2 STREAMS mystream 0
```

## Performance Optimization

### System Tuning

```bash
# /etc/sysctl.conf
# Increase system memory
vm.overcommit_memory = 1
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Disable THP (Transparent Huge Pages)
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

# Apply settings
sudo sysctl -p
```

### Redis Performance Tuning

```bash
# redis.conf optimizations

# I/O threads (Redis 6.0+)
io-threads 4
io-threads-do-reads yes

# Disable saving if using Redis as cache only
save ""

# Lazy freeing (Redis 4.0+)
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes

# Background tasks
hz 100  # Increase for more responsive background tasks

# Client optimizations
tcp-keepalive 60
tcp-backlog 511
```

### Benchmarking

```bash
# Basic benchmark
redis-benchmark -h localhost -p 6379 -a YourStrongPasswordHere123! -n 100000 -c 50

# Test specific commands
redis-benchmark -h localhost -p 6379 -a YourStrongPasswordHere123! -t set,get -n 100000

# Pipeline mode
redis-benchmark -h localhost -p 6379 -a YourStrongPasswordHere123! -P 16 -n 100000

# Custom payload size
redis-benchmark -h localhost -p 6379 -a YourStrongPasswordHere123! -d 1024 -n 100000
```

## Monitoring

### Built-in Monitoring

```bash
# Real-time stats
redis-cli -a YourStrongPasswordHere123! --stat

# Monitor commands in real-time
redis-cli -a YourStrongPasswordHere123! MONITOR

# Get server info
redis-cli -a YourStrongPasswordHere123! INFO
redis-cli -a YourStrongPasswordHere123! INFO stats
redis-cli -a YourStrongPasswordHere123! INFO memory
redis-cli -a YourStrongPasswordHere123! INFO replication

# Memory usage analysis
redis-cli -a YourStrongPasswordHere123! --bigkeys
redis-cli -a YourStrongPasswordHere123! --memkeys
redis-cli -a YourStrongPasswordHere123! MEMORY STATS
redis-cli -a YourStrongPasswordHere123! MEMORY DOCTOR
```

### Slow Log Analysis

```bash
# Configure slow log
CONFIG SET slowlog-log-slower-than 10000  # Log queries slower than 10ms
CONFIG SET slowlog-max-len 128

# View slow log
SLOWLOG GET 10
SLOWLOG LEN
SLOWLOG RESET
```

### External Monitoring Tools

```bash
# Redis Exporter for Prometheus
wget https://github.com/oliver006/redis_exporter/releases/download/v1.45.0/redis_exporter-v1.45.0.linux-amd64.tar.gz
tar xzf redis_exporter-*.tar.gz
sudo cp redis_exporter /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/redis_exporter.service <<EOF
[Unit]
Description=Redis Exporter
After=network.target

[Service]
Type=simple
User=redis
ExecStart=/usr/local/bin/redis_exporter \
    --redis.addr=localhost:6379 \
    --redis.password=YourStrongPasswordHere123!
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now redis_exporter
```

## 9. Backup and Restore

### RDB Snapshot Backup

```bash
# Manual backup
redis-cli -a YourStrongPasswordHere123! BGSAVE

# Wait for backup to complete
redis-cli -a YourStrongPasswordHere123! LASTSAVE

# Copy backup file
sudo cp /var/lib/redis/dump.rdb /backup/redis/dump_$(date +%Y%m%d_%H%M%S).rdb

# Automated backup script
cat > /usr/local/bin/redis-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/redis"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REDIS_CLI="redis-cli -a YourStrongPasswordHere123!"

# Create backup directory
mkdir -p ${BACKUP_DIR}

# Trigger backup
${REDIS_CLI} BGSAVE

# Wait for backup to complete
while [ $(${REDIS_CLI} LASTSAVE) -eq $(${REDIS_CLI} LASTSAVE) ]; do
    sleep 1
done

# Copy backup file
cp /var/lib/redis/dump.rdb ${BACKUP_DIR}/dump_${TIMESTAMP}.rdb

# Keep only last 7 days
find ${BACKUP_DIR} -name "dump_*.rdb" -mtime +7 -delete

echo "Backup completed: dump_${TIMESTAMP}.rdb"
EOF

chmod +x /usr/local/bin/redis-backup.sh
```

### AOF Backup

```bash
# If using AOF
redis-cli -a YourStrongPasswordHere123! BGREWRITEAOF

# Backup AOF file
cp /var/lib/redis/appendonly.aof /backup/redis/appendonly_$(date +%Y%m%d_%H%M%S).aof
```

### Restore Procedures

```bash
# Stop Redis
sudo systemctl stop redis

# Replace dump file
sudo cp /backup/redis/dump_20240115_120000.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb

# Start Redis
sudo systemctl start redis

# Verify data
redis-cli -a YourStrongPasswordHere123! DBSIZE
```

### Backup to Cloud Storage

```bash
#!/bin/bash
# Backup to S3
aws s3 cp /var/lib/redis/dump.rdb s3://my-bucket/redis-backups/dump_$(date +%Y%m%d_%H%M%S).rdb

# Backup to Azure
az storage blob upload --account-name myaccount --container-name redis-backups --name dump_$(date +%Y%m%d_%H%M%S).rdb --file /var/lib/redis/dump.rdb

# Backup to GCS
gsutil cp /var/lib/redis/dump.rdb gs://my-bucket/redis-backups/dump_$(date +%Y%m%d_%H%M%S).rdb
```

## 6. Troubleshooting

### Common Issues

1. **Connection refused**:
```bash
# Check if Redis is running
sudo systemctl status redis
ps aux | grep redis

# Check if Redis is listening
sudo netstat -tlnp | grep 6379
sudo ss -tlnp | grep 6379

# Check logs
sudo tail -f /var/log/redis/redis.log
sudo journalctl -u redis -f
```

2. **Authentication errors**:
```bash
# Test authentication
redis-cli -a YourWrongPassword ping
# (error) WRONGPASS invalid username-password pair

# Connect with correct password
redis-cli -a YourStrongPasswordHere123! ping
# PONG
```

3. **Memory issues**:
```bash
# Check memory usage
redis-cli -a YourStrongPasswordHere123! INFO memory

# Check evicted keys
redis-cli -a YourStrongPasswordHere123! INFO stats | grep evicted

# Set memory limit
redis-cli -a YourStrongPasswordHere123! CONFIG SET maxmemory 2gb

# Check what's using memory
redis-cli -a YourStrongPasswordHere123! --bigkeys
```

4. **Performance issues**:
```bash
# Check slow queries
redis-cli -a YourStrongPasswordHere123! SLOWLOG GET 10

# Check connected clients
redis-cli -a YourStrongPasswordHere123! CLIENT LIST

# Check persistence status
redis-cli -a YourStrongPasswordHere123! INFO persistence

# Disable persistence temporarily
redis-cli -a YourStrongPasswordHere123! CONFIG SET save ""
redis-cli -a YourStrongPasswordHere123! CONFIG SET appendonly no
```

### Recovery Procedures

```bash
# Fix corrupted AOF
redis-check-aof --fix /var/lib/redis/appendonly.aof

# Fix corrupted RDB
redis-check-rdb /var/lib/redis/dump.rdb

# Emergency flush (use with caution!)
redis-cli -a YourStrongPasswordHere123! FLUSHDB
redis-cli -a YourStrongPasswordHere123! FLUSHALL
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update redis
sudo dnf update redis

# Debian/Ubuntu
sudo apt update
sudo apt upgrade redis-server

# Arch Linux
sudo pacman -Syu redis

# Alpine Linux
apk update
apk upgrade redis

# openSUSE
sudo zypper update redis

# FreeBSD
pkg update
pkg upgrade redis

# Always backup before updates
redis-cli -a YourStrongPasswordHere123! BGSAVE
```

### Log Rotation

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/redis <<EOF
/var/log/redis/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 redis redis
    postrotate
        systemctl reload redis > /dev/null 2>&1 || true
    endscript
}
EOF
```

### Health Checks

```bash
#!/bin/bash
# /usr/local/bin/redis-health-check.sh

REDIS_CLI="redis-cli -a YourStrongPasswordHere123!"

# Check if Redis is responding
if ! ${REDIS_CLI} ping > /dev/null 2>&1; then
    echo "Redis is not responding"
    exit 1
fi

# Check memory usage
USED_MEMORY=$(${REDIS_CLI} INFO memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
echo "Memory usage: ${USED_MEMORY}"

# Check replication
ROLE=$(${REDIS_CLI} INFO replication | grep role | cut -d: -f2 | tr -d '\r')
echo "Redis role: ${ROLE}"

# Check persistence
RDB_LAST_SAVE=$(${REDIS_CLI} LASTSAVE)
echo "Last save: $(date -d @${RDB_LAST_SAVE})"

echo "Redis health check passed"
```

## Integration Examples

### Python (redis-py)

```python
import redis
from redis.sentinel import Sentinel

# Basic connection
r = redis.Redis(
    host='localhost',
    port=6379,
    password='YourStrongPasswordHere123!',
    decode_responses=True
)

# Connection pool
pool = redis.ConnectionPool(
    host='localhost',
    port=6379,
    password='YourStrongPasswordHere123!',
    max_connections=50
)
r = redis.Redis(connection_pool=pool)

# Basic operations
r.set('key', 'value')
value = r.get('key')

# Pipeline for performance
pipe = r.pipeline()
for i in range(10000):
    pipe.set(f'key:{i}', i)
pipe.execute()

# Pub/Sub
pubsub = r.pubsub()
pubsub.subscribe('channel')
for message in pubsub.listen():
    print(message)

# Sentinel connection
sentinel = Sentinel([('localhost', 26379)])
master = sentinel.master_for('mymaster', socket_timeout=0.1)
```

### Node.js (ioredis)

```javascript
const Redis = require('ioredis');

// Basic connection
const redis = new Redis({
  host: 'localhost',
  port: 6379,
  password: 'YourStrongPasswordHere123!',
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  }
});

// Cluster connection
const cluster = new Redis.Cluster([
  { port: 6379, host: '192.168.1.10' },
  { port: 6379, host: '192.168.1.11' }
]);

// Basic operations
async function example() {
  await redis.set('key', 'value');
  const value = await redis.get('key');
  
  // Pipeline
  const pipeline = redis.pipeline();
  pipeline.set('key1', 'value1');
  pipeline.set('key2', 'value2');
  pipeline.get('key1');
  const results = await pipeline.exec();
  
  // Pub/Sub
  const sub = new Redis();
  sub.subscribe('news', 'music');
  sub.on('message', (channel, message) => {
    console.log(`Received ${message} from ${channel}`);
  });
}

// Stream processing
async function streamExample() {
  // Add to stream
  await redis.xadd('mystream', '*', 'field1', 'value1');
  
  // Read from stream
  const messages = await redis.xread('STREAMS', 'mystream', '0');
}
```

### PHP (Predis/PhpRedis)

```php
<?php
// Using Predis
require 'vendor/autoload.php';

$client = new Predis\Client([
    'scheme' => 'tcp',
    'host'   => '127.0.0.1',
    'port'   => 6379,
    'password' => 'YourStrongPasswordHere123!'
]);

// Basic operations
$client->set('key', 'value');
$value = $client->get('key');

// Pipeline
$pipe = $client->pipeline();
for ($i = 0; $i < 1000; $i++) {
    $pipe->set("key:$i", $i);
}
$pipe->execute();

// Using PhpRedis extension
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('YourStrongPasswordHere123!');

// Transactions
$redis->multi();
$redis->set('key1', 'value1');
$redis->set('key2', 'value2');
$redis->exec();

// Pub/Sub
$redis->subscribe(['channel1', 'channel2'], function ($redis, $channel, $message) {
    echo "Received: $message on $channel\n";
});
?>
```

### Java (Jedis/Lettuce)

```java
// Using Jedis
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

public class RedisExample {
    private static JedisPool pool;
    
    static {
        JedisPoolConfig config = new JedisPoolConfig();
        config.setMaxTotal(128);
        config.setMaxIdle(128);
        config.setMinIdle(16);
        config.setTestOnBorrow(true);
        config.setTestOnReturn(true);
        
        pool = new JedisPool(config, "localhost", 6379, 2000, "YourStrongPasswordHere123!");
    }
    
    public static void example() {
        try (Jedis jedis = pool.getResource()) {
            // Basic operations
            jedis.set("key", "value");
            String value = jedis.get("key");
            
            // Pipeline
            Pipeline pipeline = jedis.pipelined();
            for (int i = 0; i < 10000; i++) {
                pipeline.set("key:" + i, String.valueOf(i));
            }
            pipeline.sync();
            
            // Transactions
            Transaction tx = jedis.multi();
            tx.set("key1", "value1");
            tx.set("key2", "value2");
            tx.exec();
        }
    }
}

// Using Lettuce
import io.lettuce.core.*;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;

RedisClient client = RedisClient.create("redis://password@localhost:6379");
StatefulRedisConnection<String, String> connection = client.connect();
RedisCommands<String, String> sync = connection.sync();

sync.set("key", "value");
String value = sync.get("key");
```

### Go (go-redis)

```go
package main

import (
    "context"
    "fmt"
    "github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
    // Create client
    rdb := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "YourStrongPasswordHere123!",
        DB:       0,
        PoolSize: 10,
    })

    // Basic operations
    err := rdb.Set(ctx, "key", "value", 0).Err()
    if err != nil {
        panic(err)
    }

    val, err := rdb.Get(ctx, "key").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("key", val)

    // Pipeline
    pipe := rdb.Pipeline()
    for i := 0; i < 1000; i++ {
        pipe.Set(ctx, fmt.Sprintf("key:%d", i), i, 0)
    }
    _, err = pipe.Exec(ctx)

    // Pub/Sub
    pubsub := rdb.Subscribe(ctx, "channel")
    ch := pubsub.Channel()
    for msg := range ch {
        fmt.Println(msg.Channel, msg.Payload)
    }
}
```

## Additional Resources

- [Official Documentation](https://redis.io/documentation)
- [GitHub Repository](https://github.com/redis/redis)
- [Redis Commands Reference](https://redis.io/commands)
- [Redis University](https://university.redis.com/)
- [Redis Best Practices](https://redis.io/docs/manual/patterns/)
- [Redis Security](https://redis.io/docs/manual/security/)
- [Redis Cluster Tutorial](https://redis.io/docs/manual/scaling/)
- [Community Forum](https://forum.redis.com/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.