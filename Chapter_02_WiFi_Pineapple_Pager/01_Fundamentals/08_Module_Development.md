# Module Development

## Overview

Create custom modules to extend WiFi Pineapple functionality with your own attacks, tools, and utilities.

---

## Module Structure

```
/pineapple/modules/MyModule/
├── module.php          # Backend logic (required)
├── module.html         # Frontend UI (required)
├── module.js           # Frontend logic
├── module.css          # Styling
├── module.info         # Metadata (required)
├── scripts/            # Shell scripts
│   ├── start.sh
│   └── stop.sh
├── includes/           # PHP includes
└── assets/             # Static files
```

---

## Module Files

### module.info (Required)

```json
{
    "name": "MyModule",
    "title": "My Custom Module",
    "description": "What this module does",
    "version": "1.0.0",
    "author": "Your Name"
}
```

### module.php (Required)

```php
<?php
namespace pineapple;

class MyModule extends SystemModule {

    public function route() {
        switch ($this->request->action) {
            case 'status':
                $this->getStatus();
                break;
            case 'start':
                $this->startModule();
                break;
            case 'stop':
                $this->stopModule();
                break;
            case 'getData':
                $this->getData();
                break;
        }
    }

    private function getStatus() {
        $running = $this->checkRunning();
        $this->response = array(
            "success" => true,
            "running" => $running
        );
    }

    private function startModule() {
        exec("/pineapple/modules/MyModule/scripts/start.sh &");
        $this->response = array("success" => true);
    }

    private function stopModule() {
        exec("killall mymodule_process 2>/dev/null");
        $this->response = array("success" => true);
    }

    private function checkRunning() {
        return exec("pgrep -f mymodule_process") !== "";
    }

    private function getData() {
        $data = file_get_contents("/tmp/mymodule_data.txt");
        $this->response = array(
            "success" => true,
            "data" => $data
        );
    }
}
```

### module.html (Required)

```html
<div class="panel panel-default">
    <div class="panel-heading">
        <h4>My Custom Module</h4>
    </div>
    <div class="panel-body">
        <div class="row">
            <div class="col-md-12">
                <div class="btn-group">
                    <button type="button" class="btn btn-success" ng-click="start()">
                        Start
                    </button>
                    <button type="button" class="btn btn-danger" ng-click="stop()">
                        Stop
                    </button>
                    <button type="button" class="btn btn-info" ng-click="refresh()">
                        Refresh
                    </button>
                </div>
            </div>
        </div>

        <hr>

        <div class="row">
            <div class="col-md-12">
                <div class="alert alert-info" ng-show="running">
                    Module is running
                </div>
                <div class="alert alert-warning" ng-hide="running">
                    Module is stopped
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <h5>Output:</h5>
                <pre>{{data}}</pre>
            </div>
        </div>
    </div>
</div>
```

### module.js

```javascript
registerController('MyModule', ['$api', '$scope', '$interval',
    function($api, $scope, $interval) {

    $scope.running = false;
    $scope.data = "";

    $scope.start = function() {
        $api.request({
            module: 'MyModule',
            action: 'start'
        }, function(response) {
            if (response.success) {
                $scope.running = true;
            }
        });
    };

    $scope.stop = function() {
        $api.request({
            module: 'MyModule',
            action: 'stop'
        }, function(response) {
            if (response.success) {
                $scope.running = false;
            }
        });
    };

    $scope.refresh = function() {
        $api.request({
            module: 'MyModule',
            action: 'status'
        }, function(response) {
            $scope.running = response.running;
        });

        $api.request({
            module: 'MyModule',
            action: 'getData'
        }, function(response) {
            if (response.success) {
                $scope.data = response.data;
            }
        });
    };

    // Auto-refresh every 5 seconds
    var refreshInterval = $interval($scope.refresh, 5000);

    // Initial load
    $scope.refresh();

    // Cleanup on destroy
    $scope.$on('$destroy', function() {
        $interval.cancel(refreshInterval);
    });
}]);
```

---

## Shell Scripts

### scripts/start.sh

```bash
#!/bin/bash
# Start module functionality

LOG_FILE="/tmp/mymodule.log"
DATA_FILE="/tmp/mymodule_data.txt"

echo "Starting MyModule at $(date)" >> "$LOG_FILE"

# Your main logic here
while true; do
    # Example: collect data
    echo "Timestamp: $(date)" >> "$DATA_FILE"
    echo "Data: $(some_command)" >> "$DATA_FILE"

    sleep 10
done
```

### scripts/stop.sh

```bash
#!/bin/bash
# Stop module functionality

pkill -f "mymodule" 2>/dev/null
echo "MyModule stopped at $(date)" >> /tmp/mymodule.log
```

---

## Complete Example: Client Logger

### module.info

```json
{
    "name": "ClientLogger",
    "title": "Client Logger",
    "description": "Log all connected clients with details",
    "version": "1.0.0",
    "author": "Security Trainer"
}
```

### module.php

```php
<?php
namespace pineapple;

class ClientLogger extends SystemModule {

    const LOG_FILE = "/sd/loot/clients/log.txt";

    public function route() {
        switch ($this->request->action) {
            case 'status':
                $this->getStatus();
                break;
            case 'start':
                $this->startLogging();
                break;
            case 'stop':
                $this->stopLogging();
                break;
            case 'getLogs':
                $this->getLogs();
                break;
            case 'clearLogs':
                $this->clearLogs();
                break;
        }
    }

    private function getStatus() {
        $running = $this->isRunning();
        $count = $this->getClientCount();
        $this->response = array(
            "success" => true,
            "running" => $running,
            "clientCount" => $count
        );
    }

    private function startLogging() {
        if (!is_dir("/sd/loot/clients")) {
            mkdir("/sd/loot/clients", 0755, true);
        }

        exec("nohup /pineapple/modules/ClientLogger/scripts/monitor.sh > /dev/null 2>&1 &");
        $this->response = array("success" => true);
    }

    private function stopLogging() {
        exec("pkill -f ClientLogger/scripts/monitor.sh");
        $this->response = array("success" => true);
    }

    private function isRunning() {
        $result = exec("pgrep -f 'ClientLogger/scripts/monitor.sh'");
        return !empty($result);
    }

    private function getClientCount() {
        if (file_exists(self::LOG_FILE)) {
            $lines = file(self::LOG_FILE);
            return count($lines);
        }
        return 0;
    }

    private function getLogs() {
        $logs = "";
        if (file_exists(self::LOG_FILE)) {
            $logs = file_get_contents(self::LOG_FILE);
        }
        $this->response = array(
            "success" => true,
            "logs" => $logs
        );
    }

    private function clearLogs() {
        if (file_exists(self::LOG_FILE)) {
            unlink(self::LOG_FILE);
        }
        $this->response = array("success" => true);
    }
}
```

### scripts/monitor.sh

```bash
#!/bin/bash
# Client monitoring script

LOG_FILE="/sd/loot/clients/log.txt"
KNOWN_FILE="/tmp/clientlogger_known.txt"

mkdir -p "$(dirname $LOG_FILE)"
touch "$KNOWN_FILE"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "ClientLogger started"

while true; do
    # Check DHCP leases
    if [ -f /tmp/dnsmasq.leases ]; then
        while read timestamp mac ip hostname clientid; do
            # Skip if already known
            if ! grep -q "$mac" "$KNOWN_FILE"; then
                echo "$mac" >> "$KNOWN_FILE"

                # Get vendor from OUI (first 3 octets)
                oui=$(echo "$mac" | cut -d: -f1-3 | tr ':' '-' | tr 'a-f' 'A-F')

                log "NEW CLIENT: MAC=$mac IP=$ip Hostname=$hostname OUI=$oui"
            fi
        done < /tmp/dnsmasq.leases
    fi

    sleep 5
done
```

---

## Installation

### Manual Installation

```bash
# Create directory
mkdir -p /pineapple/modules/MyModule

# Copy files
cp -r MyModule/* /pineapple/modules/MyModule/

# Set permissions
chmod +x /pineapple/modules/MyModule/scripts/*.sh

# Restart web server
/etc/init.d/nginx restart
```

### Package Creation

```bash
# Create tar package
tar -czvf MyModule.tar.gz MyModule/

# Install via web interface
# Upload to Modules > Install from file
```

---

## Debugging

### PHP Errors

```bash
# Check nginx error log
tail -f /var/log/nginx/error.log

# Enable PHP error display
# Edit /etc/php.ini
display_errors = On
error_reporting = E_ALL
```

### Shell Script Debugging

```bash
# Add to script
set -x  # Print commands
exec > /tmp/debug.log 2>&1  # Log all output
```

---

## Best Practices

1. **Error Handling**: Always check command success
2. **Logging**: Log important events
3. **Cleanup**: Clean up resources on stop
4. **Permissions**: Set appropriate file permissions
5. **Security**: Validate all inputs
6. **Documentation**: Document your module

---

[← API Reference](07_API_Reference.md) | [Back to Fundamentals](README.md)
