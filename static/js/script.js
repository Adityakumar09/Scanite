// script.js
document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domain');
    const scanBtn = document.getElementById('scanBtn');
    const stopBtn = document.getElementById('stopBtn');
    const resultContent = document.getElementById('resultContent');
    const downloadBtn = document.getElementById('downloadBtn');
    const statusLights = document.querySelectorAll('.light');
    
    let currentScanId = null;
    let checkInterval = null;
    let isAutoScroll = true;
    let userScrolledUp = false;

    // Event listeners
    scanBtn.addEventListener('click', startScan);
    stopBtn.addEventListener('click', stopScan);
    domainInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') startScan();
    });
    downloadBtn.addEventListener('click', downloadReport);
    
    // Track user scroll behavior
    resultContent.addEventListener('scroll', function() {
        const threshold = 50; // pixels from bottom
        userScrolledUp = this.scrollTop + this.clientHeight < this.scrollHeight - threshold;
    });

    function startScan() {
        const domain = domainInput.value.trim();
        if (!domain) {
            addTerminalLine('ERROR: Please enter a valid domain', 'error');
            return;
        }

        // Reset UI
        resultContent.innerHTML = '<div class="terminal-line">INITIALIZING SCAN...</div>';
        updateStatusLights('scanning');
        isAutoScroll = true;
        userScrolledUp = false;
        
        // Enable/disable buttons
        setControlsDisabled(true);
        
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `domain=${encodeURIComponent(domain)}`
        })
        .then(handleResponse)
        .then(data => {
            currentScanId = data.scan_id;
            checkScanProgress();
        })
        .catch(handleScanError);
    }

    function stopScan() {
        if (!currentScanId) return;
        
        fetch(`/scan/${currentScanId}/stop`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            addTerminalLine('Scan stop requested...', 'info');
            stopBtn.disabled = true;
        })
        .catch(error => {
            addTerminalLine(`Failed to stop scan: ${error.message}`, 'error');
        });
    }

    function handleResponse(response) {
        if (!response.ok) {
            return response.json().then(err => Promise.reject(err));
        }
        return response.json();
    }

    function handleScanError(error) {
        addTerminalLine(`SCAN FAILED: ${error.message || 'Unknown error'}`, 'error');
        updateStatusLights('error');
        setControlsDisabled(false);
    }

    function setControlsDisabled(disabled) {
        domainInput.disabled = disabled;
        scanBtn.disabled = disabled;
        stopBtn.disabled = !disabled;
    }

    function checkScanProgress() {
        if (!currentScanId) return;
        
        clearInterval(checkInterval);
        
        checkInterval = setInterval(() => {
            fetch(`/scan/${currentScanId}`)
                .then(handleResponse)
                .then(updateScanStatus)
                .catch(handleStatusError);
        }, 1000);
    }

    function updateScanStatus(data) {
        // Update results
        if (data.results?.length > 0) {
            resultContent.innerHTML = data.results.map(line => 
                `<div class="terminal-line ${getLineClass(line)}">${escapeHtml(line)}</div>`
            ).join('');
            
            // Auto-scroll only if user hasn't scrolled up
            if (!userScrolledUp) {
                resultContent.scrollTop = resultContent.scrollHeight;
            }
        }
        
        // Update status
        if (data.status === 'completed') {
            clearInterval(checkInterval);
            addTerminalLine('SCAN COMPLETED SUCCESSFULLY', 'success');
            updateStatusLights('completed');
            setControlsDisabled(false);
        } else if (data.status === 'error') {
            clearInterval(checkInterval);
            addTerminalLine('SCAN TERMINATED WITH ERRORS', 'error');
            updateStatusLights('error');
            setControlsDisabled(false);
        } else if (data.status === 'stopped') {
            clearInterval(checkInterval);
            addTerminalLine('SCAN STOPPED BY USER', 'error');
            updateStatusLights('error');
            setControlsDisabled(false);
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function getLineClass(line) {
        if (line.includes('!')) return 'error';
        if (line.includes('-')) return 'success';
        if (line.includes('[+]')) return 'info';
        return '';
    }

    function handleStatusError(error) {
        clearInterval(checkInterval);
        addTerminalLine(`ERROR CHECKING SCAN STATUS: ${error.message || 'Unknown error'}`, 'error');
        updateStatusLights('error');
        setControlsDisabled(false);
    }

    function addTerminalLine(text, type = '') {
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        resultContent.appendChild(line);
        
        if (!userScrolledUp) {
            resultContent.scrollTop = resultContent.scrollHeight;
        }
    }

    function updateStatusLights(status) {
        statusLights.forEach(light => light.style.opacity = '0.2');
        
        if (status === 'scanning') {
            statusLights[1].style.opacity = '1';
        } else if (status === 'completed') {
            statusLights[2].style.opacity = '1';
        } else if (status === 'error' || status === 'stopped') {
            statusLights[0].style.opacity = '1';
        }
    }

    function downloadReport() {
        try {
            const content = Array.from(resultContent.querySelectorAll('.terminal-line'))
                                .map(line => line.textContent)
                                .join('\n');
            if (!content.trim()) {
                addTerminalLine('No scan results to download', 'error');
                return;
            }
            
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_report_${new Date().toISOString().slice(0, 10)}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            addTerminalLine(`DOWNLOAD FAILED: ${error.message}`, 'error');
        }
    }
});