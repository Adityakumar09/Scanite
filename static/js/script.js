document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domain');
    const scanBtn = document.getElementById('scanBtn');
    const resultContent = document.getElementById('resultContent');
    const downloadBtn = document.getElementById('downloadBtn');
    const statusLights = document.querySelectorAll('.light');
    
    let currentScanId = null;
    let checkInterval = null;

    scanBtn.addEventListener('click', startScan);
    domainInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') startScan();
    });
    downloadBtn.addEventListener('click', downloadReport);

    function startScan() {
        const domain = domainInput.value.trim();
        if (!domain) {
            addTerminalLine('ERROR: Please enter a domain', 'error');
            return;
        }

        // Reset UI
        resultContent.innerHTML = '<div class="terminal-line">INITIALIZING SCAN...</div>';
        updateStatusLights('scanning');
        
        // Disable inputs during scan
        domainInput.disabled = true;
        scanBtn.disabled = true;
        
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `domain=${encodeURIComponent(domain)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            currentScanId = data.scan_id;
            checkScanProgress();
        })
        .catch(error => {
            addTerminalLine(`SCAN FAILED: ${error.message}`, 'error');
            updateStatusLights('error');
            domainInput.disabled = false;
            scanBtn.disabled = false;
        });
    }

    function checkScanProgress() {
        if (!currentScanId) return;
        
        clearInterval(checkInterval);
        
        checkInterval = setInterval(() => {
            fetch(`/scan/${currentScanId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    
                    // Update results
                    if (data.results && data.results.length > 0) {
                        resultContent.innerHTML = data.results.map(line => {
                            const lineClass = line.includes('!') ? 'error' : 
                                            line.includes('-') ? 'success' : 
                                            line.includes('[+]') ? 'info' : '';
                            return `<div class="terminal-line ${lineClass}">${line}</div>`;
                        }).join('');
                        resultContent.scrollTop = resultContent.scrollHeight;
                    }
                    
                    // Update status
                    if (data.status === 'completed') {
                        clearInterval(checkInterval);
                        addTerminalLine('SCAN COMPLETED SUCCESSFULLY', 'success');
                        updateStatusLights('completed');
                        domainInput.disabled = false;
                        scanBtn.disabled = false;
                    } else if (data.status === 'error') {
                        clearInterval(checkInterval);
                        addTerminalLine('SCAN TERMINATED WITH ERRORS', 'error');
                        updateStatusLights('error');
                        domainInput.disabled = false;
                        scanBtn.disabled = false;
                    }
                })
                .catch(error => {
                    clearInterval(checkInterval);
                    addTerminalLine(`ERROR CHECKING SCAN STATUS: ${error.message}`, 'error');
                    updateStatusLights('error');
                    domainInput.disabled = false;
                    scanBtn.disabled = false;
                });
        }, 1000);
    }

    function addTerminalLine(text, type = '') {
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        resultContent.appendChild(line);
        resultContent.scrollTop = resultContent.scrollHeight;
    }

    function updateStatusLights(status) {
        statusLights.forEach(light => light.style.opacity = '0.2');
        
        if (status === 'scanning') {
            statusLights[1].style.opacity = '1';
        } else if (status === 'completed') {
            statusLights[2].style.opacity = '1';
        } else if (status === 'error') {
            statusLights[0].style.opacity = '1';
        }
    }

    function downloadReport() {
        const content = Array.from(resultContent.querySelectorAll('.terminal-line'))
                            .map(line => line.textContent)
                            .join('\n');
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_report_${new Date().toISOString()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
});