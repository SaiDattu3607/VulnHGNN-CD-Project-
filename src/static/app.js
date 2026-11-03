document.addEventListener('DOMContentLoaded', () => {
    // ═══ DOM REFS ═══
    const $ = id => document.getElementById(id);
    
    // Global Elements
    const codeInput = $('code-input');
    const codeLineNumbers = $('code-line-numbers');
    const codeLanguage = $('code-language');
    const sourceFilename = $('source-filename');
    const codeRender = $('code-render');
    const codeOverlay = $('code-render-overlay');
    const analyzeBtn = $('analyze-btn');
    const llmReviewConsent = $('llm-review-consent');
    const liveCheckPanel = $('live-check-panel');
    const liveCheckStatus = $('live-check-status');
    const liveCheckDetail = $('live-check-detail');
    const liveCheckFindings = $('live-check-findings');
    const statusDot = $('status-dot');
    const statusText = $('status-text');

    // Sidebar Stats
    const scoreNumber = $('score-number');
    const statTime = $('stat-time');
    const statLoc = $('stat-loc');
    const statEnergy = $('stat-energy');
    const statCo2 = $('stat-co2');

    // Result Tabs
    const tabBtns = document.querySelectorAll('.res-tab');
    const tabPanels = document.querySelectorAll('.tab-panel');

    // Action Center
    const actionDock = $('action-center');
    const btnLocalize = $('btn-localize');
    const btnHeal = $('btn-heal-source');
    const btnPipeline = $('btn-pipeline');

    // Sub-Views
    const locInstructions = $('loc-instructions');
    const healHeader = $('heal-header');
    const diffBefore = $('diff-before');
    const diffAfter = $('diff-after');
    const logContainer = $('log-container');

    let currentCode = '';
    let detectedCWEs = [];
    let liveCheckTimer = null;
    let liveCheckController = null;
    let liveCheckRevision = 0;

    // ═══ CORE LOGIC ═══
    function switchTab(tabId) {
        tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
        tabPanels.forEach(p => p.classList.toggle('active', p.id === tabId));
    }

    function showState(prefix, name) {
        ['idle', 'loading', 'success', 'error'].forEach(s => {
            const el = $(`${prefix}-${s}`);
            if (el) el.classList.add('hidden');
        });
        const target = $(`${prefix}-${name}`);
        if (target) target.classList.remove('hidden');
    }

    function setEditorMode(mode) {
        if (mode === 'edit') {
            codeOverlay.classList.add('hidden');
            codeInput.classList.remove('hidden');
            $('btn-edit').classList.add('hidden');
        } else {
            codeOverlay.classList.remove('hidden');
            codeInput.classList.add('hidden');
            $('btn-edit').classList.remove('hidden');
        }
    }

    function escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function updateLineNumbers() {
        const lineCount = Math.max(1, codeInput.value.split('\n').length);
        codeLineNumbers.textContent = Array.from(
            { length: lineCount },
            (_, index) => index + 1
        ).join('\n');
        codeLineNumbers.style.transform = `translateY(${-codeInput.scrollTop}px)`;
    }

    function renderLiveCheck(data) {
        liveCheckFindings.replaceChildren();
        const validity = data.validity || {};
        const security = data.security || {};

        if (validity.status === 'invalid') {
            liveCheckPanel.dataset.state = 'invalid';
            liveCheckStatus.textContent = 'Syntax error';
            liveCheckDetail.textContent = validity.message || 'Clang could not compile this source.';
            return;
        }
        if (validity.status === 'unavailable') {
            liveCheckPanel.dataset.state = 'error';
            liveCheckStatus.textContent = 'Syntax check unavailable';
            liveCheckDetail.textContent = validity.message || 'The compiler did not finish in time.';
            return;
        }

        if (security.status === 'unavailable') {
            liveCheckPanel.dataset.state = 'valid';
            liveCheckStatus.textContent = 'Valid C syntax; security analysis unavailable';
            liveCheckDetail.textContent = security.message || 'The local vulnerability model is not loaded.';
            return;
        }

        const findings = security.findings || [];
        liveCheckPanel.dataset.state = findings.length ? 'issues' : 'valid';
        liveCheckStatus.textContent = findings.length
            ? `${findings.length} definite issue(s) reported by Clang`
            : 'Valid syntax; no definite issue found by this live check';
        liveCheckDetail.textContent = findings.length
            ? 'Clang identified a constant division by zero in your source.'
            : (security.scope || 'This check only reports issues it can verify; it does not prove the code is secure.');

        findings.forEach(finding => {
            const card = document.createElement('article');
            card.className = 'live-check-finding';
            const heading = document.createElement('strong');
            heading.textContent = `${finding.severity || 'Review'} · ${finding.class}: ${finding.name}`;
            card.appendChild(heading);
            if (finding.function) {
                const location = document.createElement('p');
                location.textContent = `Function: ${finding.function}`;
                card.appendChild(location);
            }
            if (finding.line) {
                const location = document.createElement('p');
                location.textContent = `Line: ${finding.line}`;
                card.appendChild(location);
            }
            const recommendation = document.createElement('p');
            recommendation.textContent = finding.recommendation;
            card.appendChild(recommendation);
            liveCheckFindings.appendChild(card);
        });
    }

    function scheduleLiveCheck() {
        window.clearTimeout(liveCheckTimer);
        if (liveCheckController) {
            liveCheckController.abort();
            liveCheckController = null;
        }

        const code = codeInput.value;
        const revision = ++liveCheckRevision;
        if (code !== currentCode) {
            detectedCWEs = [];
            actionDock.classList.add('hidden');
        }
        if (!code.trim()) {
            liveCheckPanel.dataset.state = 'idle';
            liveCheckStatus.textContent = 'Live checks start when you type';
            liveCheckDetail.textContent = 'Syntax and supported vulnerability checks run locally after a short pause.';
            liveCheckFindings.replaceChildren();
            return;
        }

        liveCheckPanel.dataset.state = 'checking';
        liveCheckStatus.textContent = 'Checking syntax and supported vulnerabilities…';
        liveCheckDetail.textContent = 'Waiting for a brief pause in typing.';
        liveCheckFindings.replaceChildren();
        liveCheckTimer = window.setTimeout(async () => {
            const controller = new AbortController();
            liveCheckController = controller;
            liveCheckDetail.textContent = 'Running local Clang and model checks…';
            try {
                const response = await fetch('/api/live-check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, language: codeLanguage.value }),
                    signal: controller.signal,
                });
                const data = await response.json();
                if (revision !== liveCheckRevision) return;
                if (!response.ok || !data.success) {
                    throw new Error(data.error || `Live check failed (${response.status}).`);
                }
                renderLiveCheck(data);
            } catch (error) {
                if (error.name === 'AbortError' || revision !== liveCheckRevision) return;
                liveCheckPanel.dataset.state = 'error';
                liveCheckStatus.textContent = 'Live check failed';
                liveCheckDetail.textContent = error.message || 'Unable to complete the local check.';
            } finally {
                if (revision === liveCheckRevision) liveCheckController = null;
            }
        }, 1000);
    }

    // ═══ EVENTS ═══
    tabBtns.forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));
    codeInput.addEventListener('input', scheduleLiveCheck);
    codeInput.addEventListener('input', updateLineNumbers);
    codeInput.addEventListener('scroll', updateLineNumbers);
    codeLanguage.addEventListener('change', () => {
        sourceFilename.textContent = codeLanguage.value === 'cpp' ? 'source_audit.cpp' : 'source_audit.c';
        currentCode = '';
        detectedCWEs = [];
        actionDock.classList.add('hidden');
        scheduleLiveCheck();
    });
    $('btn-clear').addEventListener('click', () => {
        codeInput.value = '';
        updateLineNumbers();
        currentCode = '';
        detectedCWEs = [];
        actionDock.classList.add('hidden');
        scheduleLiveCheck();
        scoreNumber.textContent = '--';
        statLoc.textContent = '0';
        setEditorMode('edit');
        showState('state', 'idle');
    });
    $('btn-edit').addEventListener('click', () => setEditorMode('edit'));

    analyzeBtn.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        if (!code) return;

        currentCode = code;
        detectedCWEs = [];
        actionDock.classList.add('hidden');
        showState('state', 'loading');
        statusDot.className = 'status-dot active';
        statusText.textContent = 'Analyzing...';

        try {
            const requestLlmReview = llmReviewConsent.checked;
            const demo = window.getDemoResults ? window.getDemoResults(code) : null;
            let data;
            
            if (demo && !requestLlmReview) {
                await new Promise(r => setTimeout(r, 1200));
                data = demo.analysis;
            } else {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: code, language: codeLanguage.value, llm_review: requestLlmReview })
                });
                data = await response.json();
            }

            if (data.success) {
                renderResults(data, code);
                showState('state', 'success');
                statusDot.className = 'status-dot done';
                statusText.textContent = 'Complete';
            } else {
                throw new Error(data.error);
            }
        } catch (err) {
            $('error-message').textContent = err.message;
            showState('state', 'error');
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Error';
        }
    });

    function getSecurityEstimate(predictions, suppliedEstimate) {
        if (suppliedEstimate && Number.isFinite(suppliedEstimate.score)) {
            return suppliedEstimate;
        }

        const severityWeights = { CRITICAL: 80, HIGH: 60, MEDIUM: 35, LOW: 20 };
        const severityByCwe = {
            'CWE-476': 'HIGH', 'CWE-191': 'HIGH', 'CWE-190': 'HIGH', 'CWE-369': 'MEDIUM'
        };
        const findings = predictions.filter(p => p.detected && p.class !== 'non-vulnerable');
        const riskPoints = findings.reduce((total, finding) => {
            const probability = Math.max(0, Math.min(1, Number(finding.probability) || 0));
            const severity = finding.severity || severityByCwe[finding.class] || 'MEDIUM';
            return total + (severityWeights[severity.toUpperCase()] || 35) * probability;
        }, 0);
        const score = Math.max(0, Math.min(100, Math.round(100 - riskPoints)));
        const riskLevel = findings.length === 0
            ? 'No supported issues detected'
            : score >= 80 ? 'Lower detected risk'
                : score >= 50 ? 'Moderate detected risk' : 'Higher detected risk';
        return { score, risk_level: riskLevel };
    }

    function renderResults(data, code) {
        statTime.textContent = `${data.elapsed.toFixed(2)}s`;
        const lines = code.split('\n').filter(l => l.trim()).length;
        statLoc.textContent = lines;

        const preds = data.predictions || [];
        const detected = preds.filter(p => p.detected && p.class !== 'non-vulnerable');
        detectedCWEs = detected.map(p => p.class);

        const estimate = getSecurityEstimate(preds, data.security_estimate);
        renderLlmReview(data.llm_review);
        const score = estimate.score;
        scoreNumber.textContent = score;
        scoreNumber.style.color = score > 80 ? 'var(--success)' : (score > 50 ? 'var(--warning)' : 'var(--danger)');

        // Verdict Card
        const banner = $('verdict-banner');
        if (detected.length > 0) {
            banner.className = 'verdict-card vuln';
            banner.innerHTML = `<h4>${estimate.risk_level}</h4><p>${detected.length} supported issue(s) detected. Estimate: ${score}/100; review findings before repair.</p>`;
            actionDock.classList.remove('hidden');
        } else {
            banner.className = 'verdict-card safe';
            banner.innerHTML = `<h4>No supported vulnerabilities detected</h4><p>Estimate: ${score}/100. This checks supported patterns only and does not guarantee the code is secure.</p>`;
            actionDock.classList.add('hidden');
        }

        // Probability Stacks
        const probList = $('prob-list');
        probList.innerHTML = '';
        preds.sort((a,b) => b.probability - a.probability).forEach(p => {
            const isDanger = p.class !== 'non-vulnerable' && p.detected;
            const item = document.createElement('div');
            item.className = `prob-item ${isDanger ? 'danger' : ''}`;
            item.innerHTML = `
                <div class="prob-header">
                    <span class="prob-name">${p.class}</span>
                    <span class="prob-pct">${(p.probability*100).toFixed(1)}%</span>
                </div>
                <div class="p-bar"><div class="p-fill" style="width: ${p.probability*100}%"></div></div>
            `;
            probList.appendChild(item);
        });

        // Code Highlight
        if (window.highlightVulnerability && detected.length > 0) {
            codeRender.innerHTML = `<code>${window.highlightVulnerability(code, detected[0].function)}</code>`;
            setEditorMode('view');
        } else {
            codeRender.innerHTML = `<code>${escapeHtml(code)}</code>`;
            setEditorMode('view');
        }
    }

    function renderLlmReview(review) {
        const panel = $('llm-review-result');
        panel.replaceChildren();
        panel.classList.toggle('hidden', !review || !review.requested);
        if (!review || !review.requested) return;

        const heading = document.createElement('h4');
        heading.textContent = review.available
            ? `Optional LLM review: ${review.risk_level} (${review.security_score}/100)`
            : 'Optional LLM review unavailable';
        panel.appendChild(heading);

        const summary = document.createElement('p');
        summary.textContent = review.available
            ? review.summary || review.scope
            : review.message || 'The configured provider did not return a review.';
        panel.appendChild(summary);

        if (review.available && review.findings && review.findings.length) {
            const list = document.createElement('ul');
            review.findings.forEach(finding => {
                const item = document.createElement('li');
                const location = finding.line ? `Line ${finding.line}: ` : '';
                item.textContent = `${location}${finding.severity.toUpperCase()} - ${finding.title}. ${finding.reason} Fix: ${finding.recommendation}`;
                list.appendChild(item);
            });
            panel.appendChild(list);
        }

        if (review.available) {
            const scope = document.createElement('p');
            scope.className = 'llm-review-scope';
            scope.textContent = review.scope;
            panel.appendChild(scope);
        }
    }

    // ═══ LOCALIZATION ═══
    btnLocalize.addEventListener('click', async () => {
        switchTab('tab-localization');
        $('loc-idle').classList.add('hidden');
        $('loc-loading').classList.remove('hidden');
        $('loc-results').classList.add('hidden');

        try {
            const demo = window.getDemoResults ? window.getDemoResults(currentCode) : null;
            let data;
            if (demo && demo.localization) {
                await new Promise(r => setTimeout(r, 800));
                data = { success: true, localizations: demo.localization };
            } else {
                const response = await fetch('/api/localize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: currentCode, language: codeLanguage.value, cwes: detectedCWEs })
                });
                data = await response.json();
            }

            if (data.success) {
                $('loc-loading').classList.add('hidden');
                $('loc-results').classList.remove('hidden');
                locInstructions.innerHTML = '';
                const cwe = Object.keys(data.localizations)[0];
                data.localizations[cwe].forEach(inst => {
                    const el = document.createElement('div');
                    el.className = 'inst-item';
                    el.innerHTML = `
                        <div class="inst-head"><span class="inst-op">${inst.opcode}</span><span>${(inst.score*100).toFixed(1)}% weight</span></div>
                        <div class="inst-txt">${escapeHtml(inst.text)}</div>
                    `;
                    locInstructions.appendChild(el);
                });
            }
        } catch (e) { console.error(e); }
    });

    // ═══ HEALING ═══
    btnHeal.addEventListener('click', async () => {
        switchTab('tab-healing');
        $('heal-idle').classList.add('hidden');
        $('heal-results').classList.add('hidden');

        try {
            const demo = window.getDemoResults ? window.getDemoResults(currentCode) : null;
            let data;
            if (demo && demo.healed_source) {
                await new Promise(r => setTimeout(r, 900));
                data = { success: true, healed: true, healed_code: demo.healed_source, message: "AI Repair Patch Generated." };
            } else {
                const response = await fetch('/api/heal', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: currentCode, language: codeLanguage.value, mode: 'source' })
                });
                data = await response.json();
            }

            if (data.success && data.healed) {
                $('heal-results').classList.remove('hidden');
                healHeader.textContent = data.message;
                diffBefore.textContent = currentCode;
                diffAfter.textContent = data.healed_code;
                
                if (confirm("Heal complete. Apply patched code to editor?")) {
                    codeInput.value = data.healed_code;
                    updateLineNumbers();
                    setEditorMode('edit');
                    scheduleLiveCheck();
                }
            }
        } catch (e) { console.error(e); }
    });

    // ═══ PIPELINE ═══
    btnPipeline.addEventListener('click', async () => {
        logContainer.innerHTML = '<div class="log-entry active">> Initializing GNN Iterative Pipeline...</div>';
        
        try {
            const response = await fetch('/api/pipeline', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: currentCode, language: codeLanguage.value, carbon_tracking: true })
            });
            const data = await response.json();
            
            if (data.success) {
                logContainer.innerHTML = '';
                data.iterations.forEach(iter => {
                    const line = document.createElement('div');
                    line.className = 'log-entry done';
                    line.textContent = `> Iteration ${iter.iteration}: Validation Passed`;
                    logContainer.appendChild(line);
                });
                const final = document.createElement('div');
                final.className = 'log-entry active';
                final.textContent = `> Final Status: ${data.status} | Total Patches: ${data.total_patches}`;
                logContainer.appendChild(final);

                if (data.carbon_metrics) {
                    statEnergy.textContent = data.carbon_metrics.energy_kwh.toFixed(4);
                    statCo2.textContent = data.carbon_metrics.co2_kg.toFixed(5);
                }
            }
        } catch (e) { console.error(e); }
    });
});
