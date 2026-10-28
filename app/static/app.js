// DevGuard AI — Frontend Application Controller
const app = {
  currentScan: null,
  allFindings: [],
  selectedFinding: null,
  activeFixPreview: null,
  repoMode: 'zip',

  init() {
    this.bindEvents();
    this.checkHealth();
    this.loadModels();
    this.loadDashboardStats();
    this.loadSettings();

    // Support URL hash routing
    const hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById(`pane-${hash}`)) {
      this.switchTab(hash);
    }
  },

  toast(msg, type = 'ok') {
    const container = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    container.appendChild(t);
    setTimeout(() => t.remove(), 4000);
  },

  esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  },

  switchTab(tabId) {
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-pane').forEach(el => {
      el.classList.toggle('active', el.id === `pane-${tabId}`);
    });
    window.location.hash = tabId;

    const titles = {
      dashboard: 'Security Dashboard',
      review: 'Advanced Code Review',
      repo: 'Repository & Project Scanner',
      findings: 'Security Findings Explorer',
      error: 'Error Explainer & Debugger',
      git: 'Git Diff Security Review',
      deps: 'Dependency Vulnerability Audit',
      history: 'Scan History & Comparisons',
      reports: 'Compliance & Export Reports',
      settings: 'DevGuard Configuration'
    };
    document.getElementById('pageTitle').textContent = titles[tabId] || 'DevGuard AI';

    if (tabId === 'history' || tabId === 'reports') {
      this.loadScanHistory();
    }
  },

  setRepoMode(mode) {
    this.repoMode = mode;
    document.getElementById('repoModeZipBtn').className = mode === 'zip' ? 'btn btn-primary' : 'btn btn-secondary';
    document.getElementById('repoModeLocalBtn').className = mode === 'local' ? 'btn btn-primary' : 'btn btn-secondary';
    document.getElementById('repoZipSection').style.display = mode === 'zip' ? 'block' : 'none';
    document.getElementById('repoLocalSection').style.display = mode === 'local' ? 'block' : 'none';
  },

  async checkHealth() {
    const dot = document.getElementById('ollamaStatusDot');
    const text = document.getElementById('ollamaStatusText');
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      if (data.ollama === 'connected' && data.model_available) {
        dot.className = 'status-dot connected';
        text.textContent = `Ollama: ${data.configured_model}`;
        document.getElementById('dashActiveModel').textContent = data.configured_model;
      } else if (data.ollama === 'connected') {
        dot.className = 'status-dot';
        dot.style.background = '#eab308';
        text.textContent = `Model ${data.configured_model} not found`;
      } else {
        dot.className = 'status-dot disconnected';
        text.textContent = 'Ollama offline';
      }
      if (data.endpoint) {
        document.getElementById('dashOllamaEndpoint').textContent = data.endpoint;
      }
    } catch {
      dot.className = 'status-dot disconnected';
      text.textContent = 'Backend unreachable';
    }
  },

  async loadModels() {
    try {
      const res = await fetch('/api/models');
      const data = await res.json();
      const sel = document.getElementById('globalModelSelect');
      sel.innerHTML = '';
      if (data.models && data.models.length > 0) {
        data.models.forEach(m => {
          const opt = document.createElement('option');
          opt.value = m;
          opt.textContent = m;
          if (m === data.default_model) opt.selected = true;
          sel.appendChild(opt);
        });
      } else {
        const opt = document.createElement('option');
        opt.value = data.default_model || 'gemma4:e2b';
        opt.textContent = opt.value;
        sel.appendChild(opt);
      }
    } catch (e) {
      console.warn('Could not load model list:', e);
    }
  },

  async loadDashboardStats() {
    try {
      const res = await fetch('/api/scans?limit=5');
      const scans = await res.json();
      document.getElementById('dashTotalScans').textContent = scans.length;

      let crit = 0, high = 0, medLow = 0, totalScore = 0, scoredCount = 0;
      scans.forEach(s => {
        crit += (s.critical_count || 0);
        high += (s.high_count || 0);
        medLow += (s.medium_count || 0) + (s.low_count || 0);
        if (s.risk_score !== null && s.risk_score !== undefined) {
          totalScore += s.risk_score;
          scoredCount++;
        }
      });

      document.getElementById('dashCritCount').textContent = crit;
      document.getElementById('dashHighCount').textContent = high;
      document.getElementById('dashMedLowCount').textContent = medLow;
      document.getElementById('dashAvgRisk').textContent = scoredCount > 0 ? `${Math.round(totalScore / scoredCount)}/100` : '0/100';

      const recentBox = document.getElementById('dashRecentScansList');
      if (scans.length === 0) {
        recentBox.innerHTML = '<div style="color:var(--text-dim);font-size:13px;padding:12px">No scans executed yet. Analyze a snippet or repository to begin.</div>';
      } else {
        recentBox.innerHTML = scans.map(s => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border-subtle)">
            <div>
              <strong style="color:var(--text-main);font-size:13.5px">${this.esc(s.project_name)}</strong>
              <div style="font-size:11.5px;color:var(--text-dim)">${new Date(s.created_at).toLocaleString()} · ${this.esc(s.model_name)}</div>
            </div>
            <div style="display:flex;align-items:center;gap:12px">
              <span class="sev-badge ${s.critical_count > 0 ? 'Critical' : s.high_count > 0 ? 'High' : 'Low'}">
                ${s.findings_count} findings
              </span>
              <button class="btn btn-secondary" style="padding:4px 8px;font-size:11px" onclick="app.viewHistoricalScan('${s.scan_id}')">Open</button>
            </div>
          </div>
        `).join('');
      }
    } catch (e) {
      console.warn('Dashboard stats error:', e);
    }
  },

  renderFindingsList(findings, containerId) {
    const el = document.getElementById(containerId);
    el.innerHTML = '';
    if (!findings || findings.length === 0) {
      el.innerHTML = '<div style="color:var(--text-dim);padding:14px">No findings to display.</div>';
      return;
    }

    findings.forEach(f => {
      const card = document.createElement('div');
      card.className = 'finding-card';
      card.onclick = () => this.openFindingModal(f);

      const owaspTag = f.owasp_category ? `<span style="font-size:10.5px;color:var(--teal-400);background:rgba(20,184,166,0.1);padding:2px 6px;border-radius:4px">${this.esc(f.owasp_category.split(' - ')[0])}</span>` : '';

      card.innerHTML = `
        <div class="finding-card-top">
          <div class="finding-card-title">
            <span class="sev-badge ${this.esc(f.severity)}">${this.esc(f.severity)}</span>
            <span>${this.esc(f.title)}</span>
          </div>
          <div>${owaspTag}</div>
        </div>
        <div class="finding-card-meta">
          📁 ${this.esc(f.file_path || 'snippet')} ${f.start_line ? `· Line ${f.start_line}` : ''} · 🔍 ${this.esc(f.detection_source || 'Rule')} (${Math.round((f.confidence || 0.8) * 100)}% confidence)
        </div>
        <div class="finding-card-desc">${this.esc(f.description || f.why_it_matters)}</div>
        ${f.evidence ? `<div class="finding-evidence-box">${this.esc(f.evidence)}</div>` : ''}
      `;
      el.appendChild(card);
    });
  },

  openFindingModal(f) {
    this.selectedFinding = f;
    document.getElementById('modalFindingTitle').textContent = `[${f.severity}] ${f.title}`;
    const body = document.getElementById('modalFindingBody');
    body.innerHTML = `
      <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">
        <span class="sev-badge ${this.esc(f.severity)}">${this.esc(f.severity)}</span>
        <span style="font-size:12px;color:var(--text-dim);font-family:var(--font-mono)">File: ${this.esc(f.file_path)} : line ${f.start_line || 'N/A'}</span>
        <span style="font-size:12px;color:var(--teal-400)">Confidence: ${Math.round((f.confidence || 0.8) * 100)}% (${this.esc(f.verification_status)})</span>
      </div>

      <h4 style="font-size:13px;color:var(--text-muted);margin:10px 0 4px">DESCRIPTION</h4>
      <p style="margin-bottom:12px;color:var(--text-main)">${this.esc(f.description)}</p>

      <h4 style="font-size:13px;color:var(--text-muted);margin:10px 0 4px">WHY IT MATTERS</h4>
      <p style="margin-bottom:12px;color:var(--text-main)">${this.esc(f.why_it_matters || 'Exposes the system to potential attacks or logic defects.')}</p>

      ${f.evidence ? `
        <h4 style="font-size:13px;color:var(--text-muted);margin:10px 0 4px">EVIDENCE</h4>
        <div class="finding-evidence-box" style="margin-bottom:12px">${this.esc(f.evidence)}</div>
      ` : ''}

      <h4 style="font-size:13px;color:var(--text-muted);margin:10px 0 4px">RECOMMENDED FIX</h4>
      <p style="margin-bottom:12px;color:var(--teal-400)">${this.esc(f.recommended_fix || 'Sanitize input or parameterize queries.')}</p>

      ${f.owasp_category ? `
        <h4 style="font-size:13px;color:var(--text-muted);margin:10px 0 4px">OWASP CATEGORY MAPPING</h4>
        <p style="margin-bottom:8px">
          <a href="${this.esc(f.owasp_url || '#')}" target="_blank" style="color:var(--blue-400);text-decoration:underline">
            ${this.esc(f.owasp_category)} ↗
          </a>
        </p>
      ` : ''}
    `;

    document.getElementById('findingModal').classList.add('open');
  },

  closeModal(id) {
    document.getElementById(id).classList.remove('open');
  },

  async generateFixForSelectedFinding() {
    if (!this.selectedFinding) return;
    const f = this.selectedFinding;
    const btn = document.getElementById('modalGenerateFixBtn');
    btn.disabled = true;
    btn.textContent = 'Generating patch with Ollama…';

    const snippetCode = document.getElementById('reviewCodeInput').value || f.evidence || '/* code */';

    try {
      const res = await fetch('/api/generate-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: f.finding_id,
          code_or_file: snippetCode,
          finding_title: f.title,
          finding_description: f.description,
          evidence: f.evidence,
          start_line: f.start_line,
          end_line: f.end_line,
          model_name: document.getElementById('globalModelSelect').value
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Fix generation failed');

      this.activeFixPreview = data;
      this.closeModal('findingModal');
      this.openFixPreviewModal(data);
    } catch (err) {
      this.toast(`Fix generation failed: ${err.message}`, 'bad');
    } finally {
      btn.disabled = false;
      btn.textContent = '⚡ Generate AI Fix';
    }
  },

  openFixPreviewModal(patchData) {
    const body = document.getElementById('fixPreviewModalBody');
    body.innerHTML = `
      <div style="margin-bottom:12px">
        <h4 style="font-size:13px;color:var(--text-muted)">EXPLANATION</h4>
        <p style="color:var(--text-main);margin:4px 0 10px">${this.esc(patchData.explanation)}</p>

        <h4 style="font-size:13px;color:var(--text-muted)">EXPECTED BEHAVIOR</h4>
        <p style="color:var(--teal-400);margin:4px 0 10px">${this.esc(patchData.expected_behavior)}</p>

        <h4 style="font-size:13px;color:var(--text-muted)">SUGGESTED VERIFICATION TESTS</h4>
        <ul style="margin:4px 0 12px 20px;color:var(--text-muted)">
          ${patchData.suggested_tests.map(t => `<li>${this.esc(t)}</li>`).join('')}
        </ul>

        <h4 style="font-size:13px;color:var(--text-muted)">PROPOSED UNIFIED DIFF</h4>
        <div class="finding-evidence-box" style="color:#a5f3fc;max-height:220px;overflow-y:auto">${this.esc(patchData.unified_diff)}</div>
      </div>
    `;
    document.getElementById('fixPreviewModal').classList.add('open');
  },

  async runCodeReview() {
    const code = document.getElementById('reviewCodeInput').value;
    if (!code.trim()) {
      this.toast('Please paste some code first', 'bad');
      return;
    }

    const btn = document.getElementById('startReviewBtn');
    btn.disabled = true;
    btn.textContent = 'Analyzing with Ollama…';
    const outputBox = document.getElementById('reviewOutputBox');
    outputBox.textContent = 'Running AST analysis, deterministic rule checks, and querying local model…';

    try {
      const res = await fetch('/api/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: code,
          language: document.getElementById('reviewLang').value,
          analysis_type: document.getElementById('reviewType').value,
          analysis_depth: document.getElementById('reviewDepth').value,
          custom_instructions: document.getElementById('reviewPrompt').value,
          model_name: document.getElementById('globalModelSelect').value
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Code review request failed');

      outputBox.textContent = data.summary;
      this.currentScan = data;
      this.allFindings = data.findings || [];
      document.getElementById('reviewFindingsCount').textContent = this.allFindings.length;
      document.getElementById('reviewReportMeta').textContent = `Model: ${data.model_used} · Duration: ${data.duration_ms}ms · Secrets redacted: ${data.secret_redactions}`;
      this.renderFindingsList(this.allFindings, 'reviewFindingsList');
      this.renderFindingsList(this.allFindings, 'allFindingsList');
      this.loadDashboardStats();
      this.toast('Code review completed successfully!', 'ok');
    } catch (err) {
      outputBox.textContent = `Error: ${err.message}`;
      this.toast(`Review failed: ${err.message}`, 'bad');
    } finally {
      btn.disabled = false;
      btn.textContent = '⚡ Run AI Review';
    }
  },

  async runRepoScan() {
    const btn = document.getElementById('startRepoScanBtn');
    btn.disabled = true;
    btn.textContent = 'Scanning project…';
    const outputBox = document.getElementById('repoOutputBox');
    outputBox.textContent = 'Evaluating repository structure, filtering files, and performing analysis…';

    try {
      let res;
      if (this.repoMode === 'zip') {
        const fileInput = document.getElementById('repoZipInput');
        if (!fileInput.files[0]) {
          throw new Error('Please select a ZIP file to upload.');
        }
        const fd = new FormData();
        fd.append('file', fileInput.files[0]);
        fd.append('question', document.getElementById('repoQuestionInput').value);
        fd.append('model_name', document.getElementById('globalModelSelect').value);
        res = await fetch('/api/analyze-archive', { method: 'POST', body: fd });
      } else {
        const localPath = document.getElementById('repoLocalPathInput').value.trim();
        if (!localPath) {
          throw new Error('Please enter a local directory path.');
        }
        const fd = new FormData();
        fd.append('directory_path', localPath);
        fd.append('question', document.getElementById('repoQuestionInput').value);
        fd.append('model_name', document.getElementById('globalModelSelect').value);
        res = await fetch('/api/analyze-local', { method: 'POST', body: fd });
      }

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Repository scan failed');

      outputBox.textContent = data.summary || data.analysis;
      this.allFindings = data.findings || [];
      this.renderFindingsList(this.allFindings, 'allFindingsList');
      document.getElementById('repoScannedCount').textContent = (data.files_scanned || []).length;
      document.getElementById('repoSkippedCount').textContent = (data.files_skipped || []).length;

      const detailsEl = document.getElementById('repoFilesDetails');
      detailsEl.innerHTML = `
        <strong>Scanned (${(data.files_scanned || []).length}):</strong> ${(data.files_scanned || []).join(', ') || 'None'}<br><br>
        <strong>Skipped (${(data.files_skipped || []).length}):</strong> ${(data.files_skipped || []).join(', ') || 'None'}
      `;

      this.toast('Repository scan complete!', 'ok');
      this.loadDashboardStats();
    } catch (err) {
      outputBox.textContent = `Error: ${err.message}`;
      this.toast(err.message, 'bad');
    } finally {
      btn.disabled = false;
      btn.textContent = '🚀 Start Repository Scan';
    }
  },

  async explainError() {
    const msg = document.getElementById('errMessageInput').value.trim();
    if (!msg) {
      this.toast('Please provide an error message', 'bad');
      return;
    }
    const btn = document.getElementById('explainErrorBtn');
    btn.disabled = true;
    btn.textContent = 'Analyzing error with Ollama…';
    const outputBox = document.getElementById('errorExplanationOutput');
    outputBox.textContent = 'Analyzing stack trace and source context…';

    try {
      const res = await fetch('/api/explain-error', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          language: document.getElementById('errLang').value,
          error_message: msg,
          stack_trace: document.getElementById('errStackInput').value,
          related_code: document.getElementById('errCodeInput').value,
          experience_level: document.getElementById('errExperience').value,
          model_name: document.getElementById('globalModelSelect').value
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Error explainer request failed');

      outputBox.textContent = `
--- ROOT CAUSE SUMMARY ---
${data.summary}

--- LIKELY CAUSES ---
${data.likely_causes.map(c => `• ${c}`).join('\n')}

--- EVIDENCE ANALYSIS ---
${data.evidence_analysis}

--- DEBUGGING STEPS ---
${data.debugging_steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}

--- POSSIBLE FIXES ---
${data.possible_fixes.join('\n')}

--- RECOMMENDED TESTS ---
${data.suggested_tests.map(t => `• ${t}`).join('\n')}

--- UNCERTAINTIES & ASSUMPTIONS ---
${data.uncertainties_and_assumptions}
      `.trim();
      this.toast('Explanation generated successfully!', 'ok');
    } catch (err) {
      outputBox.textContent = `Error: ${err.message}`;
      this.toast(err.message, 'bad');
    } finally {
      btn.disabled = false;
      btn.textContent = '⚡ Explain Error & Suggest Fixes';
    }
  },

  async runGitReview() {
    const repoPath = document.getElementById('gitRepoPath').value.trim();
    if (!repoPath) {
      this.toast('Please enter a Git repository path on disk', 'bad');
      return;
    }

    const btn = document.getElementById('runGitReviewBtn');
    btn.disabled = true;
    btn.textContent = 'Inspecting Git diff…';
    const outputBox = document.getElementById('gitDiffOutput');
    outputBox.textContent = 'Running git diff and checking changed lines for security issues…';

    try {
      const res = await fetch('/api/git-review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository_path: repoPath,
          base_ref: document.getElementById('gitBaseRef').value || 'HEAD~1',
          target_ref: document.getElementById('gitTargetRef').value || '',
          model_name: document.getElementById('globalModelSelect').value
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Git diff review failed');

      outputBox.textContent = `
CHANGED FILES (${data.files_changed.length}):
${data.files_changed.join('\n') || 'None'}

AI DIFF REVIEW:
${data.diff_summary}

POTENTIAL REGRESSIONS:
${data.potential_regressions.map(r => `• ${r}`).join('\n')}

MISSING TEST COVERAGE:
${data.missing_tests.map(t => `• ${t}`).join('\n')}
      `.trim();
      this.toast('Git review complete!', 'ok');
    } catch (err) {
      outputBox.textContent = `Error: ${err.message}`;
      this.toast(err.message, 'bad');
    } finally {
      btn.disabled = false;
      btn.textContent = '🌿 Inspect Git Diff';
    }
  },

  async scanDependencies() {
    const content = document.getElementById('depContentInput').value.trim();
    if (!content) {
      this.toast('Please paste manifest content', 'bad');
      return;
    }

    const btn = document.getElementById('scanDepsBtn');
    btn.disabled = true;
    btn.textContent = 'Auditing dependencies…';
    const container = document.getElementById('depResultsContainer');
    container.innerHTML = '<div style="color:var(--text-muted);font-size:13px">Parsing dependencies without executing code…</div>';

    try {
      const res = await fetch('/api/scan-dependencies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manifest_type: document.getElementById('depManifestType').value,
          content: content,
          enable_online_lookup: document.getElementById('depOnlineToggle').checked
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Dependency audit failed');

      document.getElementById('depResultsMeta').textContent = `Parsed ${data.packages_parsed} packages · Found ${data.vulnerabilities_found} advisories`;

      let html = `<div style="margin-bottom:12px;font-size:12px;color:var(--text-dim)">${this.esc(data.notice)}</div>`;

      if (data.vulnerabilities.length === 0) {
        html += '<div style="color:var(--teal-400);font-weight:700">✓ No known vulnerabilities detected for the specified packages and versions.</div>';
      } else {
        html += `
          <table class="data-table">
            <thead>
              <tr>
                <th>Package</th>
                <th>Installed</th>
                <th>Severity</th>
                <th>Advisory / Fix</th>
              </tr>
            </thead>
            <tbody>
              ${data.vulnerabilities.map(v => `
                <tr>
                  <td><strong>${this.esc(v.package_name)}</strong><br><span style="font-size:11px;color:var(--text-dim)">${this.esc(v.ecosystem)}</span></td>
                  <td><code>${this.esc(v.installed_version)}</code></td>
                  <td><span class="sev-badge ${this.esc(v.severity)}">${this.esc(v.severity)}</span></td>
                  <td>
                    <a href="${this.esc(v.advisory_url)}" target="_blank" style="color:var(--blue-400);font-weight:600">${this.esc(v.vulnerability_id)}</a>
                    ${v.fixed_version ? `<div style="font-size:11px;color:var(--teal-400)">Fixed in: ${this.esc(v.fixed_version)}</div>` : ''}
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      }
      container.innerHTML = html;
      this.toast('Dependency audit finished!', 'ok');
    } catch (err) {
      container.innerHTML = `<div style="color:var(--red-500)">Error: ${this.esc(err.message)}</div>`;
      this.toast(err.message, 'bad');
    } finally {
      btn.disabled = false;
      btn.textContent = '🔍 Audit Dependencies';
    }
  },

  async loadScanHistory() {
    try {
      const q = document.getElementById('historySearchInput').value.trim();
      const res = await fetch(`/api/scans?limit=50${q ? `&query=${encodeURIComponent(q)}` : ''}`);
      const scans = await res.json();
      const tbody = document.getElementById('historyTableBody');
      const repSel = document.getElementById('reportScanSelect');

      if (repSel) {
        repSel.innerHTML = '<option value="">Select a scan…</option>' + scans.map(s => `
          <option value="${s.scan_id}">${this.esc(s.project_name)} (${new Date(s.created_at).toLocaleDateString()})</option>
        `).join('');
      }

      if (scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-dim)">No scans recorded.</td></tr>';
        return;
      }

      tbody.innerHTML = scans.map(s => `
        <tr>
          <td><code style="color:var(--teal-400)">${this.esc(s.scan_id)}</code></td>
          <td><strong>${this.esc(s.project_name)}</strong></td>
          <td style="font-size:12px;color:var(--text-dim)">${new Date(s.created_at).toLocaleString()}</td>
          <td><code>${this.esc(s.model_name)}</code></td>
          <td><span class="sev-badge ${s.critical_count > 0 ? 'Critical' : s.high_count > 0 ? 'High' : 'Low'}">${s.findings_count}</span></td>
          <td><strong>${s.risk_score ?? 'N/A'}/100</strong></td>
          <td>
            <button class="btn btn-secondary" style="padding:4px 8px;font-size:11.5px" onclick="app.viewHistoricalScan('${s.scan_id}')">View</button>
            <button class="btn btn-danger" style="padding:4px 8px;font-size:11.5px" onclick="app.deleteScan('${s.scan_id}')">Delete</button>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      console.warn('History error:', e);
    }
  },

  async viewHistoricalScan(scanId) {
    try {
      const res = await fetch(`/api/scans/${scanId}`);
      const data = await res.json();
      this.currentScan = data;
      this.allFindings = data.findings || [];
      this.switchTab('findings');
      this.renderFindingsList(this.allFindings, 'allFindingsList');
      this.toast(`Loaded scan: ${data.summary.project_name}`, 'ok');
    } catch (e) {
      this.toast('Could not load scan details', 'bad');
    }
  },

  async deleteScan(scanId) {
    if (!confirm(`Are you sure you want to delete scan '${scanId}'?`)) return;
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
      if (res.ok) {
        this.toast('Scan deleted successfully', 'ok');
        this.loadScanHistory();
        this.loadDashboardStats();
      } else {
        throw new Error('Failed to delete scan');
      }
    } catch (err) {
      this.toast(err.message, 'bad');
    }
  },

  exportReport(format) {
    const scanId = document.getElementById('reportScanSelect').value;
    if (!scanId) {
      this.toast('Please choose a scan first', 'bad');
      return;
    }
    window.location.href = `/api/scans/${scanId}/report?format=${format}`;
  },

  async loadSettings() {
    try {
      const res = await fetch('/api/settings');
      const data = await res.json();
      document.getElementById('cfgOllamaUrl').value = data.ollama_url || 'http://localhost:11434';
      document.getElementById('cfgDefaultModel').value = data.default_model || 'gemma4:e2b';
      document.getElementById('cfgTimeout').value = data.timeout || 180;
      document.getElementById('cfgOnlineDepToggle').checked = !!data.online_dependency_check;
    } catch (e) {
      console.warn('Could not load settings:', e);
    }
  },

  async saveSettings() {
    const btn = document.getElementById('saveSettingsBtn');
    btn.disabled = true;
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ollama_url: document.getElementById('cfgOllamaUrl').value,
          default_model: document.getElementById('cfgDefaultModel').value,
          timeout: parseInt(document.getElementById('cfgTimeout').value, 10),
          enable_online_dep_check: document.getElementById('cfgOnlineDepToggle').checked
        })
      });
      if (res.ok) {
        this.toast('Configuration saved successfully!', 'ok');
        this.checkHealth();
        this.loadModels();
      } else {
        throw new Error('Failed to update settings');
      }
    } catch (err) {
      this.toast(err.message, 'bad');
    } finally {
      btn.disabled = false;
    }
  },

  bindEvents() {
    // Nav menu click
    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', () => this.switchTab(el.dataset.tab));
    });

    // Sample snippet
    document.getElementById('loadSampleSnippetBtn').addEventListener('click', () => {
      document.getElementById('reviewLang').value = 'Python';
      document.getElementById('reviewCodeInput').value = `import os
import sqlite3
import hashlib

def login_user(username, password):
    # Potential SQL injection via string concatenation
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    
    # Insecure hashing with MD5
    hashed_pwd = hashlib.md5(password.encode()).hexdigest()
    
    # Insecure command execution
    os.system("echo 'User logged in: ' " + username)
    
    return cursor.fetchone()
`;
      this.toast('Sample Python vulnerable code loaded', 'ok');
    });

    // Sample dependency manifest
    document.getElementById('loadSampleDepsBtn').addEventListener('click', () => {
      document.getElementById('depManifestType').value = 'requirements.txt';
      document.getElementById('depContentInput').value = `flask==1.0.2
requests==2.20.0
urllib3==1.24.1
fastapi==0.115.0
pydantic==2.8.0
`;
      this.toast('Sample requirements.txt loaded', 'ok');
    });

    // Code Review
    document.getElementById('startReviewBtn').addEventListener('click', () => this.runCodeReview());

    // Repo Scan
    document.getElementById('startRepoScanBtn').addEventListener('click', () => this.runRepoScan());

    // Error Explainer
    document.getElementById('explainErrorBtn').addEventListener('click', () => this.explainError());
    document.getElementById('copyErrorExplanationBtn').addEventListener('click', () => {
      const text = document.getElementById('errorExplanationOutput').textContent;
      navigator.clipboard.writeText(text);
      this.toast('Explanation copied to clipboard!', 'ok');
    });

    // Git Review
    document.getElementById('runGitReviewBtn').addEventListener('click', () => this.runGitReview());

    // Dependencies
    document.getElementById('scanDepsBtn').addEventListener('click', () => this.scanDependencies());

    // History & Reports
    document.getElementById('refreshHistoryBtn').addEventListener('click', () => this.loadScanHistory());
    document.getElementById('historySearchInput').addEventListener('input', () => this.loadScanHistory());
    document.getElementById('exportMarkdownBtn').addEventListener('click', () => this.exportReport('markdown'));
    document.getElementById('exportJsonBtn').addEventListener('click', () => this.exportReport('json'));
    document.getElementById('exportSarifBtn').addEventListener('click', () => this.exportReport('sarif'));

    // Settings
    document.getElementById('saveSettingsBtn').addEventListener('click', () => this.saveSettings());

    // Modal Fix Generation
    document.getElementById('modalGenerateFixBtn').addEventListener('click', () => this.generateFixForSelectedFinding());

    // Copy Fix
    document.getElementById('copySuggestedFixBtn').addEventListener('click', () => {
      if (this.activeFixPreview && this.activeFixPreview.proposed_replacement) {
        navigator.clipboard.writeText(this.activeFixPreview.proposed_replacement);
        this.toast('Suggested replacement code copied to clipboard!', 'ok');
      }
    });

    // Findings Filter in Explorer
    const filterFindings = () => {
      const q = document.getElementById('findingSearchInput').value.toLowerCase();
      const sev = document.getElementById('findingSeverityFilter').value;
      const filtered = this.allFindings.filter(f => {
        const matchesQ = !q || (f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q) || (f.cwe_id && f.cwe_id.toLowerCase().includes(q)));
        const matchesSev = sev === 'all' || f.severity === sev;
        return matchesQ && matchesSev;
      });
      this.renderFindingsList(filtered, 'allFindingsList');
    };
    document.getElementById('findingSearchInput').addEventListener('input', filterFindings);
    document.getElementById('findingSeverityFilter').addEventListener('change', filterFindings);
  }
};

window.addEventListener('DOMContentLoaded', () => app.init());
