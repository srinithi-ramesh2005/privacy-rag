// Strict Session & RBAC Enforcement Gate
const sessionStr = localStorage.getItem('rag_session') || localStorage.getItem('rag_verifier_session');
if (!sessionStr) {
    window.location.href = '/'; // Kick out unauthenticated users
}
let session = null;
try {
    session = JSON.parse(sessionStr);
    if (!session) {
        window.location.href = '/';
    } else if (session.status === 'pending') {
        window.location.href = '/pending';
    }
    // If the user is not an admin, forcibly hide all admin elements
    if (session && session.role !== 'admin') {
        document.querySelectorAll('.admin-only-feature').forEach(el => el.style.display = 'none');
    }
} catch (e) {
    window.location.href = '/';
}

/**
 * Unified Asymmetric RAG Verifier - Frontend Dashboard Controller
 */
document.addEventListener('DOMContentLoaded', () => {

  // Security Gate: Ensure user is logged in
  const currentSessionStr = localStorage.getItem('rag_session') || localStorage.getItem('rag_verifier_session');
  if (!currentSessionStr) {
    window.location.href = '/';
    return;
  }
  const domSession = JSON.parse(currentSessionStr);
  if (domSession && domSession.status === 'pending') {
    window.location.href = '/pending';
    return;
  }
  // If the user is not an admin, forcibly hide all admin elements
  if (domSession && domSession.role !== 'admin') {
    document.querySelectorAll('.admin-only-feature').forEach(el => el.style.display = 'none');
  }

  // ─── Theme Toggle Setup ───
  const btnThemeToggle = document.getElementById('btn-theme-toggle');
  const themeLabel = document.getElementById('theme-label');
  const iconSun = document.getElementById('theme-icon-sun');
  const iconMoon = document.getElementById('theme-icon-moon');

  function updateThemeUI(theme) {
    if (theme === 'light') {
      if (themeLabel) themeLabel.textContent = 'Dark Mode';
      if (iconSun) iconSun.style.display = 'block';
      if (iconMoon) iconMoon.style.display = 'none';
    } else {
      if (themeLabel) themeLabel.textContent = 'Light Mode';
      if (iconSun) iconSun.style.display = 'none';
      if (iconMoon) iconMoon.style.display = 'block';
    }
  }

  const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
  updateThemeUI(currentTheme);

  btnThemeToggle?.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('rag_verifier_theme', next);
    updateThemeUI(next);
  });

  // ─── Utilities ───
  function escapeHtml(val) {
    if (val === null || val === undefined) return '';
    const str = typeof val === 'string' ? val : String(val);
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  /**
   * Render LLM markdown answer to safe HTML.
   * Supports: ### headers, **bold**, *italic*, `code`, bullet lists, numbered lists, blockquotes.
   */
  function renderMarkdown(md) {
    if (!md) return '';
    let html = md
      // Escape HTML characters to prevent XSS
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // 1. Code blocks (```lang ... ```)
    html = html.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
      return `<pre class="ans-pre"><code class="ans-codeblock">${code.trim()}</code></pre>\n`;
    });

    // 2. Headers (### H3, ## H2, # H1)
    html = html.replace(/^### (.+)$/gm, '<h3 class="ans-h3">$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2 class="ans-h2">$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h2 class="ans-h2">$1</h2>');

    // 3. Blockquotes
    html = html.replace(/^&gt; (.+)$/gm, '<blockquote class="ans-quote">$1</blockquote>');

    // 4. Bold and Italic
    html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // 5. Inline Code
    html = html.replace(/`([^`]+)`/g, '<code class="ans-code">$1</code>');

    // 6. Markdown Tables (| col1 | col2 | ... |)
    html = html.replace(/((?:^\|.+\|\r?\n?)+)/gm, (tableBlock) => {
      const rows = tableBlock.trim().split('\n').map(r => r.trim()).filter(Boolean);
      if (rows.length < 2) return tableBlock;

      let tableHtml = '<div class="ans-table-wrap"><table class="ans-table">';
      let isHeader = true;

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (/^\|[\s:-]+\|/.test(row)) {
          isHeader = false;
          continue;
        }
        const cells = row.split('|').slice(1, -1).map(c => c.trim());
        if (isHeader) {
          tableHtml += '<thead><tr>' + cells.map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>';
          isHeader = false;
        } else {
          tableHtml += '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
        }
      }
      tableHtml += '</tbody></table></div>\n';
      return tableHtml;
    });

    // 7. Numbered Lists
    html = html.replace(/((?:^\d+\.[ \t]+.+\n?)+)/gm, (block) => {
      const items = block.trim().split('\n').map(l => {
        const m = l.match(/^\d+\.[ \t]+(.+)$/);
        return m ? `<li>${m[1]}</li>` : '';
      }).filter(Boolean).join('');
      return `<ol class="ans-ol">${items}</ol>\n`;
    });

    // 8. Bullet Lists
    html = html.replace(/((?:^[-*][ \t]+.+\n?)+)/gm, (block) => {
      const items = block.trim().split('\n').map(l => {
        const m = l.match(/^[-*][ \t]+(.+)$/);
        return m ? `<li>${m[1]}</li>` : '';
      }).filter(Boolean).join('');
      return `<ul class="ans-ul">${items}</ul>\n`;
    });

    // 9. Paragraph breaks
    const lines = html.split('\n');
    const paras = [];
    let buf = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) {
        if (buf.length) { paras.push(buf.join(' ')); buf = []; }
      } else if (/^<(h[123]|ul|ol|blockquote|div|pre)/.test(trimmed)) {
        if (buf.length) { paras.push(buf.join(' ')); buf = []; }
        paras.push(trimmed);
      } else {
        buf.push(trimmed);
      }
    }
    if (buf.length) paras.push(buf.join(' '));

    return paras.map(p => {
      if (/^<(h[123]|ul|ol|blockquote|div|pre)/.test(p.trim())) return p;
      return `<p class="ans-para">${p}</p>`;
    }).join('');
  }

  function formatTimestamp(ts) {
    if (!ts) return 'Just now';
    if (typeof ts === 'number') {
      const d = new Date(ts > 1e11 ? ts : ts * 1000);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return String(ts);
  }

  function getOrgDisplayName(orgId) {
    if (!orgId) return 'Default Org';
    const known = {
      'org_1': 'Enterprise Tech Systems', 'org_2': 'Global Financial Corp', 'org_3': 'Healthcare Plus',
      'org_4': 'AeroSpace Defense', 'org_5': 'National Security Agency', 'org_6': 'PharmaBio Therapeutics',
      'org_7': 'Apex Fintech Capital', 'org_8': 'BioGen Genomics', 'org_9': 'CyberDefense Intelligence',
      'org_10': 'Quantum Cryptography Labs',
      'org_enterprise_01': 'Enterprise Tech Systems', 'org_finance_corp': 'Global Financial Corp',
      'org_healthcare_plus': 'Healthcare Plus', 'default_org': 'Unified Core Systems'
    };
    if (known[orgId]) return known[orgId];
    return orgId.replace(/^org_/, '').replace(/[_-]+/g, ' ').trim().replace(/\b\w/g, c => c.toUpperCase()) || orgId;
  }

  const $ = (id) => document.getElementById(id);

  // DOM refs
  const healthDot = $('health-dot'), healthLabel = $('health-label');
  const verifyForm = $('verify-form'), queryInput = $('query-input');
  const userIdInput = $('user-id-input'), orgIdInput = $('org-id-input');
  const btnSubmit = $('btn-submit');
  const verdictBanner = $('verdict-banner'), verdictBadge = $('verdict-badge');
  const verdictTiming = $('verdict-timing'), verdictHeadline = $('verdict-headline');
  const verdictSubtext = $('verdict-subtext');

  const cardGateAcl = $('card-gate-acl'), pillGateAcl = $('pill-gate-acl'), detailGateAcl = $('detail-gate-acl');
  const metaAclUser = $('meta-acl-user'), metaAclOrg = $('meta-acl-org');
  const cardGateIntegrity = $('card-gate-integrity'), pillGateIntegrity = $('pill-gate-integrity');
  const detailGateIntegrity = $('detail-gate-integrity'), metaIntegrityRoot = $('meta-integrity-root');
  const cardGateDecryption = $('card-gate-decryption'), pillGateDecryption = $('pill-gate-decryption');
  const detailGateDecryption = $('detail-gate-decryption'), metaDecryptedCount = $('meta-decrypted-count');
  const cardGateBoundary = $('card-gate-boundary'), pillGateBoundary = $('pill-gate-boundary');
  const detailGateBoundary = $('detail-gate-boundary'), rowMissing = $('row-missing-clusters');
  const tagsMissing = $('tags-missing-clusters');
  const cardGateGrounding = $('card-gate-grounding'), pillGateGrounding = $('pill-gate-grounding');
  const detailGateGrounding = $('detail-gate-grounding'), meterScoreText = $('meter-score-text');

  const maskedQueryVal = $('masked-query-val'), answerContent = $('answer-content');
  const btnCopyAnswer = $('btn-copy-answer'), chunksCountBadge = $('chunks-count-badge');
  const chunksList = $('chunks-list');
  const metricChunks = $('metric-chunks'), metricChunksBadge = $('metric-chunks-badge');

  const userBadgeWrap = $('user-badge-wrap'), sessionUsername = $('session-username');
  const sessionRole = $('session-role'), sessionOrg = $('session-org'), sessionStatus = $('session-status');
  const btnOpenAdminModal = $('btn-open-admin-modal'), adminPendingBadge = $('admin-pending-badge');
  const btnAuthAction = $('btn-auth-action'), authActionText = $('auth-action-text');
  const userStatusNotice = $('user-status-notice'), userStatusNoticeText = $('user-status-notice-text');

  const btnNewOrg = $('btn-new-org'), btnViewOrgDocs = $('btn-view-org-docs');
  const workbenchDocCount = $('workbench-doc-count'), orgOptions = $('org-options');

  const authModal = $('auth-modal'), btnCloseAuthModal = $('btn-close-auth-modal');
  const authCredentialsView = $('auth-credentials-view');
  const authOtpView = $('auth-otp-view');
  const authPendingView = $('auth-pending-view');

  const tabLoginBtn = $('tab-login-btn'), tabSignupBtn = $('tab-signup-btn');
  const tabLoginPanel = $('tab-login-panel'), tabSignupPanel = $('tab-signup-panel');
  const formLogin = $('form-login'), loginEmail = $('login-email');
  const loginPassword = $('login-password'), loginFeedback = $('login-feedback');
  const btnSubmitLogin = $('btn-submit-login');
  const btnFillAdminDemo = $('btn-fill-admin-demo');

  const formSignup = $('form-signup'), signupEmail = $('signup-email');
  const signupPassword = $('signup-password');
  const signupFeedback = $('signup-feedback'), btnSubmitSignup = $('btn-submit-signup');
  const linkSwitchToSignup = $('link-switch-to-signup'), linkSwitchToLogin = $('link-switch-to-login');

  const formVerifyOtp = $('form-verify-otp'), otpCodeInput = $('otp-code-input');
  const otpFeedback = $('otp-feedback'), btnSubmitOtp = $('btn-submit-otp');
  const otpTargetEmailDisplay = $('otp-target-email-display');
  const btnResendOtp = $('btn-resend-otp'), btnBackToLoginFromOtp = $('btn-back-to-login-from-otp');

  const pendingAccountEmail = $('pending-account-email');
  const btnCheckApprovalStatus = $('btn-check-approval-status'), btnPendingSignout = $('btn-pending-signout');

  const adminModal = $('admin-modal'), adminModalSubtitle = $('admin-modal-subtitle');
  const btnCloseAdminModal = $('btn-close-admin-modal'), adminPendingTotal = $('admin-pending-total');
  const btnApproveAllUsers = $('btn-approve-all-users'), btnRefreshApprovals = $('btn-refresh-approvals');
  const adminActionFeedback = $('admin-action-feedback'), adminPendingList = $('admin-pending-list');

  const btnOpenIngestModal = $('btn-open-ingest-modal'), btnCloseIngestModal = $('btn-close-ingest-modal');
  const ingestModal = $('ingest-modal'), tabIngestFile = $('tab-ingest-file'), tabIngestText = $('tab-ingest-text');
  const fileUploadWrap = $('file-upload-wrap'), textUploadWrap = $('text-upload-wrap');
  const btnRunIngest = $('btn-run-ingest'), ingestBtnText = $('ingest-btn-text');
  const ingestStatusBox = $('ingest-status-box');

  const btnOpenOrgDocs = $('btn-open-org-docs'), btnViewQdrant = $('btn-view-qdrant');
  const qdrantModal = $('qdrant-modal'), btnCloseQdrantModal = $('btn-close-qdrant-modal');
  const qdrantModalContent = $('qdrant-modal-content');

  // Session
  let currentSession = null;
  let pendingVerificationEmail = localStorage.getItem('rag_pending_email') || '';
  try {
    const saved = localStorage.getItem('rag_session') || localStorage.getItem('rag_verifier_session');
    if (saved) currentSession = JSON.parse(saved);
  } catch (e) {}

  async function checkHealth() {
    try {
      const res = await fetch('/health');
      if (res.ok) {
        healthDot.className = 'status-dot online';
        healthLabel.textContent = 'API Connected';
      } else throw new Error('degraded');
    } catch {
      healthDot.className = 'status-dot offline';
      healthLabel.textContent = 'API Disconnected';
    }
  }
  checkHealth(); setInterval(checkHealth, 10000);

  async function loadOrganizations() {
    try {
      const res = await fetch('/api/v1/organizations');
      if (!res.ok) return;
      const data = await res.json();
      const orgs = data.organizations || [];
      if (orgOptions) {
        orgOptions.innerHTML = '';
        orgs.forEach(o => {
          const opt = document.createElement('option');
          opt.value = o;
          opt.textContent = `${getOrgDisplayName(o)} (${o})`;
          orgOptions.appendChild(opt);
        });
      }
      if (orgIdInput && !orgIdInput.value.trim() && orgs.length > 0) {
        orgIdInput.value = orgs[0];
      }
      if (orgIdInput && orgIdInput.value.trim()) {
        updateWorkbenchDocCount(orgIdInput.value.trim());
      }
    } catch (e) { console.warn('orgs load:', e); }
  }
  loadOrganizations();

  let docDebounce = null;
  async function updateWorkbenchDocCount(orgId) {
    if (!workbenchDocCount) return;
    if (!orgId || !orgId.trim()) { workbenchDocCount.textContent = '0'; return; }
    try {
      const res = await fetch(`/api/v1/documents/${encodeURIComponent(orgId.trim())}`);
      if (res.ok) {
        const data = await res.json();
        workbenchDocCount.textContent = (data.documents ? data.documents.length : 0);
      } else workbenchDocCount.textContent = '0';
    } catch { workbenchDocCount.textContent = '0'; }
  }

  function setTenant(orgId, userId) {
    if (orgIdInput && orgId) orgIdInput.value = orgId;
    if (userIdInput && userId) userIdInput.value = userId;
    const iorg = $('ingest-org-id'), iuser = $('ingest-user-id');
    const gten = $('google-chooser-tenant'), sgn = $('signup-org');
    if (iorg && orgId) iorg.value = orgId;
    if (iuser && userId) iuser.value = userId;
    if (gten && orgId) gten.value = orgId;
    if (sgn && orgId) sgn.value = orgId;
    updateWorkbenchDocCount(orgId);
  }

  orgIdInput?.addEventListener('input', () => {
    clearTimeout(docDebounce);
    docDebounce = setTimeout(() => setTenant(orgIdInput.value.trim(), userIdInput?.value || ''), 350);
  });

  btnNewOrg?.addEventListener('click', () => {
    if (orgIdInput) {
      orgIdInput.value = '';
      orgIdInput.placeholder = 'Type new Organization ID (e.g. my_project)...';
      orgIdInput.focus();
    }
    if (workbenchDocCount) workbenchDocCount.textContent = '0';
  });

  btnViewOrgDocs?.addEventListener('click', () => openOrgDocumentsViewer());

  async function updateAdminBadgeCount() {
    if (!currentSession || currentSession.role !== 'admin') {
      if (btnOpenAdminModal) btnOpenAdminModal.style.display = 'none';
      return;
    }
    try {
      const res = await fetch(`/api/v1/admin/pending-users?admin_id=${encodeURIComponent(currentSession.username)}`);
      if (res.ok) {
        const data = await res.json();
        const n = data.total_pending || 0;
        if (adminPendingBadge) adminPendingBadge.textContent = n;
        if (btnOpenAdminModal) btnOpenAdminModal.style.display = 'inline-flex';
      } else {
        if (btnOpenAdminModal) btnOpenAdminModal.style.display = 'none';
      }
    } catch {}
  }

  function renderSessionUI(syncInputs = true) {
    if (!currentSession) {
      if (userBadgeWrap) userBadgeWrap.style.display = 'none';
      if (btnOpenAdminModal) btnOpenAdminModal.style.display = 'none';
      if (authActionText) authActionText.textContent = 'Sign In / Register';
      return;
    }
    if (userBadgeWrap) userBadgeWrap.style.display = 'inline-flex';
    const uDisplay = document.getElementById('session-username-display');
    const rDisplay = document.getElementById('session-role-display');
    const oDisplay = document.getElementById('session-org-display');

    if (uDisplay) {
      if (currentSession.auth_provider === 'google') {
        uDisplay.innerHTML = `<span class="sso-badge-google">G</span> ${escapeHtml(currentSession.username)}`;
      } else {
        uDisplay.textContent = currentSession.username || currentSession.email || 'User';
      }
    }
    if (rDisplay) {
      rDisplay.textContent = (currentSession.role || 'member').toUpperCase();
      rDisplay.className = `user-badge-role ${currentSession.role === 'admin' ? 'role-admin' : 'role-user'}`;
    }
    if (oDisplay) {
      oDisplay.textContent = getOrgDisplayName(currentSession.org_id || 'default_org');
    }

    if (sessionUsername) {
      if (currentSession.auth_provider === 'google') {
        sessionUsername.innerHTML = `<span class="sso-badge-google">G</span> ${escapeHtml(currentSession.username)}`;
      } else {
        sessionUsername.textContent = currentSession.username;
      }
    }
    if (sessionRole) {
      sessionRole.textContent = currentSession.role.toUpperCase();
      sessionRole.className = `user-badge-role ${currentSession.role === 'admin' ? 'role-admin' : 'role-user'}`;
    }
    if (sessionOrg) sessionOrg.textContent = getOrgDisplayName(currentSession.org_id);
    if (sessionStatus) {
      sessionStatus.textContent = currentSession.status.toUpperCase();
      sessionStatus.className = `status-tag ${currentSession.status}`;
    }

    // Strict UI hiding: If role !== 'admin', hide all admin-only elements
    if (currentSession.role !== 'admin') {
      document.querySelectorAll('.admin-only-feature').forEach(el => el.style.display = 'none');
    } else {
      document.querySelectorAll('.admin-only-feature').forEach(el => {
        if (el.tagName === 'A') el.style.display = 'inline-flex';
      });
    }
    if (authActionText) authActionText.textContent = 'Switch User / Logout';

    if (syncInputs) {
      userIdInput.value = currentSession.username;
      orgIdInput.value = currentSession.org_id;
      setTenant(currentSession.org_id, currentSession.username);
    }

    if (userStatusNotice && userStatusNoticeText) {
      userStatusNotice.style.display = 'flex';
      if (currentSession.status === 'pending') {
        userStatusNotice.className = 'user-notice-banner notice-pending';
        userStatusNoticeText.innerHTML = `<strong>Pending Approval:</strong> User <code>${escapeHtml(currentSession.username)}</code> requested access to <strong>${getOrgDisplayName(currentSession.org_id)}</strong>.`;
      } else if (currentSession.status === 'rejected') {
        userStatusNotice.className = 'user-notice-banner notice-rejected';
        userStatusNoticeText.innerHTML = `<strong>Access Denied:</strong> User <code>${escapeHtml(currentSession.username)}</code> was not approved.`;
      } else {
        userStatusNotice.className = 'user-notice-banner notice-approved';
        userStatusNoticeText.innerHTML = `<strong>Session:</strong> <code>${escapeHtml(currentSession.username)}</code> &bull; Role: <strong>${escapeHtml(currentSession.role.toUpperCase())}</strong> &bull; Org: <strong>${getOrgDisplayName(currentSession.org_id)}</strong> &bull; Status: <strong>Approved</strong>`;
      }
    }
    updateAdminBadgeCount();
  }

  // Initial auth status check on app open:
  if (!currentSession || currentSession.status !== 'approved') {
    renderSessionUI(false);
    if (currentSession && currentSession.status === 'pending') {
      openPendingScreen(currentSession.email || pendingVerificationEmail);
    } else {
      activateAuthTab('login');
      authModal?.showModal();
    }
  } else {
    renderSessionUI(true);
  }

  function showAuthView(viewName) {
    if (authCredentialsView) authCredentialsView.style.display = viewName === 'credentials' ? 'block' : 'none';
    if (authOtpView) authOtpView.style.display = viewName === 'otp' ? 'block' : 'none';
    if (authPendingView) authPendingView.style.display = viewName === 'pending' ? 'block' : 'none';

    const title = $('auth-modal-title');
    if (title) {
      if (viewName === 'otp') title.textContent = 'Email Verification';
      else if (viewName === 'pending') title.textContent = 'Account Status';
      else title.textContent = 'Account Access';
    }
  }

  function activateAuthTab(tab) {
    showAuthView('credentials');
    if (tab === 'signup') {
      tabSignupBtn?.classList.add('active');
      tabLoginBtn?.classList.remove('active');
      if (tabSignupPanel) tabSignupPanel.style.display = 'block';
      if (tabLoginPanel) tabLoginPanel.style.display = 'none';
      if (signupFeedback) signupFeedback.style.display = 'none';
    } else {
      tabLoginBtn?.classList.add('active');
      tabSignupBtn?.classList.remove('active');
      if (tabLoginPanel) tabLoginPanel.style.display = 'block';
      if (tabSignupPanel) tabSignupPanel.style.display = 'none';
      if (loginFeedback) loginFeedback.style.display = 'none';
    }
  }

  function openOtpScreen(email, msg = '') {
    pendingVerificationEmail = email;
    localStorage.setItem('rag_pending_email', email);
    if (otpTargetEmailDisplay) otpTargetEmailDisplay.textContent = email;
    if (otpCodeInput) { otpCodeInput.value = ''; }
    if (otpFeedback) {
      if (msg) {
        otpFeedback.style.display = 'block';
        otpFeedback.style.background = 'rgba(59, 130, 246, 0.15)';
        otpFeedback.style.border = '1px solid rgba(59, 130, 246, 0.4)';
        otpFeedback.style.color = '#93c5fd';
        otpFeedback.textContent = msg;
      } else {
        otpFeedback.style.display = 'none';
      }
    }
    showAuthView('otp');
    authModal?.showModal();
    setTimeout(() => otpCodeInput?.focus(), 100);
  }

  function openPendingScreen(email) {
    pendingVerificationEmail = email || pendingVerificationEmail;
    if (pendingAccountEmail) pendingAccountEmail.textContent = pendingVerificationEmail || 'Your Account';
    showAuthView('pending');
    authModal?.showModal();
  }

  tabLoginBtn?.addEventListener('click', () => activateAuthTab('login'));
  tabSignupBtn?.addEventListener('click', () => activateAuthTab('signup'));
  linkSwitchToSignup?.addEventListener('click', e => { e.preventDefault(); activateAuthTab('signup'); });
  linkSwitchToLogin?.addEventListener('click', e => { e.preventDefault(); activateAuthTab('login'); });
  btnBackToLoginFromOtp?.addEventListener('click', () => activateAuthTab('login'));
  btnPendingSignout?.addEventListener('click', () => {
    currentSession = null;
    localStorage.removeItem('rag_verifier_session');
    activateAuthTab('login');
  });

  btnFillAdminDemo?.addEventListener('click', () => {
    if (loginEmail) loginEmail.value = 'admin@local.rag';
    if (loginPassword) loginPassword.value = 'AdminPass2026!';
    if (loginFeedback) loginFeedback.style.display = 'none';
    loginPassword?.focus();
  });

  btnAuthAction?.addEventListener('click', () => {
    localStorage.removeItem('token');
    localStorage.removeItem('rag_user_token');
    localStorage.removeItem('rag_verifier_session');
    window.location.href = '/';
  });

  btnCloseAuthModal?.addEventListener('click', () => authModal?.close());
  authModal?.addEventListener('click', e => { if (e.target === authModal) authModal.close(); });

  // STEP 1: Registration Form submission -> POST /api/v1/auth/register
  formSignup?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = signupEmail.value.trim();
    const password = signupPassword.value;
    btnSubmitSignup.disabled = true;
    if (signupFeedback) signupFeedback.style.display = 'none';

    try {
      const res = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Registration failed');
      }
      openOtpScreen(email, data.message || 'Verification code sent to your email.');
    } catch (err) {
      if (signupFeedback) {
        signupFeedback.style.display = 'block';
        signupFeedback.style.background = 'rgba(239, 68, 68, 0.15)';
        signupFeedback.style.border = '1px solid rgba(239, 68, 68, 0.4)';
        signupFeedback.style.color = '#f87171';
        signupFeedback.textContent = err.message;
      }
    } finally {
      btnSubmitSignup.disabled = false;
    }
  });

  // STEP 2: Verify OTP submission -> POST /api/v1/auth/verify-otp
  formVerifyOtp?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const otp = otpCodeInput.value.trim();
    if (!pendingVerificationEmail) {
      activateAuthTab('signup');
      return;
    }
    btnSubmitOtp.disabled = true;
    if (otpFeedback) otpFeedback.style.display = 'none';

    try {
      const res = await fetch('/api/v1/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: pendingVerificationEmail, otp })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Invalid OTP code.');
      }
      // Status upgraded to PENDING_APPROVAL -> Redirect to Step 3 Waiting Screen
      openPendingScreen(pendingVerificationEmail);
    } catch (err) {
      if (otpFeedback) {
        otpFeedback.style.display = 'block';
        otpFeedback.style.background = 'rgba(239, 68, 68, 0.15)';
        otpFeedback.style.border = '1px solid rgba(239, 68, 68, 0.4)';
        otpFeedback.style.color = '#f87171';
        otpFeedback.textContent = err.message;
      }
    } finally {
      btnSubmitOtp.disabled = false;
    }
  });

  btnResendOtp?.addEventListener('click', async () => {
    if (!pendingVerificationEmail) return;
    try {
      btnResendOtp.textContent = 'Resending...';
      const res = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: pendingVerificationEmail, password: 'RenewOtpTempPass2026!' })
      });
      const data = await res.json();
      if (otpFeedback) {
        otpFeedback.style.display = 'block';
        otpFeedback.style.background = 'rgba(16, 185, 129, 0.15)';
        otpFeedback.style.border = '1px solid rgba(16, 185, 129, 0.4)';
        otpFeedback.style.color = '#34d399';
        otpFeedback.textContent = 'A new 6-digit verification code has been dispatched to your email.';
      }
    } catch (err) {
      if (otpFeedback) {
        otpFeedback.style.display = 'block';
        otpFeedback.style.background = 'rgba(239, 68, 68, 0.15)';
        otpFeedback.style.border = '1px solid rgba(239, 68, 68, 0.4)';
        otpFeedback.style.color = '#f87171';
        otpFeedback.textContent = 'Failed to resend OTP. Please try again.';
      }
    } finally {
      btnResendOtp.textContent = 'Resend code';
    }
  });

  // STEP 3: Pending Approval Check
  btnCheckApprovalStatus?.addEventListener('click', async () => {
    btnCheckApprovalStatus.disabled = true;
    btnCheckApprovalStatus.textContent = 'Checking Status...';
    try {
      const res = await fetch('/api/v1/auth/users');
      const data = await res.json();
      const users = data.users || [];
      const user = users.find(u => (u.email && u.email.toLowerCase() === pendingVerificationEmail.toLowerCase()) || u.username === pendingVerificationEmail);
      if (user && user.status === 'approved') {
        alert('🎉 Your account has been approved by the Administrator! Please sign in now.');
        activateAuthTab('login');
        if (loginEmail) loginEmail.value = pendingVerificationEmail;
        if (loginPassword) loginPassword.focus();
      } else if (user && user.status === 'rejected') {
        alert('Your registration request was rejected by the administrator.');
      } else {
        alert('Account Status: Still Pending Administrator Approval.\n\nYour account has verified email and is awaiting Administrator review. Access will be granted once approved.');
      }
    } catch (e) {
      alert('Could not verify approval status at this time. Please try again.');
    } finally {
      btnCheckApprovalStatus.disabled = false;
      btnCheckApprovalStatus.textContent = 'Check Approval Status';
    }
  });

  // User Login Form submission -> POST /api/v1/auth/login
  formLogin?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = loginEmail.value.trim();
    const password = loginPassword.value;
    btnSubmitLogin.disabled = true;
    if (loginFeedback) loginFeedback.style.display = 'none';

    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();

      if (res.status === 403) {
        const detail = data.detail || {};
        const code = typeof detail === 'object' ? detail.code : '';
        const targetEmail = (typeof detail === 'object' ? detail.email : null) || email;

        if (code === 'UNVERIFIED') {
          openOtpScreen(targetEmail, detail.message || 'Please verify your email with the 6-digit code.');
          return;
        }
        if (code === 'PENDING_APPROVAL' || res.status === 403) {
          openPendingScreen(targetEmail);
          return;
        }
      }

      if (!res.ok) {
        const msg = (typeof data.detail === 'string') ? data.detail : (data.detail?.message || data.message || 'Login failed');
        throw new Error(msg);
      }

      // Approved login
      currentSession = data.user;
      localStorage.setItem('rag_verifier_session', JSON.stringify(currentSession));
      if (data.token) localStorage.setItem('rag_user_token', data.token);
      renderSessionUI(true);
      authModal?.close();
    } catch (err) {
      if (loginFeedback) {
        loginFeedback.style.display = 'block';
        loginFeedback.style.background = 'rgba(239, 68, 68, 0.15)';
        loginFeedback.style.border = '1px solid rgba(239, 68, 68, 0.4)';
        loginFeedback.style.color = '#f87171';
        loginFeedback.textContent = err.message;
      }
    } finally {
      btnSubmitLogin.disabled = false;
    }
  });

  btnOpenAdminModal?.addEventListener('click', () => {
    adminActionFeedback.style.display = 'none';
    adminModal.showModal();
    loadAdminPendingUsers();
  });
  btnCloseAdminModal?.addEventListener('click', () => adminModal.close());
  adminModal?.addEventListener('click', e => { if (e.target === adminModal) adminModal.close(); });
  btnRefreshApprovals?.addEventListener('click', () => loadAdminPendingUsers());

  btnApproveAllUsers?.addEventListener('click', async () => {
    if (!currentSession || currentSession.role !== 'admin') return;
    if (!confirm('Approve all pending user requests across all organizations?')) return;
    try {
      btnApproveAllUsers.disabled = true;
      btnApproveAllUsers.textContent = 'Approving...';
      const res = await fetch(`/api/v1/admin/approve-all?admin_id=${encodeURIComponent(currentSession.username)}`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Bulk approval failed');
      adminActionFeedback.style.display = 'block';
      adminActionFeedback.style.background = 'rgba(16,185,129,0.15)';
      adminActionFeedback.style.border = '1px solid rgba(16,185,129,0.4)';
      adminActionFeedback.style.color = '#6ee7b7';
      adminActionFeedback.textContent = data.message || `Approved ${data.approved_count} user(s).`;
      loadAdminPendingUsers();
    } catch (err) {
      adminActionFeedback.style.display = 'block';
      adminActionFeedback.style.background = 'rgba(239,68,68,0.15)';
      adminActionFeedback.style.border = '1px solid rgba(239,68,68,0.4)';
      adminActionFeedback.style.color = '#fca5a5';
      adminActionFeedback.textContent = `${err.message}`;
    } finally {
      btnApproveAllUsers.disabled = false;
      btnApproveAllUsers.textContent = 'Approve All';
    }
  });

  async function loadAdminPendingUsers() {
    if (!currentSession || currentSession.role !== 'admin') return;
    if (adminModalSubtitle) adminModalSubtitle.innerHTML = `Admin: <strong>${escapeHtml(currentSession.username)}</strong> &bull; Multi-Org User Approval Authority`;
    adminPendingList.innerHTML = '<div style="text-align:center;padding:1.5rem;color:#94a3b8;">Loading...</div>';
    try {
      const res = await fetch(`/api/v1/admin/pending-users?admin_id=${encodeURIComponent(currentSession.username)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed');
      const users = data.pending_users || [];
      if (adminPendingTotal) adminPendingTotal.textContent = users.length;
      if (adminPendingBadge) adminPendingBadge.textContent = users.length;
      if (users.length === 0) {
        adminPendingList.innerHTML = '<div style="text-align:center;padding:2rem;color:#94a3b8;font-size:0.85rem;">No pending sign-ups.</div>';
        return;
      }
      let html = '';
      users.forEach(u => {
        html += `
          <div class="approval-user-card">
            <div class="approval-user-info">
              <div class="approval-user-name">
                ${escapeHtml(u.full_name || u.username)}
                <span style="font-family:monospace;font-size:0.76rem;color:#a5b4fc;">(@${escapeHtml(u.username)})</span>
                ${u.auth_provider === 'google' ? '<span class="sso-badge-google">G</span>' : ''}
              </div>
              <div class="approval-user-meta">
                <span>Email: ${escapeHtml(u.email || 'N/A')}</span> &bull;
                <span>Org: ${escapeHtml(u.org_id)}</span> &bull;
                <span>Time: ${escapeHtml(formatTimestamp(u.created_at))}</span>
              </div>
            </div>
            <div class="approval-actions">
              <button type="button" class="btn-approve" data-user="${escapeHtml(u.username)}">Approve</button>
              <button type="button" class="btn-reject" data-user="${escapeHtml(u.username)}">Reject</button>
            </div>
          </div>`;
      });
      adminPendingList.innerHTML = html;
      adminPendingList.querySelectorAll('.btn-approve').forEach(b => {
        b.addEventListener('click', () => handleApprovalDecision(b.dataset.user, 'approved'));
      });
      adminPendingList.querySelectorAll('.btn-reject').forEach(b => {
        b.addEventListener('click', () => handleApprovalDecision(b.dataset.user, 'rejected'));
      });
    } catch (err) {
      adminPendingList.innerHTML = `<div style="padding:1rem;color:#f87171;background:rgba(239,68,68,0.1);border-radius:8px;">Failed: ${escapeHtml(err.message)}</div>`;
    }
  }

  async function handleApprovalDecision(username, decision) {
    try {
      const res = await fetch('/api/v1/admin/approve-user', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ admin_id: currentSession.username, target_username: username, status: decision })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Approval failed');
      adminActionFeedback.style.display = 'block';
      adminActionFeedback.style.background = decision === 'approved' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)';
      adminActionFeedback.style.border = decision === 'approved' ? '1px solid rgba(16,185,129,0.4)' : '1px solid rgba(239,68,68,0.4)';
      adminActionFeedback.style.color = decision === 'approved' ? '#6ee7b7' : '#fca5a5';
      adminActionFeedback.textContent = `User '${username}' ${decision.toUpperCase()}.`;
      loadAdminPendingUsers();
    } catch (err) {
      adminActionFeedback.style.display = 'block';
      adminActionFeedback.style.background = 'rgba(239,68,68,0.15)';
      adminActionFeedback.style.border = '1px solid rgba(239,68,68,0.4)';
      adminActionFeedback.style.color = '#fca5a5';
      adminActionFeedback.textContent = `${err.message}`;
    }
  }

  renderSessionUI(true);

  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') verifyForm.requestSubmit();
  });

  
  // ─── Active Conversation & Chat History State (Requirement 3, 4, 5) ───
  let activeConversationId = localStorage.getItem('rag_active_conv_id') || null;
  let conversationHistory = []; // Array of {role: 'user'|'assistant', content: string}
  let conversationsCache = [];

  function getEffectiveUserId() {
    return (currentSession && (currentSession.user_id || currentSession.username || currentSession.email)) || userIdInput?.value.trim() || 'usr_admin';
  }

  function getEffectiveOrgId() {
    return (currentSession && currentSession.org_id) || orgIdInput?.value.trim() || 'psg';
  }

  const conversationsList = document.getElementById('conversations-list');
  const sidebarSearchInput = document.getElementById('sidebar-search-input');
  const btnClearChatSearch = document.getElementById('btn-clear-chat-search');
  const btnSidebarNewChat = document.getElementById('btn-sidebar-new-chat');
  const activeConversationTitle = document.getElementById('active-conversation-title');
  const btnRenameActiveChat = document.getElementById('btn-rename-active-chat');
  const sidebarConvCount = document.getElementById('sidebar-conv-count');
  const btnToggleSidebar = document.getElementById('btn-toggle-sidebar');
  const chatSidebar = document.getElementById('chat-sidebar');
  const chatStreamContainer = document.getElementById('chat-stream-container');
  const chatThread = document.getElementById('chat-thread');

  // Security Verification Modal elements (Requirement 2)
  const securityModal = document.getElementById('security-modal');
  const btnOpenSecurityModal = document.getElementById('btn-open-security-modal');
  const btnCloseSecurityModal = document.getElementById('btn-close-security-modal');
  const btnCloseSecurityFooter = document.getElementById('btn-close-security-footer');
  const securityStatusIndicator = document.getElementById('security-status-indicator');
  const securityOverallBadge = document.getElementById('security-overall-badge');

  // Sidebar toggle
  btnToggleSidebar?.addEventListener('click', () => {
    chatSidebar?.classList.toggle('collapsed');
  });

  // Security Modal events
  btnOpenSecurityModal?.addEventListener('click', () => {
    securityModal?.showModal();
  });
  btnCloseSecurityModal?.addEventListener('click', () => {
    securityModal?.close();
  });
  btnCloseSecurityFooter?.addEventListener('click', () => {
    securityModal?.close();
  });

  // Auto-resize query textarea
  queryInput?.addEventListener('input', () => {
    queryInput.style.height = 'auto';
    queryInput.style.height = Math.min(queryInput.scrollHeight, 180) + 'px';
  });

  // Enter to submit, Shift+Enter for newline
  queryInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      verifyForm?.requestSubmit();
    }
  });

  // ─── Conversations API Integration ───
  async function loadConversations(searchQuery = '') {
    if (!currentSession) return;
    const uId = getEffectiveUserId();
    const oId = getEffectiveOrgId();

    const headerOrgText = document.getElementById('active-org-header-text');
    if (headerOrgText) headerOrgText.textContent = oId;

    try {
      const url = `/api/v1/conversations?user_id=${encodeURIComponent(uId)}&org_id=${encodeURIComponent(oId)}${searchQuery ? '&search=' + encodeURIComponent(searchQuery) : ''}`;
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      conversationsCache = data.conversations || [];
      renderConversationsList(conversationsCache);
    } catch (err) {
      console.warn('Failed to load conversations:', err);
    }
  }

  function renderConversationsList(convs) {
    if (!conversationsList) return;
    if (sidebarConvCount) sidebarConvCount.textContent = convs.length;

    if (!convs || convs.length === 0) {
      conversationsList.innerHTML = '<div class="sidebar-empty-placeholder">No conversations yet.<br>Start a new chat below!</div>';
      return;
    }

    conversationsList.innerHTML = convs.map(c => {
      const isActive = c.conversation_id === activeConversationId;
      const d = new Date(c.updated_at * 1000);
      const timeStr = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
      return `
        <div class="conversation-item ${isActive ? 'active' : ''}" data-id="${escapeHtml(c.conversation_id)}">
          <div class="conv-item-left" title="${escapeHtml(c.title)}">
            <span class="conv-item-icon">💬</span>
            <span class="conv-title">${escapeHtml(c.title)}</span>
          </div>
          <div class="conv-actions">
            <button type="button" class="conv-btn btn-rename-conv" data-id="${escapeHtml(c.conversation_id)}" title="Rename">✏️</button>
            <button type="button" class="conv-btn btn-delete-conv" data-id="${escapeHtml(c.conversation_id)}" title="Delete">🗑️</button>
          </div>
        </div>
      `;
    }).join('');

    // Wire click events
    conversationsList.querySelectorAll('.conversation-item').forEach(el => {
      el.addEventListener('click', (e) => {
        if (e.target.closest('.conv-btn')) return;
        const cid = el.dataset.id;
        if (cid) selectConversation(cid);
      });
    });

    conversationsList.querySelectorAll('.btn-rename-conv').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const cid = btn.dataset.id;
        const conv = conversationsCache.find(x => x.conversation_id === cid);
        promptRenameConversation(cid, conv ? conv.title : '');
      });
    });

    conversationsList.querySelectorAll('.btn-delete-conv').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const cid = btn.dataset.id;
        deleteConversation(cid);
      });
    });
  }

  async function selectConversation(convId) {
    if (!convId) return;
    activeConversationId = convId;
    localStorage.setItem('rag_active_conv_id', convId);

    const uId = getEffectiveUserId();
    const oId = getEffectiveOrgId();

    try {
      const res = await fetch(`/api/v1/conversations/${encodeURIComponent(convId)}?user_id=${encodeURIComponent(uId)}&org_id=${encodeURIComponent(oId)}`);
      if (!res.ok) {
        startNewChat();
        return;
      }
      const data = await res.json();
      const conv = data.conversation || {};
      const messages = data.messages || [];

      if (activeConversationTitle) {
        activeConversationTitle.textContent = conv.title || 'Conversation';
      }

      // Rebuild message stream
      if (chatThread) {
        chatThread.innerHTML = '';
        conversationHistory = [];

        if (messages.length === 0) {
          showWelcomeCard();
        } else {
          messages.forEach(m => {
            if (m.role === 'user') {
              appendUserMessage(m.content);
              conversationHistory.push({ role: 'user', content: m.content });
            } else if (m.role === 'assistant') {
              const renderedHtml = renderMarkdown(m.content);
              appendAssistantMessage(renderedHtml, m.metadata || {}, m.metadata?.timing_ms || 0);
              conversationHistory.push({ role: 'assistant', content: m.content });
            }
          });
        }
      }

      // Highlight active in sidebar
      renderConversationsList(conversationsCache);
    } catch (err) {
      console.error('Error selecting conversation:', err);
    }
  }

  function startNewChat() {
    activeConversationId = null;
    conversationHistory = [];
    localStorage.removeItem('rag_active_conv_id');
    if (activeConversationTitle) activeConversationTitle.textContent = 'New Conversation';
    showWelcomeCard();
    renderConversationsList(conversationsCache);
    if (queryInput) {
      queryInput.value = '';
      queryInput.focus();
    }
  }

  function showWelcomeCard() {
    if (!chatThread) return;
    chatThread.innerHTML = `
      <div class="chat-assistant-box chat-welcome-card" id="chat-welcome-box">
        <div class="welcome-header">
          <span class="welcome-icon">🔒</span>
          <h3>Intelligent Secure Document Assistant</h3>
        </div>
        <p>
          Ask arbitrary natural-language questions, request complete document summaries, compare documents, or request step-by-step breakdowns, Tamil / Thanglish explanations, or Markdown tables. All answers are strictly grounded in your verified documents.
        </p>
        <div class="welcome-features-grid">
          <div class="feature-item">
            <strong>🛡️ 5-Gate Cryptographic Security</strong>
            <span>Two-tier MMR integrity, Voronoi cell DBV, and AEAD decryption.</span>
          </div>
          <div class="feature-item">
            <strong>💾 Persistent Conversation History</strong>
            <span>Conversations remembered across sessions with previous chat lookup.</span>
          </div>
          <div class="feature-item">
            <strong>⚡ Dynamic Document Routing</strong>
            <span>Automatic latest document summary and cross-document comparisons.</span>
          </div>
        </div>
      </div>
    `;
    const ansContent = document.getElementById('answer-content');
    if (ansContent) ansContent.innerHTML = '';
  }

  async function promptRenameConversation(convId, oldTitle) {
    const newTitle = prompt('Enter a new title for this conversation:', oldTitle);
    if (!newTitle || !newTitle.trim() || newTitle.trim() === oldTitle) return;

    const uId = getEffectiveUserId();
    const oId = getEffectiveOrgId();

    try {
      const res = await fetch(`/api/v1/conversations/${encodeURIComponent(convId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: uId, org_id: oId, title: newTitle.trim() })
      });
      if (res.ok) {
        if (convId === activeConversationId && activeConversationTitle) {
          activeConversationTitle.textContent = newTitle.trim();
        }
        loadConversations(sidebarSearchInput?.value.trim() || '');
      }
    } catch (err) {
      console.warn('Rename error:', err);
    }
  }

  btnRenameActiveChat?.addEventListener('click', () => {
    if (!activeConversationId) return;
    const conv = conversationsCache.find(x => x.conversation_id === activeConversationId);
    promptRenameConversation(activeConversationId, conv ? conv.title : (activeConversationTitle?.textContent || ''));
  });

  async function deleteConversation(convId) {
    if (!confirm('Are you sure you want to delete this conversation?')) return;
    const uId = getEffectiveUserId();
    const oId = getEffectiveOrgId();

    try {
      const res = await fetch(`/api/v1/conversations/${encodeURIComponent(convId)}?user_id=${encodeURIComponent(uId)}&org_id=${encodeURIComponent(oId)}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        if (convId === activeConversationId) {
          startNewChat();
        }
        loadConversations(sidebarSearchInput?.value.trim() || '');
      }
    } catch (err) {
      console.warn('Delete error:', err);
    }
  }

  btnSidebarNewChat?.addEventListener('click', startNewChat);

  // Search input with debounce
  let searchDebounce = null;
  sidebarSearchInput?.addEventListener('input', () => {
    const val = sidebarSearchInput.value.trim();
    if (btnClearChatSearch) btnClearChatSearch.style.display = val ? 'block' : 'none';
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => {
      loadConversations(val);
    }, 250);
  });

  btnClearChatSearch?.addEventListener('click', () => {
    if (sidebarSearchInput) sidebarSearchInput.value = '';
    if (btnClearChatSearch) btnClearChatSearch.style.display = 'none';
    loadConversations();
  });

  // Wire Quick Prompt Buttons
  document.querySelectorAll('.quick-prompt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (queryInput) {
        queryInput.value = btn.dataset.prompt || btn.textContent;
        queryInput.focus();
        queryInput.dispatchEvent(new Event('input'));
      }
    });
  });

  function appendUserMessage(text) {
    const thread = document.getElementById('chat-thread');
    if (!thread) return;
    const welcome = document.getElementById('chat-welcome-box');
    if (welcome) welcome.remove();

    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    bubble.innerHTML = `
      <div class="chat-bubble-header">
        <span class="chat-bubble-author"><span class="chat-avatar-user">You</span></span>
        <span>Just now</span>
      </div>
      <div class="chat-user-box">${escapeHtml(text)}</div>
    `;
    thread.appendChild(bubble);
    if (chatStreamContainer) chatStreamContainer.scrollTop = chatStreamContainer.scrollHeight;
  }

  function appendAssistantMessage(answerHtml, data, clientLat) {
    const thread = document.getElementById('chat-thread');
    if (!thread) return;
    const bd = data.verification_breakdown || {};
    const aclPassed = data.acl_verified ?? true;
    const integPassed = data.integrity_verified ?? true;
    const boundPassed = data.ivf_boundary_verification?.is_complete ?? true;
    const decPassed = data.decryption_verified ?? true;
    const groundPassed = !data.hallucination_report?.flagged;

    const sources = data.sources || [];
    let sourcesHtml = '';
    if (sources.length > 0) {
      sourcesHtml = '<div class="chat-sources-row">' + sources.map(s => `
        <span class="source-tag" title="${escapeHtml(s.doc_id)}">📄 ${escapeHtml(s.filename)} (${s.chunk_count} chunks)</span>
      `).join('') + '</div>';
    }

    // COMPACT RETRIEVAL SUMMARY (Requirement 1: Total chunks, chunk #, cluster #, NO chunk text/similarity/hashes!)
    const rSummary = data.retrieval_summary || {};
    const totalChunks = rSummary.total_chunks ?? (data.retrieved_chunks_count || (data.decrypted_chunks ? data.decrypted_chunks.length : 0));
    const chunksList = rSummary.chunks || (data.decrypted_chunks || []).map((c, i) => ({
      chunk_number: c.chunk_index || (i + 1),
      cluster_id: c.cluster_id || '0'
    }));

    let compactRetrievalHtml = '';
    if (totalChunks > 0 && chunksList.length > 0) {
      const chips = chunksList.map(c => `
        <span class="retrieval-chip">#${c.chunk_number} &middot; Cluster ${escapeHtml(c.cluster_id)}</span>
      `).join('');
      compactRetrievalHtml = `
        <div class="compact-retrieval-summary">
          <div class="retrieval-summary-header">
            <span>📦 Retrieved Context: <strong>${totalChunks} Chunks</strong></span>
          </div>
          <div class="retrieval-chips-container">
            ${chips}
          </div>
        </div>
      `;
    }

    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    bubble.innerHTML = `
      <div class="chat-bubble-header">
        <span class="chat-bubble-author"><span class="chat-avatar-assistant">AI</span> Secure Assistant</span>
        <span>${data.execution_time_ms || clientLat} ms</span>
      </div>
      <div class="chat-assistant-box">
        ${answerHtml}
        ${compactRetrievalHtml}
        <div class="chat-meta-bar">
          <div class="chat-gates-summary">
            <button type="button" class="chat-gate-chip ${aclPassed ? 'pass' : 'fail'}" onclick="document.getElementById('btn-open-security-modal')?.click()" title="Gate 1 ACL">G1 ACL</button>
            <button type="button" class="chat-gate-chip ${integPassed ? 'pass' : 'fail'}" onclick="document.getElementById('btn-open-security-modal')?.click()" title="Gate 2 MMR Integrity">G2 MMR</button>
            <button type="button" class="chat-gate-chip ${boundPassed ? 'pass' : 'fail'}" onclick="document.getElementById('btn-open-security-modal')?.click()" title="Gate 3 Dynamic Boundary">G3 DBV</button>
            <button type="button" class="chat-gate-chip ${decPassed ? 'pass' : 'fail'}" onclick="document.getElementById('btn-open-security-modal')?.click()" title="Gate 4 AEAD Decryption">G4 AEAD</button>
            <button type="button" class="chat-gate-chip ${groundPassed ? 'pass' : 'fail'}" onclick="document.getElementById('btn-open-security-modal')?.click()" title="Gate 5 Grounding">G5 NLI</button>
          </div>
          ${sourcesHtml}
        </div>
      </div>
    `;
    thread.appendChild(bubble);
    if (chatStreamContainer) chatStreamContainer.scrollTop = chatStreamContainer.scrollHeight;
  }

  verifyForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!currentSession || currentSession.status !== 'approved') {
      if (currentSession && currentSession.status === 'pending') {
        openPendingScreen(currentSession.email || pendingVerificationEmail);
      } else {
        activateAuthTab('login');
        authModal?.showModal();
      }
      return;
    }

    const q = queryInput.value.trim();
    if (!q) return;

    btnSubmit.classList.add('loading');
    btnSubmit.disabled = true;

    if (verdictBadge) verdictBadge.textContent = 'VERIFYING...';
    if (verdictHeadline) verdictHeadline.textContent = 'Auditing 5 Security Gates...';
    if (verdictSubtext) verdictSubtext.textContent = 'Verifying ACL, Merkle proofs, Voronoi boundary, and AEAD decryption...';
    if (verdictBanner) verdictBanner.className = 'verdict-banner';

    if (answerContent) answerContent.innerHTML = '<p class="placeholder-text">Searching documents...</p>';

    // 1. Render User Message to conversational thread
    appendUserMessage(q);
    queryInput.value = '';
    queryInput.style.height = 'auto';

    // 2. Build payload with conversation_id & history for ChatGPT-like multi-turn context
    const payload = {
      query_text: q,
      user_id: getEffectiveUserId(),
      org_id: getEffectiveOrgId(),
      conversation_id: activeConversationId,
      simulate_missing_cluster: false,
      simulate_integrity_failure: false,
      conversation_history: conversationHistory
    };
    const t0 = performance.now();

    try {
      const userToken = localStorage.getItem('token') || localStorage.getItem('rag_user_token') || '';
      const res = await fetch('/api/v1/query-verify', {
        method: 'POST', headers: {
          'Content-Type': 'application/json',
          'Authorization': userToken ? ('Bearer ' + userToken) : ''
        },
        body: JSON.stringify(payload)
      });
      const clientLat = Math.round(performance.now() - t0);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: 'HTTP ' + res.status }));
        renderBackendError(errData.detail || `Server returned status ${res.status}`, res.status);
        return;
      }
      const data = await res.json();

      // Update active conversation ID if newly created on backend
      if (data.conversation_id) {
        activeConversationId = data.conversation_id;
        localStorage.setItem('rag_active_conv_id', activeConversationId);
      }

      try {
        renderVerificationResults(data, clientLat);
      } catch (renderErr) {
        console.error('Rendering error in renderVerificationResults:', renderErr);
        renderFrontendDisplayError(renderErr.message);
      }

      // Refresh sidebar list so new/updated conversations display with auto-title
      loadConversations(sidebarSearchInput?.value.trim() || '');
    } catch (networkErr) {
      console.error('Network / fetch err:', networkErr);
      renderNetworkError(networkErr.message);
    } finally {
      btnSubmit.classList.remove('loading');
      btnSubmit.disabled = false;
    }
  });

  function renderVerificationResults(data, clientLat) {
    const lat = data.execution_time_ms || clientLat;
    if (verdictTiming) verdictTiming.textContent = `Latency: ${lat} ms`;

    // Populate stage-wise latency profile chips in Security modal
    const timings = data.stage_timings_ms || data.verification_breakdown?.stage_timings_ms;
    if (timings) {
      const setTime = (id, val) => {
        const el = $(id);
        if (el) el.textContent = (val !== undefined && val !== null) ? `${val} ms` : '--';
      };
      setTime('time-query-embed', timings.query_embedding_ms);
      setTime('time-qdrant', timings.qdrant_retrieval_ms);
      setTime('time-dbv', timings.dbv_boundary_verify_ms);
      setTime('time-mmr', timings.mmr_proof_verify_ms);
      setTime('time-aead', timings.aead_decrypt_ms);
      setTime('time-rerank', timings.hybrid_reranking_ms);
      setTime('time-llm', timings.llm_generation_ms);
      setTime('time-grounding', timings.grounding_evaluation_ms);
      setTime('time-total-e2e', timings.total_e2e_ms || lat);
    }
    const bd = data.verification_breakdown || {};
    const acl = bd.acl || { passed: data.acl_verified ?? true };
    const integ = bd.integrity || { passed: data.integrity_verified };
    const dec = bd.decryption || { passed: data.decryption_verified ?? true };
    const bound = bd.boundary || {
      passed: data.ivf_boundary_verification?.is_complete ?? true,
      coverage_ratio: data.ivf_boundary_verification?.coverage_ratio ?? 1.0,
      required_clusters: data.ivf_boundary_verification?.required_clusters || [],
      retrieved_clusters: data.ivf_boundary_verification?.retrieved_clusters || [],
      missing_clusters: data.ivf_boundary_verification?.missing_clusters || []
    };
    const ground = bd.grounding || {
      passed: !data.hallucination_report?.flagged,
      grounding_score: data.hallucination_report?.grounding_score || 0.0
    };

    const isSuccess = data.status === 'SUCCESS' && !data.hallucination_report?.flagged
      && integ.passed && bound.passed && acl.passed;

    // Update Live Security Status Indicator on top-right button
    if (securityStatusIndicator) {
      securityStatusIndicator.className = 'security-status-indicator ' + (isSuccess ? 'pass' : 'fail');
      securityStatusIndicator.title = `Security Verification: ${isSuccess ? 'PASS' : 'FAIL'}`;
    }
    if (securityOverallBadge) {
      securityOverallBadge.className = 'security-overall-badge ' + (isSuccess ? 'pass' : 'fail');
      securityOverallBadge.textContent = isSuccess ? 'PASS' : 'FAIL';
    }

    if (verdictBanner) {
      if (isSuccess) {
        verdictBanner.className = 'verdict-banner verdict-success';
        if (verdictBadge) verdictBadge.textContent = 'VERIFIED & SECURE';
        if (verdictHeadline) verdictHeadline.textContent = 'All 5 Security Gates Passed';
        if (verdictSubtext) verdictSubtext.textContent = 'ACL, MMR cryptographic proof, Voronoi cell boundary, and AEAD decryption fully verified.';
      } else if (!acl.passed || data.status === 'ACL_VIOLATION') {
        verdictBanner.className = 'verdict-banner verdict-fail';
        if (verdictBadge) verdictBadge.textContent = 'ACL_BLOCKED';
        if (verdictHeadline) verdictHeadline.textContent = 'Gate 1 Failure: Multi-Tenant Access Blocked';
        if (verdictSubtext) verdictSubtext.textContent = data.hallucination_report?.reason || acl.details || 'Access denied: Cross-tenant isolation block.';
      } else if (!integ.passed || data.status === 'MMR_TAMPERED') {
        verdictBanner.className = 'verdict-banner verdict-fail';
        if (verdictBadge) verdictBadge.textContent = 'TAMPERED';
        if (verdictHeadline) verdictHeadline.textContent = 'Gate 2 Failure: MMR Tampering Detected';
        if (verdictSubtext) verdictSubtext.textContent = data.hallucination_report?.reason || 'Cryptographic Merkle tree verification failed.';
      } else if (!bound.passed || data.status === 'IVF_BOUNDARY_INCOMPLETENESS') {
        verdictBanner.className = 'verdict-banner verdict-fail';
        if (verdictBadge) verdictBadge.textContent = 'BOUNDARY_INCOMPLETE';
        if (verdictHeadline) verdictHeadline.textContent = 'Gate 3 Failure: Voronoi Boundary Incomplete';
        if (verdictSubtext) verdictSubtext.textContent = data.hallucination_report?.reason || 'IVF Voronoi boundary incomplete.';
      } else {
        verdictBanner.className = 'verdict-banner verdict-fail';
        if (verdictBadge) verdictBadge.textContent = data.status;
        if (verdictHeadline) verdictHeadline.textContent = `Verification Halted: ${data.status}`;
        if (verdictSubtext) verdictSubtext.textContent = data.hallucination_report?.reason || 'Verification failure.';
      }
    }

    updateGateCard(cardGateAcl, pillGateAcl, detailGateAcl, acl.passed,
      acl.passed ? 'PASS' : 'BLOCKED', acl.details || (acl.passed ? 'ACL verified.' : 'ACL denied.'));
    if (metaAclUser) metaAclUser.textContent = acl.user_id || userIdInput.value;
    if (metaAclOrg) metaAclOrg.textContent = acl.org_id || orgIdInput.value;

    updateGateCard(cardGateIntegrity, pillGateIntegrity, detailGateIntegrity, integ.passed,
      integ.passed ? 'VALID' : 'TAMPERED', integ.details || (integ.passed ? 'MMR proof verified.' : 'MMR mismatch.'));
    if (metaIntegrityRoot) metaIntegrityRoot.textContent = integ.passed ? (integ.enterprise_root || 'VERIFIED') : 'HASH MISMATCH!';

    const cov = (bound.coverage_ratio ?? 1.0) * 100;
    const bPass = bound.passed && integ.passed && acl.passed;
    updateGateCard(cardGateBoundary, pillGateBoundary, detailGateBoundary, bPass,
      bPass ? `${cov.toFixed(0)}%` : (!integ.passed ? 'HALTED' : 'DROPPED'),
      bound.details || (bPass ? 'Voronoi boundary complete.' : 'Incomplete.'));
    const miss = bound.missing_clusters || [];
    if (rowMissing) {
      if (miss.length > 0 && bPass) {
        rowMissing.style.display = 'flex';
        if (tagsMissing) tagsMissing.innerHTML = miss.map(c => `<span class="c-tag missing">C-${c}</span>`).join('');
      } else rowMissing.style.display = 'none';
    }

    const dPass = dec.passed && integ.passed && acl.passed;
    updateGateCard(cardGateDecryption, pillGateDecryption, detailGateDecryption, dPass,
      dPass ? 'DECRYPTED' : 'HALTED', dec.details || (dPass ? 'AEAD decryption OK.' : 'Decryption halted.'));
    const cnt = (!integ.passed || !data.acl_verified) ? 0 : (data.retrieved_chunks_count ?? 0);
    if (metaDecryptedCount) metaDecryptedCount.textContent = dPass ? `${cnt} chunks` : '0 chunks';

    const score = ground.grounding_score || 0.0;
    const scorePct = (score * 100).toFixed(1);
    const gPass = ground.passed && integ.passed && bound.passed && isSuccess;
    updateGateCard(cardGateGrounding, pillGateGrounding, detailGateGrounding, gPass,
      gPass ? `${scorePct}%` : 'HALTED', ground.details || (gPass ? 'Grounded.' : 'Grounding failed.'));
    if (meterScoreText) meterScoreText.textContent = gPass ? score.toFixed(4) : '0.0000';

    if (maskedQueryVal) maskedQueryVal.textContent = data.masked_query || queryInput.value;

    if (answerContent) {
      if (data.status === 'ACL_VIOLATION' || !data.acl_verified) {
        answerContent.innerHTML = `<div style="color:#f87171;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);padding:14px 16px;border-radius:6px;"><strong>Cross-Tenant Access Blocked:</strong> ${escapeHtml(data.answer || 'Access denied.')}</div>`;
      } else if (!integ.passed || data.status === 'MMR_TAMPERED') {
        answerContent.innerHTML = `<div style="color:#f87171;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:14px 16px;border-radius:6px;"><strong>Security Alert - Tampering Detected:</strong> MMR integrity failure. Decryption halted.</div>`;
      } else if (!bound.passed || data.status === 'IVF_BOUNDARY_INCOMPLETENESS') {
        answerContent.innerHTML = `<div style="color:#fbbf24;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);padding:14px 16px;border-radius:6px;"><strong>Boundary Incomplete:</strong> Missing clusters [${miss.join(', ')}].</div>`;
      } else if (data.answer) {
        const renderedAns = renderMarkdown(data.answer);
        if (answerContent) answerContent.innerHTML = renderedAns;
        // Append to conversation thread & record in history
        appendAssistantMessage(renderedAns, data, lat);
        conversationHistory.push({ role: 'user', content: queryInput.value.trim() });
        conversationHistory.push({ role: 'assistant', content: data.answer });
      } else {
        answerContent.innerHTML = `<div style="color:#f87171;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:12px 14px;border-radius:6px;"><strong>Blocked:</strong> ${escapeHtml(data.hallucination_report?.reason || 'No verified context.')}</div>`;
      }
    }

    const chunks = (!integ.passed || !data.acl_verified) ? [] : (data.decrypted_chunks || []);
    if (chunksCountBadge) chunksCountBadge.textContent = chunks.length;
    if (metricChunksBadge) metricChunksBadge.textContent = `${chunks.length} Chunks`;
    if (chunksList) {
      chunksList.innerHTML = `<div class="compact-hidden-chunks">Total: ${chunks.length} chunks</div>`;
    }
  }

  // Load initial conversations on page load
  loadConversations();
  if (activeConversationId) {
    selectConversation(activeConversationId);
  }

  function updateGateCard(card, pill, detail, passed, pillText, detailText) {
    if (card) {
      card.classList.remove('gate-pass', 'gate-fail');
      card.classList.add(passed ? 'gate-pass' : 'gate-fail');
    }
    if (pill) {
      pill.textContent = pillText || (passed ? 'PASS' : 'FAIL');
      pill.className = `gate-ribbon-pill ${passed ? 'pass' : 'fail'}`;
    }
    if (detail && detailText) detail.textContent = detailText;
  }

  function renderBackendError(msg, statusCode) {
    if (securityStatusIndicator) {
      securityStatusIndicator.className = 'security-status-indicator fail';
      securityStatusIndicator.title = `Backend Server Error (${statusCode})`;
    }
    if (securityOverallBadge) {
      securityOverallBadge.className = 'security-overall-badge fail';
      securityOverallBadge.textContent = 'SERVER_ERROR';
    }
    if (verdictBanner) verdictBanner.className = 'verdict-banner verdict-fail';
    if (verdictBadge) verdictBadge.textContent = `HTTP ${statusCode}`;
    if (verdictHeadline) verdictHeadline.textContent = 'Backend Service Error';
    if (verdictSubtext) verdictSubtext.textContent = msg;
    if (answerContent) {
      answerContent.innerHTML = `<div style="color:#f87171;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:14px 16px;border-radius:6px;"><strong>Server Error (HTTP ${statusCode}):</strong> ${escapeHtml(msg)}</div>`;
    }
  }

  function renderNetworkError(msg) {
    if (securityStatusIndicator) {
      securityStatusIndicator.className = 'security-status-indicator fail';
      securityStatusIndicator.title = 'Network Connection Error';
    }
    if (securityOverallBadge) {
      securityOverallBadge.className = 'security-overall-badge fail';
      securityOverallBadge.textContent = 'NETWORK_ERROR';
    }
    if (verdictBanner) verdictBanner.className = 'verdict-banner verdict-fail';
    if (verdictBadge) verdictBadge.textContent = 'NETWORK ERROR';
    if (verdictHeadline) verdictHeadline.textContent = 'Network Connection Failed';
    if (verdictSubtext) verdictSubtext.textContent = msg || 'Could not reach the RAG API server.';
    if (answerContent) {
      answerContent.innerHTML = `<div style="color:#f87171;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:14px 16px;border-radius:6px;"><strong>Network Error:</strong> Unable to connect to server. (${escapeHtml(msg)})</div>`;
    }
  }

  function renderFrontendDisplayError(msg) {
    console.warn('Frontend presentation exception caught:', msg);
    // Never mark security gates as failed or report API failure when backend succeeded
    if (answerContent && (!answerContent.innerHTML || !answerContent.innerHTML.trim())) {
      answerContent.innerHTML = `<div style="color:#f59e0b;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);padding:12px 14px;border-radius:6px;"><strong>UI Display Notice:</strong> Response was cryptographically verified by backend, but encountered a client-side display error: ${escapeHtml(msg)}</div>`;
    }
  }

  function renderPipelineError(msg) {
    if (verdictBanner) verdictBanner.className = 'verdict-banner verdict-fail';
    if (verdictBadge) verdictBadge.textContent = 'PIPELINE ERROR';
    if (verdictHeadline) verdictHeadline.textContent = 'Pipeline Request Failed';
    if (verdictSubtext) verdictSubtext.textContent = msg;
    if (answerContent) {
      answerContent.innerHTML = `<div style="color:#f87171;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:12px 14px;border-radius:6px;"><strong>Failed:</strong> ${escapeHtml(msg)}</div>`;
    }
  }

  btnCopyAnswer?.addEventListener('click', () => {
    const t = answerContent?.innerText;
    if (t) navigator.clipboard.writeText(t).then(() => {
      const s = btnCopyAnswer.querySelector('span');
      if (s) { const o = s.textContent; s.textContent = 'Copied!'; setTimeout(() => s.textContent = o, 1500); }
    });
  });

  if (btnOpenIngestModal && ingestModal) {
    const ingestOrg = $('ingest-org-id'), ingestUser = $('ingest-user-id');
    if (ingestOrg && ingestUser) {
      ingestOrg.addEventListener('input', () => {
        const v = ingestOrg.value.trim();
        if (v) {
          const clean = v.replace(/^org_/, '').replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
          ingestUser.value = `usr_${clean || 'admin'}`;
        }
      });
    }
    btnOpenIngestModal.addEventListener('click', () => {
      if (ingestOrg && orgIdInput) ingestOrg.value = orgIdInput.value.trim() || '';
      if (ingestUser && userIdInput) ingestUser.value = userIdInput.value.trim() || 'usr_admin';
      if (ingestStatusBox) ingestStatusBox.style.display = 'none';
      ingestModal.showModal();
    });
  }
  if (btnCloseIngestModal && ingestModal) {
    btnCloseIngestModal.addEventListener('click', () => ingestModal.close());
    ingestModal.addEventListener('click', e => { if (e.target === ingestModal) ingestModal.close(); });
  }
  if (tabIngestFile && tabIngestText) {
    tabIngestFile.addEventListener('click', () => {
      tabIngestFile.classList.add('active'); tabIngestText.classList.remove('active');
      if (fileUploadWrap) fileUploadWrap.style.display = 'block';
      if (textUploadWrap) textUploadWrap.style.display = 'none';
    });
    tabIngestText.addEventListener('click', () => {
      tabIngestText.classList.add('active'); tabIngestFile.classList.remove('active');
      if (fileUploadWrap) fileUploadWrap.style.display = 'none';
      if (textUploadWrap) textUploadWrap.style.display = 'block';
    });
  }

  const ingestFileInput = $('ingest-file-input');
  if (ingestFileInput) {
    ingestFileInput.addEventListener('change', () => {
      if (ingestFileInput.files && ingestFileInput.files.length > 0) {
        const fname = ingestFileInput.files[0].name;
        const clean = 'doc_' + fname.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
        const di = $('ingest-doc-id');
        if (di) di.value = clean;
      }
    });
  }

  if (btnRunIngest) {
    btnRunIngest.addEventListener('click', async () => {
      let docId = $('ingest-doc-id').value.trim();
      const userId = $('ingest-user-id').value.trim() || 'usr_admin';
      const orgId = $('ingest-org-id').value.trim() || (orgIdInput ? orgIdInput.value.trim() : '') || 'default_org';
      ingestBtnText.textContent = 'Encrypting & Indexing...';
      btnRunIngest.disabled = true;
      if (ingestStatusBox) ingestStatusBox.style.display = 'none';
      try {
        let result;
        const isFile = tabIngestFile.classList.contains('active');
        if (isFile) {
          const fi = $('ingest-file-input');
          if (!fi.files || fi.files.length === 0) throw new Error('Select a PDF or TXT file.');
          const file = fi.files[0];
          if (!docId) docId = 'doc_' + file.name.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
          const fd = new FormData();
          fd.append('file', file); fd.append('doc_id', docId);
          fd.append('user_id', userId); fd.append('org_id', orgId);
          fd.append('chunk_size', '500'); fd.append('overlap', '50');
          const userToken = localStorage.getItem('token') || localStorage.getItem('rag_user_token') || '';
          const res = await fetch('/api/v1/ingest-document', {
            method: 'POST',
            headers: userToken ? { 'Authorization': 'Bearer ' + userToken } : {},
            body: fd
          });
          if (!res.ok) { const err = await res.json(); throw new Error(err.detail || 'File ingest failed'); }
          result = await res.json();
        } else {
          const ti = $('ingest-text-input');
          const text = ti.value.trim();
          if (!text) throw new Error('Enter plaintext to ingest.');
          const userToken = localStorage.getItem('token') || localStorage.getItem('rag_user_token') || '';
          const res = await fetch('/api/v1/ingest-text', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': userToken ? ('Bearer ' + userToken) : ''
            },
            body: JSON.stringify({ text, doc_id: docId, user_id: userId, org_id: orgId, chunk_size: 500, overlap: 50, filename: `${docId}.txt` })
          });
          if (!res.ok) { const err = await res.json(); throw new Error(err.detail || 'Text ingest failed'); }
          result = await res.json();
        }
        ingestStatusBox.style.display = 'block';
        ingestStatusBox.style.background = 'rgba(16,185,129,0.12)';
        ingestStatusBox.style.border = '1px solid rgba(16,185,129,0.35)';
        ingestStatusBox.style.color = '#34d399';
        ingestStatusBox.innerHTML = `
          <strong>Ingested Successfully</strong><br/>
          • <strong>${result.total_chunks} chunks</strong> created<br/>
          • <strong>${result.qdrant_points_upserted} points</strong> indexed
          <div style="margin-top:8px;"><button type="button" id="btn-quick-one-line" class="preset-btn">Summarize in one line</button></div>`;
        const qb = $('btn-quick-one-line');
        if (qb) qb.addEventListener('click', () => {
          queryInput.value = 'Summarize this document in one line.';
          queryInput.focus(); queryInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
          ingestModal.close();
        });
        userIdInput.value = userId;
        orgIdInput.value = orgId;
        setTenant(orgId, userId);
        loadOrganizations();
        updateWorkbenchDocCount(orgId);
      } catch (err) {
        ingestStatusBox.style.display = 'block';
        ingestStatusBox.style.background = 'rgba(239,68,68,0.12)';
        ingestStatusBox.style.border = '1px solid rgba(239,68,68,0.35)';
        ingestStatusBox.style.color = '#f87171';
        ingestStatusBox.innerHTML = `<strong>Error:</strong> ${escapeHtml(err.message)}`;
      } finally {
        ingestBtnText.textContent = 'Upload & Ingest';
        btnRunIngest.disabled = false;
      }
    });
  }

  async function openOrgDocumentsViewer() {
    if (!qdrantModal || !qdrantModalContent) return;
    const orgId = (orgIdInput && orgIdInput.value.trim()) || 'default_org';
    const disp = getOrgDisplayName(orgId);
    const titleEl = $('qdrant-modal-title');
    if (titleEl) titleEl.textContent = `Documents in ${disp} (${orgId})`;
    qdrantModalContent.innerHTML = `<p style="color:#a5b4fc;padding:1rem;">Loading...</p>`;
    qdrantModal.showModal();
    try {
      const res = await fetch(`/api/v1/documents/${encodeURIComponent(orgId)}`);
      if (!res.ok) { const err = await res.json().catch(() => ({ detail: 'HTTP ' + res.status })); throw new Error(err.detail || 'Failed'); }
      const data = await res.json();
      const docs = data.documents || [];
      if (docs.length === 0) {
        qdrantModalContent.innerHTML = `
          <div style="padding:2rem;text-align:center;color:var(--text-secondary);">
            <h4 style="margin:0 0 0.4rem 0;font-size:1rem;color:var(--text-primary);">No documents stored for ${escapeHtml(disp)}</h4>
            <p style="font-size:0.82rem;margin-bottom:1rem;">Upload a document to this organization.</p>
            <button type="button" id="btn-modal-go-ingest" class="submit-btn" style="max-width:200px;margin:0 auto;">Upload Document</button>
          </div>`;
        const g = $('btn-modal-go-ingest');
        if (g) g.addEventListener('click', () => { qdrantModal.close(); btnOpenIngestModal?.click(); });
        return;
      }
      let html = `
        <div style="margin-bottom:1rem;padding:0.85rem 1rem;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.25);border-radius:8px;display:flex;justify-content:space-between;align-items:center;gap:10px;">
          <div>
            <div style="font-weight:600;color:var(--text-primary);font-size:0.9rem;">${docs.length} Document(s) &bull; ${data.total_chunks} Chunks</div>
            <div style="font-size:0.72rem;color:var(--text-secondary);margin-top:2px;">Org: <strong>${escapeHtml(disp)}</strong> &bull; AES-256-GCM</div>
          </div>
          <div style="display:flex;gap:8px;">
            <input type="text" id="doc-search-filter" placeholder="Filter..." style="padding:5px 10px;font-size:0.78rem;width:170px;" />
            <button type="button" id="btn-purge-collection" class="preset-btn" style="color:var(--color-danger);">Delete All</button>
          </div>
        </div>
        <div id="docs-card-list" style="display:flex;flex-direction:column;gap:10px;">`;
      docs.forEach(doc => {
        html += `
          <div class="org-doc-card" data-doc-title="${escapeHtml((doc.filename || '').toLowerCase())}" data-doc-text="${escapeHtml((doc.full_text || '').slice(0, 300).toLowerCase())}">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;border-bottom:1px solid var(--border-color);padding-bottom:8px;">
              <div>
                <div style="display:flex;align-items:center;gap:8px;">
                  <h4 style="margin:0;font-size:0.92rem;color:var(--text-primary);font-weight:600;">${escapeHtml(doc.filename)}</h4>
                  <span class="chunk-badge">Encrypted</span>
                </div>
                <div style="font-size:0.74rem;color:var(--text-secondary);margin-top:4px;display:flex;flex-wrap:wrap;gap:10px;">
                  <span>Doc ID: <code>${escapeHtml(doc.doc_id)}</code></span>
                  <span>Chunks: ${doc.total_chunks}</span>
                  <span>User: <code>${escapeHtml(doc.user_id)}</code></span>
                </div>
              </div>
              <div style="display:flex;gap:6px;">
                <button type="button" class="btn-query-doc preset-btn" data-query="Summarize ${escapeHtml(doc.filename)}">Search</button>
                <button type="button" class="btn-delete-doc preset-btn" data-docid="${escapeHtml(doc.doc_id)}" title="Delete">Delete</button>
              </div>
            </div>
            <div style="background:var(--bg-page);border:1px solid var(--border-color);border-radius:4px;padding:10px;max-height:200px;overflow-y:auto;">
              <div style="font-size:0.82rem;line-height:1.6;color:var(--text-primary);white-space:pre-wrap;">${escapeHtml(doc.full_text || '[No content]')}</div>
            </div>
            <details style="margin-top:8px;font-size:0.74rem;color:var(--text-secondary);">
              <summary style="cursor:pointer;">View ${doc.total_chunks} chunks</summary>
              <div style="margin-top:6px;display:flex;flex-direction:column;gap:6px;">
                ${doc.chunks.map((chk, i) => `
                  <div style="padding:6px 10px;background:var(--bg-surface-hover);border-radius:4px;border:1px solid var(--border-color);font-size:0.71rem;">
                    <div style="display:flex;justify-content:space-between;color:var(--color-primary);margin-bottom:2px;">
                      <span>Chunk #${i + 1} (${chk.chunk_id})</span>
                      <span>Cluster C-${chk.cluster_id}</span>
                    </div>
                    <div style="color:var(--text-secondary);font-family:monospace;font-size:0.68rem;word-break:break-all;">
                      Leaf: ${escapeHtml((chk.leaf_hash || '').slice(0, 32))}...
                    </div>
                  </div>
                `).join('')}
              </div>
            </details>
          </div>`;
      });
      html += '</div>';
      qdrantModalContent.innerHTML = html;

      const f = $('doc-search-filter');
      if (f) {
        f.addEventListener('input', () => {
          const q = f.value.toLowerCase().trim();
          qdrantModalContent.querySelectorAll('.org-doc-card').forEach(card => {
            const t = card.dataset.docTitle || '', x = card.dataset.docText || '';
            card.style.display = (!q || t.includes(q) || x.includes(q)) ? 'block' : 'none';
          });
        });
      }
      qdrantModalContent.querySelectorAll('.btn-query-doc').forEach(b => {
        b.addEventListener('click', () => {
          const q = b.dataset.query;
          if (q) { queryInput.value = q; queryInput.focus(); }
          qdrantModal.close();
        });
      });
      qdrantModalContent.querySelectorAll('.btn-delete-doc').forEach(b => {
        b.addEventListener('click', async () => {
          const did = b.dataset.docid;
          if (confirm(`Delete document '${did}'?`)) {
            b.textContent = 'Deleting...';
            await fetch(`/api/v1/documents/${encodeURIComponent(orgId)}/${encodeURIComponent(did)}`, { method: 'DELETE' });
            openOrgDocumentsViewer();
          }
        });
      });
      const purge = $('btn-purge-collection');
      if (purge) {
        purge.addEventListener('click', async () => {
          if (confirm(`Delete ALL documents in ${data.collection_name}?`)) {
            purge.textContent = 'Deleting...';
            await fetch(`/api/v1/collections/${encodeURIComponent(orgId)}`, { method: 'DELETE' });
            openOrgDocumentsViewer();
          }
        });
      }
    } catch (err) {
      qdrantModalContent.innerHTML = `<div style="padding:1rem;color:#f87171;background:rgba(239,68,68,0.1);border-radius:8px;">Error: ${escapeHtml(err.message)}</div>`;
    }
  }

  if (btnOpenOrgDocs) btnOpenOrgDocs.addEventListener('click', openOrgDocumentsViewer);
  if (btnViewQdrant) btnViewQdrant.addEventListener('click', openOrgDocumentsViewer);
  if (btnCloseQdrantModal && qdrantModal) {
    btnCloseQdrantModal.addEventListener('click', () => qdrantModal.close());
    qdrantModal.addEventListener('click', e => { if (e.target === qdrantModal) qdrantModal.close(); });
  }

});