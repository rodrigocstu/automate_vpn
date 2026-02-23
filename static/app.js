/* ═══════════════════════════════════════════════════════════════
   VPN GlobalProtect — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    const userRole = window.USER_ROLE || 'guest';

    // CMDB Pagination State
    window.cmdbCurrentPage = 0;
    window.cmdbPageSize = 25;
    window.cmdbTotalRecords = 0;

    // ── Tab switching ──
    const tabs = document.querySelectorAll('.tab:not(.tab-disabled)');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            if (!target) return;
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            const targetContent = document.getElementById(`tab-${target}`);
            if (targetContent) targetContent.classList.add('active');
            hideResults();
        });
    });

    // ── Show/hide EXT fields ──
    const tipoSelect = document.getElementById('tipo');
    const extFields = document.getElementById('extFields');

    if (tipoSelect && extFields) {
        tipoSelect.addEventListener('change', () => {
            extFields.style.display = tipoSelect.value === 'EXT' ? 'block' : 'none';
        });
    }


    // ── Form submission (Mode 2: params) — only for admin/user ──
    const formParams = document.getElementById('formParams');
    if (formParams && userRole !== 'guest') {
        formParams.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = e.target.querySelector('button[type="submit"]');
            if (!btn) return;
            setLoading(btn, true);
            hideResults();

            const data = {
                ritm: val('ritm'),
                minsal: val('minsal'),
                rut: val('rut'),
                tipo: val('tipo'),
                vencimiento: val('vencimiento'),
                ips: val('ips'),
                puertos: val('puertos'),
                obs: val('obs'),
                vsys: val('vsys'),
                zona_origen: val('zona_origen'),
                zona_destino: val('zona_destino'),
                grupo_int: val('grupo_int'),
                grupo_ext: val('grupo_ext'),
                log_setting: val('log_setting'),
                profile_group: val('profile_group'),
                crear_objetos: document.getElementById('crear_objetos')?.checked ?? true,
                incluir_commit: document.getElementById('incluir_commit')?.checked ?? false,
            };

            try {
                const resp = await fetch('/api/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });

                if (resp.status === 401) { window.location.href = '/login'; return; }
                if (resp.status === 403) {
                    const r = await resp.json();
                    if (r.must_change_pw) { window.location.href = '/change-password'; return; }
                    showError(r.error || 'Acceso denegado.');
                    return;
                }

                const result = await resp.json();
                if (result.error) {
                    showError(result.error);
                } else if (result.success) {
                    showResults(result);
                }
            } catch (err) {
                showError('Error de conexión con el servidor.');
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── Ticket parsing (Mode 1) — only for admin/user ──
    const btnParseTicket = document.getElementById('btnParseTicket');
    if (btnParseTicket && userRole !== 'guest') {
        btnParseTicket.addEventListener('click', async () => {
            const btn = btnParseTicket;
            const texto = document.getElementById('ticketText').value.trim();

            if (!texto) {
                showError('Pega el texto del ticket primero.');
                return;
            }

            setLoading(btn, true);
            hideResults();

            try {
                const resp = await fetch('/api/ticket', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ texto }),
                });

                if (resp.status === 401) { window.location.href = '/login'; return; }
                if (resp.status === 403) {
                    showError('Acceso denegado. Permisos insuficientes.');
                    return;
                }

                const result = await resp.json();
                if (result.error) {
                    showError(result.error);
                } else if (result.missing && result.missing.length > 0) {
                    showMissing(result.parsed, result.missing);
                } else if (result.success) {
                    showResults(result);
                }
            } catch (err) {
                showError('Error de conexión con el servidor.');
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── Excel upload (Mode 3) — only for admin/user ──
    const fileUploadArea = document.getElementById('fileUploadArea');
    const fileInput = document.getElementById('excelFile');
    const fileNameSpan = document.getElementById('fileName');

    if (fileUploadArea && fileInput) {
        fileUploadArea.addEventListener('click', () => fileInput.click());

        fileUploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadArea.classList.add('dragover');
        });

        fileUploadArea.addEventListener('dragleave', () => {
            fileUploadArea.classList.remove('dragover');
        });

        fileUploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                fileNameSpan.textContent = e.dataTransfer.files[0].name;
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                fileNameSpan.textContent = fileInput.files[0].name;
            }
        });
    }

    const btnProcessExcel = document.getElementById('btnProcessExcel');
    if (btnProcessExcel && userRole !== 'guest') {
        btnProcessExcel.addEventListener('click', async () => {
            const btn = btnProcessExcel;
            const file = fileInput?.files[0];
            const row = document.getElementById('excelRow')?.value || 3;

            if (!file) {
                showError('Selecciona un archivo Excel primero.');
                return;
            }

            setLoading(btn, true);
            hideResults();

            const formData = new FormData();
            formData.append('file', file);
            formData.append('row', row);

            try {
                const resp = await fetch('/api/excel', {
                    method: 'POST',
                    body: formData,
                });

                if (resp.status === 401) { window.location.href = '/login'; return; }
                if (resp.status === 403) {
                    showError('Acceso denegado. Permisos insuficientes.');
                    return;
                }

                const result = await resp.json();
                if (result.error) {
                    showError(result.error);
                } else if (result.success) {
                    showResults(result);
                }
            } catch (err) {
                showError('Error de conexión con el servidor.');
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── Download template (admin/user only) ──
    const btnTemplate = document.getElementById('btnDownloadTemplate');
    if (btnTemplate) {
        btnTemplate.addEventListener('click', () => {
            window.location.href = '/api/template';
        });
    }

    // ── VPN S2S Form (IPsec Site-to-Site) ──
    const btnGenerateS2S = document.getElementById('btnGenerateS2S');
    if (btnGenerateS2S && userRole === 'super_admin') {
        btnGenerateS2S.addEventListener('click', async () => {
            const btn = btnGenerateS2S;

            // Validate required fields manually
            const peer_ip = val('s2s_peer_ip');
            const local_subnet = val('s2s_local_subnet');
            const remote_subnet = val('s2s_remote_subnet');
            const psk = document.getElementById('s2s_psk')?.value || '';
            const tunnel_id = val('s2s_tunnel_id');

            if (!peer_ip || !local_subnet || !remote_subnet || !psk || !tunnel_id) {
                showError('Completa los campos requeridos: Peer IP, Subredes, PSK y N° de Túnel.');
                return;
            }

            const s2sResult = document.getElementById('s2s_result');
            if (s2sResult) s2sResult.classList.add('hidden');
            setLoading(btn, true);

            const data = {
                ritm: val('s2s_ritm'),
                peer_ip,
                local_subnet,
                remote_subnet,
                psk,
                tunnel_id,
                local_wan_ip: val('s2s_local_wan_ip'),
                local_if: val('s2s_local_if'),
                vr: val('s2s_vr'),
                local_zone: val('s2s_local_zone'),
                tunnel_zone: val('s2s_tunnel_zone'),
                create_policies: document.getElementById('s2s_create_policies')?.checked ?? true,
                // Crypto selectors (PAN-OS 10.2.x)
                ike_enc: val('ike_enc'),
                ike_hash: val('ike_hash'),
                ike_dh: val('ike_dh'),
                ike_lifetime: val('ike_lifetime') || '8',
                ipsec_enc: val('ipsec_enc'),
                ipsec_auth: val('ipsec_auth'),
                ipsec_dh: val('ipsec_dh'),
                ipsec_lifetime: val('ipsec_lifetime') || '1',
            };

            try {
                const resp = await fetch('/api/s2s', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });

                if (resp.status === 401) { window.location.href = '/login'; return; }
                if (resp.status === 403) {
                    const r = await resp.json();
                    showError(r.error || 'Acceso denegado.');
                    return;
                }

                const result = await resp.json();
                if (result.error) {
                    showError(result.error);
                } else if (result.success) {
                    const cliPre = document.getElementById('s2sCliOutput');
                    if (cliPre) cliPre.textContent = result.cli;
                    if (s2sResult) s2sResult.classList.remove('hidden');
                    s2sResult?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            } catch (err) {
                showError('Error de conexión con el servidor.');
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── Copy S2S CLI ──
    const btnCopyS2S = document.getElementById('btnCopyS2S');
    if (btnCopyS2S) {
        btnCopyS2S.addEventListener('click', async () => {
            const text = document.getElementById('s2sCliOutput')?.textContent || '';
            try {
                await navigator.clipboard.writeText(text);
                document.getElementById('copyS2SIcon').textContent = '✅';
                document.getElementById('copyS2SText').textContent = 'Copiado';
                setTimeout(() => {
                    document.getElementById('copyS2SIcon').textContent = '📋';
                    document.getElementById('copyS2SText').textContent = 'Copiar';
                }, 2000);
            } catch { /* clipboard not available */ }
        });
    }


    // ── Módulo Ansible Wizard ──
    if (userRole === 'super_admin') {
        initAnsibleWizard();
        initCmdbModule();
    }

    // ── App-ID Search Widget ──
    const btnAppSearch = document.getElementById('btnAppIdSearch');
    const appSearchInput = document.getElementById('appid_search');
    if (btnAppSearch && appSearchInput) {
        const doSearch = async () => {
            const q = appSearchInput.value.trim();
            if (!q) return;
            const res = document.getElementById('appid_results');
            if (!res) return;
            try {
                const r = await fetch(`/api/appid-search?q=${encodeURIComponent(q)}`);
                const data = await r.json();
                if (!data.results || data.results.length === 0) {
                    res.innerHTML = '<span style="padding:0.4rem;color:var(--text-muted)">Sin resultados: ' + q + '</span>';
                } else {
                    res.innerHTML = data.results.slice(0, 20).map(app =>
                        `<div style="padding:0.3rem 0.5rem;cursor:pointer;border-radius:4px;display:flex;justify-content:space-between;gap:0.5rem;"
                              onmouseover="this.style.background='rgba(0,200,255,0.08)'"
                              onmouseout="this.style.background='transparent'"
                              onclick="s2sAddApp('${app.id}','${app.name.replace(/'/g, '\\&apos;')}')"> 
                            <span><code style="font-size:0.78rem">${app.id}</code> &mdash; ${app.name}</span>
                            <span style="font-size:0.7rem;opacity:0.6">${app.category} | &#9888;${app.risk}</span>
                        </div>`
                    ).join('');
                }
                res.style.display = 'block';
            } catch (e) { console.error('appid search:', e); }
        };
        btnAppSearch.addEventListener('click', doSearch);
        appSearchInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); doSearch(); } });
        document.addEventListener('click', e => {
            const res = document.getElementById('appid_results');
            if (res && !res.contains(e.target) && e.target !== appSearchInput && e.target !== btnAppSearch)
                res.style.display = 'none';
        });
    }

    // Inicializar UI

    // ═══════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════

    function val(id) {
        const el = document.getElementById(id);
        return el ? el.value.trim() : '';
    }

    function setLoading(btn, loading) {
        if (loading) {
            btn.classList.add('loading');
            btn.dataset.origText = btn.innerHTML;
            const icon = btn.querySelector('.btn-icon');
            if (icon) icon.textContent = '⏳';
        } else {
            btn.classList.remove('loading');
            btn.innerHTML = btn.dataset.origText || btn.innerHTML;
        }
    }

    function hideResults() {
        const results = document.getElementById('results');
        const errorBox = document.getElementById('errorBox');
        const missingBox = document.getElementById('missingBox');
        if (results) results.classList.add('hidden');
        if (errorBox) errorBox.classList.add('hidden');
        if (missingBox) missingBox.classList.add('hidden');
    }

    function showError(msg) {
        const box = document.getElementById('errorBox');
        if (box) {
            box.textContent = '❌ ' + msg;
            box.classList.remove('hidden');
        }
    }

    function showMissing(parsed, missing) {
        const box = document.getElementById('missingBox');
        if (!box) return;
        let html = '<strong>⚠️ Datos detectados:</strong><br>';
        for (const [k, v] of Object.entries(parsed)) {
            html += `&nbsp;&nbsp;• ${k}: <code>${Array.isArray(v) ? v.join(', ') : v}</code><br>`;
        }
        html += `<br><strong>Faltan:</strong> ${missing.join(', ')}`;
        html += '<br><em>Completa los campos faltantes en la pestaña Parámetros.</em>';
        box.innerHTML = html;
        box.classList.remove('hidden');
    }

    function showResults(result) {
        const d = result.datos;

        // Data table
        const tableData = [
            ['RITM', d.ritm],
            ['MINSAL (input)', d.minsal_input],
            ['MINSAL (norm)', d.minsal_norm],
            ['RUT (input)', d.rut_input],
            ['RUT (norm)', d.rut_norm],
            ['TIPO', d.tipo],
            ['Vencimiento', d.vencimiento],
            ['IPs destino', (d.ips || []).join(', ') || 'N/A'],
            ['Puertos', (d.puertos || []).join(', ') || 'N/A'],
            ['vsys', d.vsys],
            ['Zona origen', d.zona_origen],
            ['Zona destino', d.zona_destino],
            ['Grupo', d.grupo],
        ];

        const tableHtml = tableData.map(([k, v]) =>
            `<div class="data-row">
            <span class="data-key">${k}</span>
            <span class="data-value">${v || 'N/A'}</span>
        </div>`
        ).join('');
        document.getElementById('dataTable').innerHTML = tableHtml;

        // Credentials
        document.getElementById('credUsername').textContent = d.username;
        document.getElementById('credUsernameLen').textContent = `${d.username_length} caracteres`;
        document.getElementById('credPassword').textContent = d.password;
        document.getElementById('credPasswordLen').textContent = `${d.password_length} caracteres`;

        // CLI
        document.getElementById('cliOutput').textContent = result.cli;

        // Ansible
        const ansibleArea = document.getElementById('ansibleResultArea');
        const ansibleOutput = document.getElementById('ansibleOutput');
        if (ansibleOutput && result.datos && result.datos.ansible_playbook) {
            ansibleOutput.textContent = result.datos.ansible_playbook;
            if (ansibleArea) ansibleArea.classList.remove('hidden');
        } else if (ansibleArea) {
            ansibleArea.classList.add('hidden');
        }

        // Show results section
        document.getElementById('results').classList.remove('hidden');

        // Scroll to results
        setTimeout(() => {
            document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);
    }

}); // end DOMContentLoaded

/* ── App-ID Tag Management (global scope for onclick handlers) ── */
const _s2sSelectedApps = new Set();

function s2sAddApp(id, name) {
    if (_s2sSelectedApps.has(id)) return;
    _s2sSelectedApps.add(id);
    _s2sRenderTags();
    const res = document.getElementById('appid_results');
    if (res) res.style.display = 'none';
    const input = document.getElementById('appid_search');
    if (input) input.value = '';
}

function s2sAddPreset(type) {
    const presets = {
        networking: ['ping', 'dns', 'ntp', 'ssh', 'snmp', 'syslog', 'ldap', 'ldap-ssl', 'kerberos'],
        database: ['mssql', 'mysql', 'postgresql', 'oracle-db', 'mongodb', 'redis'],
        healthcare: ['hl7', 'dicom', 'fhir', 'ssl', 'web-browsing'],
        management: ['snmp', 'snmp-trap', 'netconf', 'restconf', 'grpc', 'syslog', 'ssh'],
    };
    (presets[type] || []).forEach(id => _s2sSelectedApps.add(id));
    _s2sRenderTags();
}

function s2sClearApps() {
    _s2sSelectedApps.clear();
    _s2sRenderTags();
}

function _s2sRenderTags() {
    const container = document.getElementById('appid_selected');
    const hidden = document.getElementById('s2s_applications');
    if (!container) return;
    container.innerHTML = [..._s2sSelectedApps].map(id =>
        `<span style="background:var(--accent-color);color:#fff;border-radius:12px;padding:2px 10px;font-size:0.78rem;display:flex;align-items:center;gap:4px;">
            ${id}
            <span onclick="s2sRemoveApp('${id}')" style="cursor:pointer;font-weight:bold;opacity:0.8;margin-left:2px;">×</span>
         </span>`
    ).join('') || '<span style="color:var(--text-muted);font-size:0.8rem;padding:4px">Sin aplicaciones — se usará <code>any</code></span>';
    if (hidden) hidden.value = [..._s2sSelectedApps].join(',');
}

function s2sRemoveApp(id) {
    _s2sSelectedApps.delete(id);
    _s2sRenderTags();
}

/**
 * Migra configuración de QA a PRD desde el Dashboard principal.
 */
async function migrateToPrdFromDashboard() {
    const riskChecklist =
        "⚠️ PROTOCOLO DE CHANGE ENABLEMENT (ITIL 4):\n\n" +
        "1. SERVICE TRANSITION: Sincronización de activos de configuración (CIs).\n" +
        "2. CHANGE ASSESSMENT: Mitigación vía Backup preventivo en el servidor.\n" +
        "3. VALIDATION & TESTING: Garantía de integridad y paridad en entorno PRD.\n\n" +
        "¿Confirmas el inicio del despliegue a PRD?";

    if (!confirm(riskChecklist)) {
        return;
    }

    const btn = document.getElementById('btnMigrateDashboard');
    const originalHtml = btn.innerHTML;

    try {
        btn.disabled = true;
        btn.innerHTML = '📦 Migrando...';

        const response = await fetch('/api/admin/migrate-to-prd', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': window.CSRF_TOKEN || ''
            }
        });

        const data = await response.json();
        if (data.success) {
            alert('✅ Success: ' + data.message);
        } else {
            alert('❌ Error: ' + (data.error || 'Fallo en la migración'));
        }
    } catch (err) {
        alert('❌ Error de red al comunicar con el servidor.');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
    }
}

/* ── Herramientas Complementarias ── */


/**
 * Descarga la plantilla Excel para carga masiva.
 * Solo disponible para Super Admin.
 */
async function downloadTemplate() {
    window.location.href = '/api/template';
}

/* ── Módulo Ansible "Elite Edition" Wizard ── */

/**
 * Inicializa el Wizard de Ansible.
 * Maneja navegación, simulación y generación de playbooks.
 */
function initAnsibleWizard() {
    const btnApply = document.getElementById('btnAnsibleGenerateStandard');
    const resultArea = document.getElementById('ansibleResultArea');
    const playbookOutput = document.getElementById('ansibleOutput');
    const btnCopyAnsible = document.getElementById('btnCopyAnsible');

    if (!btnApply) return;

    btnApply.addEventListener('click', async () => {
        setLoading(btnApply, true);

        const data = {
            firewall_ip: val('ansible_firewall_ip'),
            username: val('ansible_username'),
            password: val('ansible_password'),
            portal_name: val('ansible_portal_name') || 'GP-Portal',
            gateway_name: val('ansible_gateway_name') || 'GP-Gateway',
            if_name: val('ansible_if_name'),
            if_zone: val('ansible_if_zone'),
            route_dest: val('ansible_route_dest') || '0.0.0.0/0',
            route_nexthop: val('ansible_route_nexthop') || '',
            bulk_objects: val('ansible_bulk_objects') || '',
            nat_name: val('ansible_nat_name'),
            nat_type: val('ansible_nat_type'),
            nat_src_zone: val('ansible_nat_src_zone') || val('ansible_src_zone'),
            nat_dest_zone: val('ansible_nat_dest_zone') || val('ansible_dest_zone'),
            nat_translated: val('ansible_nat_translated') || '',
            src_zone: val('ansible_src_zone'),
            dest_zone: val('ansible_dest_zone'),
            tags: val('ansible_tags'),
            create_checkpoint: document.getElementById('ansible_create_checkpoint')?.checked ?? false,
            auto_commit: document.getElementById('ansible_auto_commit')?.checked ?? false
        };

        try {
            const resp = await fetch('/api/ansible', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            const result = await resp.json();
            if (result.error) {
                showError(result.error);
            } else {
                resultArea.classList.remove('hidden');
                playbookOutput.textContent = result.playbook;
                resultArea.scrollIntoView({ behavior: 'smooth' });
            }
        } catch (err) {
            showError('Error al conectar con el motor Ansible.');
        } finally {
            setLoading(btnApply, false);
        }
    });

    if (btnCopyAnsible) {
        btnCopyAnsible.addEventListener('click', async () => {
            const text = playbookOutput.textContent;
            try {
                await navigator.clipboard.writeText(text);
                const icon = document.getElementById('copyAnsibleIcon');
                const label = document.getElementById('copyAnsibleText');
                if (icon) icon.textContent = '✅';
                if (label) label.textContent = 'Copiado';
                setTimeout(() => {
                    if (icon) icon.textContent = '📋';
                    if (label) label.textContent = 'Copiar';
                }, 2000);
            } catch (e) { }
        });
    }
}

/**
 * Inicializa el módulo de CMDB (ServiceNow style).
 */
function initCmdbModule() {
    const btnRefresh = document.getElementById('btnRefreshCmdb');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', loadCmdbData);
    }

    // Carga inicial si la pestaña CMDB se vuelve activa
    document.querySelectorAll('.tab').forEach(t => {
        t.addEventListener('click', () => {
            if (t.dataset.tab === 'cmdb') {
                loadCmdbData();
                loadCmdbStats();
                loadCmdbBatches();
            }
        });
    });

    // Manejar carga masiva
    const formUpload = document.getElementById('formCmdbUpload');
    if (formUpload) {
        formUpload.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnCmdbUpload');
            const fileInput = document.getElementById('cmdbFile');
            const descInput = document.getElementById('cmdbDescription');
            const progress = document.getElementById('cmdbUploadProgress');

            if (!fileInput.files.length) return;

            setLoading(btn, true);
            if (progress) progress.classList.remove('hidden');

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('description', descInput.value);

            try {
                const resp = await fetch('/api/cmdb/upload', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': window.CSRF_TOKEN || '' },
                    body: formData
                });
                const result = await resp.json();
                if (result.success) {
                    alert(`✅ Sincronización exitosa.\nAgregados: ${result.stats.added}\nActualizados: ${result.stats.updated}\nDesactivados: ${result.stats.deactivated}`);
                    loadCmdbData();
                    loadCmdbStats();
                    loadCmdbBatches();
                    formUpload.reset();
                } else {
                    showError(result.error || 'Error en la sincronización.');
                }
            } catch (err) {
                showError('Error de conexión al subir la CMDB.');
            } finally {
                setLoading(btn, false);
                if (progress) progress.classList.add('hidden');
            }
        });
    }

    // Manejar sincronización local (servidor)
    const btnSyncLocal = document.getElementById('btnCmdbSyncLocal');
    if (btnSyncLocal) {
        btnSyncLocal.addEventListener('click', async () => {
            const btn = btnSyncLocal;
            const descInput = document.getElementById('cmdbDescription');
            const progress = document.getElementById('cmdbUploadProgress');

            if (!confirm('¿Deseas sincronizar usando el archivo configurado en el servidor?')) return;

            setLoading(btn, true);
            if (progress) progress.classList.remove('hidden');

            const formData = new FormData();
            formData.append('description', descInput.value || 'Sincronización Local Manual');

            try {
                const resp = await fetch('/api/cmdb/upload-local', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': window.CSRF_TOKEN || '' },
                    body: formData
                });
                const result = await resp.json();
                if (result.success) {
                    alert('✅ Reconciliación local completada con éxito.');
                    loadCmdbData();
                    loadCmdbStats();
                    loadCmdbBatches();
                } else {
                    showError(result.error || 'Error en la sincronización local.');
                }
            } catch (err) {
                showError('Error de conexión con el servidor (Local Sync).');
            } finally {
                setLoading(btn, false);
                if (progress) progress.classList.add('hidden');
            }
        });
    }

    // Manejar búsqueda inteligente (Autocomplete) en CMDB
    const cmdbSearchInput = document.getElementById('cmdb_search_input');
    const cmdbSearchResults = document.getElementById('cmdb_search_results');

    if (cmdbSearchInput && cmdbSearchResults) {
        let debounceTimer;
        cmdbSearchInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            const q = cmdbSearchInput.value.trim();
            if (q.length < 2) {
                cmdbSearchResults.classList.add('hidden');
                return;
            }

            debounceTimer = setTimeout(async () => {
                try {
                    const resp = await fetch(`/api/cmdb/search?q=${encodeURIComponent(q)}`);
                    const results = await resp.json();

                    if (results.length === 0) {
                        cmdbSearchResults.innerHTML = '<div style="padding:1rem;color:var(--text-muted)">Sin resultados.</div>';
                    } else {
                        cmdbSearchResults.innerHTML = results.map(item => `
                            <div class="appid-item" onclick="selectCmdbResult(${JSON.stringify(item).replace(/"/g, '&quot;')})">
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <span style="font-weight:600; color:var(--accent-color);">${item.name}</span>
                                    <span style="font-size:0.75rem; opacity:0.6;">${item.region}</span>
                                </div>
                                <div style="font-size:0.8rem; opacity:0.8;">📍 ${item.address}, ${item.comuna}</div>
                                <div style="display:flex; gap:0.5rem; margin-top:4px;">
                                    <span class="ci-badge" style="font-size:0.65rem; background:rgba(0,150,255,0.1); color:var(--accent-color);">💻 ${item.hw_model || 'No HW'}</span>
                                    <span class="ci-badge" style="font-size:0.65rem; background:rgba(0,200,100,0.1); color:#4ade80;">🌐 ${item.net_access || 'No Net'}</span>
                                </div>
                            </div>
                        `).join('');
                    }
                    cmdbSearchResults.classList.remove('hidden');
                } catch (err) {
                    console.error('Search error', err);
                }
            }, 300);
        });

        document.addEventListener('click', (e) => {
            if (!cmdbSearchInput.contains(e.target) && !cmdbSearchResults.contains(e.target)) {
                cmdbSearchResults.classList.add('hidden');
            }
        });

        // Pagination Listeners
        const pageSizeSelect = document.getElementById('cmdb_page_size');
        const prevBtn = document.getElementById('btnCmdbPrevPage');
        const nextBtn = document.getElementById('btnCmdbNextPage');

        if (pageSizeSelect) {
            pageSizeSelect.addEventListener('change', () => {
                window.cmdbPageSize = parseInt(pageSizeSelect.value);
                window.cmdbCurrentPage = 0;
                loadCmdbData();
            });
        }

        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (window.cmdbCurrentPage > 0) {
                    window.cmdbCurrentPage--;
                    loadCmdbData();
                }
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                const maxPage = Math.ceil(window.cmdbTotalRecords / window.cmdbPageSize) - 1;
                if (window.cmdbCurrentPage < maxPage) {
                    window.cmdbCurrentPage++;
                    loadCmdbData();
                }
            });
        }
    }
}

// Batch History Modal Functions
window.showBatchHistoryModal = function () {
    const modal = document.getElementById('batchHistoryModal');
    if (modal) {
        modal.classList.remove('hidden');
        loadCmdbBatches();
    }
};

window.closeBatchHistoryModal = function () {
    const modal = document.getElementById('batchHistoryModal');
    if (modal) modal.classList.add('hidden');
};

async function loadCmdbData() {
    const tbody = document.getElementById('cmdbTableBody');
    const pageInfo = document.getElementById('cmdb_page_info');
    if (!tbody) return;

    try {
        const offset = window.cmdbCurrentPage * window.cmdbPageSize;
        const resp = await fetch(`/api/cmdb?limit=${window.cmdbPageSize}&offset=${offset}`);
        const data = await resp.json();

        window.cmdbTotalRecords = data.total;
        if (pageInfo) {
            const totalPages = Math.ceil(data.total / window.cmdbPageSize) || 1;
            pageInfo.textContent = `Pág. ${window.cmdbCurrentPage + 1} de ${totalPages}`;
        }

        renderCmdbTable(data.results);
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="6" class="error-text">Fallo al conectar con la CMDB.</td></tr>';
    }
}

async function loadCmdbStats() {
    try {
        const resp = await fetch('/api/cmdb/stats');
        const stats = await resp.json();

        const totalEl = document.getElementById('statTotalCI');
        const fwEl = document.getElementById('statFirewalls');
        const prdEl = document.getElementById('statProd');

        if (totalEl) totalEl.textContent = stats.total;
        if (fwEl) {
            const fw = stats.by_class.find(c => c.ci_class === 'Firewall');
            fwEl.textContent = fw ? fw.count : 0;
        }
        if (prdEl) {
            const prd = stats.by_env.find(e => e.environment === 'PRD');
            prdEl.textContent = prd ? prd.count : 0;
        }
    } catch (e) {
        console.error('Error loading CMDB stats', e);
    }
}

function renderCmdbTable(cis) {
    const tbody = document.getElementById('cmdbTableBody');
    if (!tbody) return;

    if (!cis || cis.length === 0) {
        tbody.innerHTML = '<tr><td colspan="22" style="text-align:center;padding:2rem">Sin registros en esta página.</td></tr>';
        return;
    }

    tbody.innerHTML = cis.map(ci => `
        <tr onclick="selectCmdbResult(${JSON.stringify(ci).replace(/"/g, '&quot;')})" style="cursor:pointer;">
            <td class="sticky-col" style="font-weight:600; color:var(--accent-color);">${ci.name}</td>
            <td style="font-size:0.75rem;">${ci.address}</td>
            <td>${ci.comuna}</td>
            <td>${ci.region}</td>
            <td>${ci.provincia || '—'}</td>
            <td style="font-size:0.75rem; opacity:0.7;">${ci.macrozone || '—'}</td>
            <td style="font-size:0.75rem;">${ci.contratante || '—'}</td>
            <td><span class="ci-badge" style="font-size:0.65rem;">${ci.tipo_establecimiento || '—'}</span></td>
            <td>${ci.complejidad || '—'}</td>
            <td class="mono" style="color:#00d2ff;">${ci.hw_model || '—'}</td>
            <td style="font-size:0.75rem;">${ci.hw_type || '—'}</td>
            <td class="mono">${ci.hw_sw || '—'}</td>
            <td class="mono">${ci.hw_vc || '—'}</td>
            <td class="mono">${ci.hw_sop || '—'}</td>
            <td class="mono">${ci.hw_sat || '—'}</td>
            <td class="mono">${ci.hw_800 || '—'}</td>
            <td class="mono">${ci.hw_mov || '—'}</td>
            <td class="mono">${ci.hw_bam || '—'}</td>
            <td class="mono">${ci.hw_samu || '—'}</td>
            <td class="mono">${ci.hw_ccm || '—'}</td>
            <td class="mono">${ci.hw_fw || '—'}</td>
            <td class="mono" style="color:#00d2ff;">${ci.hw_fw_sug || '—'}</td>
            <td style="color:#2ecc71; font-weight:600;">${ci.net_access || '—'}</td>
            <td class="mono">${ci.net_bw || '—'}</td>
            <td style="font-size:0.75rem; opacity:0.8;">${ci.net_acc_r1 || '—'}</td>
            <td class="mono" style="font-size:0.7rem;">${ci.net_bw_r1 || '—'}</td>
            <td style="font-size:0.75rem; opacity:0.8;">${ci.net_acc_r2 || '—'}</td>
            <td class="mono" style="font-size:0.7rem;">${ci.net_bw_r2 || '—'}</td>
            <td style="font-size:0.75rem; opacity:0.8;">${ci.net_acc_r3 || '—'}</td>
            <td class="mono" style="font-size:0.7rem;">${ci.net_bw_r3 || '—'}</td>
            <td>${ci.net_wifi || '—'}</td>
            <td>${ci.net_home || '—'}</td>
            <td>${ci.net_dedicated || '—'}</td>
            <td style="font-size:0.7rem;">${ci.net_sug1 || '—'}</td>
            <td style="font-size:0.7rem;">${ci.net_sug2 || '—'}</td>
            <td style="font-size:0.7rem;">${ci.net_sug_sat || '—'}</td>
            <td class="mono">${ci.net_voz || '—'}</td>
            <td class="mono">${ci.net_datos || '—'}</td>
            <td class="mono" style="font-size:0.65rem; opacity:0.5;">${(ci.batch_id || '').substring(0, 8)}...</td>
        </tr>
    `).join('');
}

async function showCiDetail(id) {
    try {
        const resp = await fetch(`/api/cmdb/${id}`);
        const data = await resp.json();
        alert(`Relaciones de ${data.ci.name}:\n\nPadres: ${data.parents.map(p => p.name).join(', ') || 'Ninguno'}\n\nHijos: ${data.children.map(c => c.name).join(', ') || 'Ninguno'}`);
    } catch (e) {
        alert('Error al cargar detalle del CI');
    }
}

async function loadCmdbBatches() {
    const tbody = document.getElementById('batchTableBody');
    if (!tbody) return;

    try {
        const resp = await fetch('/api/cmdb/batches');
        const batches = await resp.json();

        if (!batches || batches.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:1rem;color:var(--text-muted)">Sin historial de lotes.</td></tr>';
            return;
        }

        tbody.innerHTML = batches.map(b => `
            <tr>
                <td class="mono" style="font-size:0.75rem">${b.id.substring(0, 8)}...</td>
                <td>${b.description || 'Sin descripción'}</td>
                <td>${b.user_name}</td>
                <td class="mono" style="font-size:0.8rem">${b.created_at}</td>
                <td><span class="status-badge status-${b.status === 'undone' ? 'retired' : 'operational'}">${b.status}</span></td>
                <td>
                    ${b.status !== 'undone' ?
                `<button class="btn btn-sm btn-danger" onclick="undoCmdbBatch('${b.id}')" title="Deshacer Lote">↩️ Deshacer</button>` :
                '<span style="font-size:0.8rem;opacity:0.6">Revertido</span>'
            }
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Error loading batches', err);
    }
}

async function undoCmdbBatch(batchId) {
    if (!confirm('⚠️ ¿Estás seguro de que quieres revertir esta carga masiva? Se restaurará el estado anterior de los CIs afectados.')) return;

    try {
        const resp = await fetch(`/api/cmdb/batch/undo/${batchId}`, {
            method: 'POST',
            headers: { 'X-CSRF-Token': window.CSRF_TOKEN || '' }
        });
        const result = await resp.json();
        if (result.success) {
            alert('✅ Lote revertido con éxito.');
            loadCmdbData();
            loadCmdbStats();
            loadCmdbBatches();
        } else {
            alert('❌ Error: ' + result.error);
        }
    } catch (err) {
        alert('Error de conexión al deshacer el lote.');
    }
}

window.undoCmdbBatch = undoCmdbBatch;
window.showCiDetail = showCiDetail;

/**
 * Muestra los detalles de un establecimiento seleccionado del buscador.
 */
function selectCmdbResult(item) {
    const container = document.getElementById('cmdb_detail_container');
    const title = document.getElementById('detail_title');
    const content = document.getElementById('detail_content');

    if (!container || !title || !content) return;

    title.textContent = item.name;
    content.innerHTML = `
        <div class="cmdb-detail-grid" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap:1rem; margin-top:1rem;">
            <!-- GRUPO: UBICACIÓN -->
            <div class="detail-section" style="background:rgba(0,0,0,0.2); padding:1rem; border-radius:8px; border-left:4px solid var(--accent-color);">
                <h4 style="margin-top:0; color:var(--accent-color); font-size:0.9rem; text-transform:uppercase;">📍 Ubicación y Contrato</h4>
                <div class="detail-item"><span class="stat-label">Dirección:</span> <span class="stat-value">${item.address}</span></div>
                <div class="detail-item"><span class="stat-label">Comuna / Provincia:</span> <span class="stat-value">${item.comuna} / ${item.provincia || 'N/A'}</span></div>
                <div class="detail-item"><span class="stat-label">Región:</span> <span class="stat-value">${item.region}</span></div>
                <div class="detail-item"><span class="stat-label">Macrozona:</span> <span class="stat-value">${item.macrozone || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Contratante:</span> <span class="stat-value">${item.contratante || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Tipo / Complejidad:</span> <span class="stat-value">${item.tipo_establecimiento} / ${item.complejidad}</span></div>
            </div>

            <!-- GRUPO: HARDWARE -->
            <div class="detail-section" style="background:rgba(0,0,0,0.2); padding:1rem; border-radius:8px; border-left:4px solid #00d2ff;">
                <h4 style="margin-top:0; color:#00d2ff; font-size:0.9rem; text-transform:uppercase;">📟 Hardware y Seguridad</h4>
                <div class="detail-item"><span class="stat-label">Core Actual:</span> <span class="stat-value" style="font-weight:700;">${item.hw_model || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Tipo Equipo:</span> <span class="stat-value">${item.hw_type || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Firewall:</span> <span class="stat-value">${item.hw_fw || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">FW Sugerido:</span> <span class="stat-value" style="color:#00d2ff;">${item.hw_fw_sug || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">SW / VC:</span> <span class="stat-value">${item.hw_sw || '—'} / ${item.hw_vc || '—'}</span></div>
            </div>

            <!-- GRUPO: CONECTIVIDAD PPAL -->
            <div class="detail-section" style="background:rgba(0,0,0,0.2); padding:1rem; border-radius:8px; border-left:4px solid #2ecc71;">
                <h4 style="margin-top:0; color:#2ecc71; font-size:0.9rem; text-transform:uppercase;">🌐 Red Principal</h4>
                <div class="detail-item"><span class="stat-label">Acceso:</span> <span class="stat-value" style="color:#2ecc71; font-weight:700;">${item.net_access || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Ancho de Banda:</span> <span class="stat-value">${item.net_bw || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Internet Dedicado:</span> <span class="stat-value">${item.net_dedicated || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">WiFi:</span> <span class="stat-value">${item.net_wifi || '—'}</span></div>
            </div>

            <!-- GRUPO: RESPALDOS -->
            <div class="detail-section" style="background:rgba(0,0,0,0.2); padding:1rem; border-radius:8px; border-left:4px solid #f1c40f;">
                <h4 style="margin-top:0; color:#f1c40f; font-size:0.9rem; text-transform:uppercase;">🔄 Respaldo y Sugerencias</h4>
                <div class="detail-item"><span class="stat-label">Respaldo 1:</span> <span class="stat-value">${item.net_acc_r1 || '—'} (${item.net_bw_r1 || '0'})</span></div>
                <div class="detail-item"><span class="stat-label">Respaldo 2:</span> <span class="stat-value">${item.net_acc_r2 || '—'} (${item.net_bw_r2 || '0'})</span></div>
                <div class="detail-item"><span class="stat-label">Respaldo 3:</span> <span class="stat-value">${item.net_acc_r3 || '—'} (${item.net_bw_r3 || '0'})</span></div>
                <div class="detail-item"><span class="stat-label">Sugeridos (1/2):</span> <span class="stat-value">${item.net_sug1 || '—'} / ${item.net_sug2 || '—'}</span></div>
            </div>

            <!-- GRUPO: SERVICIOS Y OTROS -->
            <div class="detail-section" style="background:rgba(0,0,0,0.2); padding:1rem; border-radius:8px; border-left:4px solid #e67e22;">
                <h4 style="margin-top:0; color:#e67e22; font-size:0.9rem; text-transform:uppercase;">📞 Telefonía y Otros</h4>
                <div class="detail-item"><span class="stat-label">Voz / Datos:</span> <span class="stat-value">${item.net_voz || '—'} / ${item.net_datos || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Línea 800:</span> <span class="stat-value">${item.hw_800 || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Satelital:</span> <span class="stat-value">${item.hw_sat || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">Móviles / BAM:</span> <span class="stat-value">${item.hw_mov || '—'} / ${item.hw_bam || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">SAMU 131:</span> <span class="stat-value">${item.hw_samu || '—'}</span></div>
                <div class="detail-item"><span class="stat-label">CCM / Soporte:</span> <span class="stat-value">${item.hw_ccm || '—'} / ${item.hw_sop || '—'}</span></div>
            </div>
        </div>
        <style>
            .detail-item { display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.4rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.2rem; }
            .detail-item .stat-label { opacity: 0.7; }
            .detail-item .stat-value { text-align: right; word-break: break-word; max-width: 60%; }
        </style>
    `;

    container.classList.remove('hidden');
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    document.getElementById('cmdb_search_results').classList.add('hidden');
}

window.selectCmdbResult = selectCmdbResult;
