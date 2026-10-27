(() => {
  const $ = (id) => document.getElementById(id);
  const form = $('scan-form');
  const domainInput = $('domain-input');
  const scanButton = $('scan-button');
  const resultsBody = $('results-body');
  const results = [];
  let currentDomain = '';
  let toastTimer;

  function toast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2300);
  }
  function setState(state) {
    $('empty-state').hidden = state !== 'empty';
    $('loading-state').hidden = state !== 'loading';
    $('error-state').hidden = state !== 'error';
    $('table-scroll').hidden = state !== 'table';
  }
  function setActions(enabled) {
    $('copy-button').disabled = !enabled;
    $('export-button').disabled = !enabled;
    $('filter-input').disabled = !enabled;
  }
  function renderRows(filter = '') {
    const query = filter.trim().toLowerCase();
    const visible = results.filter((host) => host.includes(query));
    resultsBody.replaceChildren();
    visible.forEach((host, index) => {
      const tr = document.createElement('tr');
      const number = document.createElement('td');
      number.className = 'row-number';
      number.textContent = String(index + 1).padStart(2, '0');
      const hostCell = document.createElement('td');
      hostCell.className = 'host-cell';
      hostCell.textContent = host;
      const parentCell = document.createElement('td');
      parentCell.className = 'parent-cell';
      parentCell.textContent = currentDomain;
      const typeCell = document.createElement('td');
      const chip = document.createElement('span');
      chip.className = 'type-chip';
      chip.textContent = 'SUBDOMAIN';
      typeCell.append(chip);
      const actionCell = document.createElement('td');
      const copy = document.createElement('button');
      copy.className = 'copy-row';
      copy.type = 'button';
      copy.title = 'Copy subdomain';
      copy.setAttribute('aria-label', `Copy ${host}`);
      copy.textContent = '▣';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(host); toast('Subdomain disalin.'); }
        catch { toast('Clipboard tidak tersedia di browser ini.'); }
      });
      actionCell.append(copy);
      tr.append(number, hostCell, parentCell, typeCell, actionCell);
      resultsBody.append(tr);
    });
    $('visible-count').textContent = `${visible.length} result${visible.length === 1 ? '' : 's'}`;
    $('result-count').textContent = String(results.length);
    $('results-caption').textContent = results.length ? `${results.length} unique hostname${results.length === 1 ? '' : 's'} discovered for ${currentDomain}.` : `Tidak ada subdomain yang ditemukan untuk ${currentDomain}.`;
    if (!visible.length && results.length) {
      resultsBody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:30px;color:#7886a0">No matching results</td></tr>';
    }
  }

  async function checkStatus() {
    try {
      const response = await fetch('/api/status');
      const data = await response.json();
      if (data.subfinder_available) {
        $('engine-state').textContent = 'Engine ready';
        $('engine-detail').textContent = 'Subfinder detected';
        $('status-light').classList.add('online');
      } else {
        $('engine-state').textContent = 'Engine not found';
        $('engine-detail').textContent = 'Install Subfinder first';
        $('status-light').classList.remove('online');
      }
    } catch {
      $('engine-state').textContent = 'Backend offline';
      $('engine-detail').textContent = 'Check deployment logs';
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const domain = domainInput.value.trim();
    if (!domain) { domainInput.focus(); return; }
    scanButton.disabled = true;
    scanButton.innerHTML = '<span class="btn-icon">◌</span> Searching...';
    $('stat-count').textContent = '…';
    $('stat-time').textContent = '…';
    $('time-unit').textContent = '';
    $('stat-count').style.color = '';
    setActions(false);
    setState('loading');
    try {
      const response = await fetch('/api/scan', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''},
        body: JSON.stringify({domain})
      });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || 'Pencarian gagal.');
      currentDomain = data.domain;
      results.splice(0, results.length, ...data.results);
      $('stat-count').textContent = String(data.count);
      $('stat-time').textContent = data.elapsed_seconds < 60 ? String(data.elapsed_seconds) : (data.elapsed_seconds / 60).toFixed(1);
      $('time-unit').textContent = data.elapsed_seconds < 60 ? 'sec' : 'min';
      $('stat-count').style.color = data.count ? '#e9e6ff' : '#95a2ba';
      renderRows($('filter-input').value);
      setState(data.count ? 'table' : 'empty');
      setActions(data.count > 0);
      if (data.count) toast(`${data.count} subdomain ditemukan.`);
      else toast('Pencarian selesai, tidak ada hasil.');
    } catch (error) {
      setState('error');
      $('error-text').textContent = error.message || 'Terjadi kesalahan yang tidak diketahui.';
      $('stat-count').textContent = '—';
      $('stat-time').textContent = '—';
      $('time-unit').textContent = '';
    } finally {
      scanButton.disabled = false;
      scanButton.innerHTML = '<span class="btn-icon">⌕</span> Find subdomains <span class="button-arrow">↗</span>';
    }
  });

  $('filter-input').addEventListener('input', (event) => renderRows(event.target.value));
  $('copy-button').addEventListener('click', async () => {
    if (!results.length) return;
    try { await navigator.clipboard.writeText(results.join('\n')); toast(`${results.length} subdomain disalin.`); }
    catch { toast('Clipboard tidak tersedia di browser ini.'); }
  });
  $('export-button').addEventListener('click', () => {
    if (!results.length) return;
    const quote = (value) => `"${String(value).replaceAll('"', '""')}"`;
    const rows = [['subdomain', 'parent_domain', 'type'], ...results.map(host => [host, currentDomain, 'SUBDOMAIN'])];
    const csv = '\ufeff' + rows.map(row => row.map(quote).join(',')).join('\r\n');
    const blob = new Blob([csv], {type: 'text/csv;charset=utf-8;'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${currentDomain}-subdomains.csv`;
    document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    toast('CSV berhasil diekspor.');
  });

  checkStatus();
})();
