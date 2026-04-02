(function () {
  function updateClock() {
    const el = document.getElementById('topbar-time');
    if (el) el.textContent = new Date().toLocaleString();
  }

  async function refreshTopState() {
    try {
      const [scanResp, notifyResp, dashResp] = await Promise.all([
        fetch('/scan-listener/status', { credentials: 'same-origin' }),
        fetch('/notifications/status', { credentials: 'same-origin' }),
        fetch('/dashboard/summary', { credentials: 'same-origin' }),
      ]);
      if (scanResp.ok) {
        const data = await scanResp.json();
        const dot = document.getElementById('scan-dot');
        const text = document.getElementById('scan-text');
        if (dot && text) {
          dot.className = 'dot ' + (data.running ? 'ok' : 'warn');
          text.textContent = '扫描监听 ' + (data.running ? '在线' : '离线');
        }
      }
      if (notifyResp.ok) {
        const data = await notifyResp.json();
        const dot = document.getElementById('notify-dot');
        const text = document.getElementById('notify-text');
        if (dot && text) {
          dot.className = 'dot ' + (data.enabled ? 'ok' : 'warn');
          text.textContent = '通知 ' + (data.enabled ? '启用' : '关闭');
        }
      }
      if (dashResp.ok) {
        const data = await dashResp.json();
        const stats = data.stats || {};
        const risk = data.risk_summary || {};
        const topEvents = document.getElementById('top-events');
        const topPolicies = document.getElementById('top-policies');
        const topBlocked = document.getElementById('top-blocked');
        const topCritical = document.getElementById('top-critical');
        if (topEvents) topEvents.textContent = stats.events ?? '-';
        if (topPolicies) topPolicies.textContent = stats.policies ?? '-';
        if (topBlocked) topBlocked.textContent = stats.blocked ?? '-';
        if (topCritical) topCritical.textContent = risk.critical ?? '-';
      }
    } catch (e) {
    }
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function sortArrow(currentSortBy, currentSortOrder, field) {
    if (currentSortBy !== field) return '';
    return currentSortOrder === 'asc' ? '▲' : '▼';
  }

  function mountGrid(config) {
    const state = {
      page: Number(config.page || 1),
      page_size: Number(config.pageSize || 20),
      sort_by: config.sortBy || 'id',
      sort_order: config.sortOrder || 'desc',
      q: config.query || '',
    };
    const bodyEl = document.getElementById(config.bodyId);
    const totalEl = document.getElementById(config.totalId);
    const prevEl = document.getElementById(config.prevId);
    const nextEl = document.getElementById(config.nextId);
    const pageEl = document.getElementById(config.pageId);
    const sizeEl = document.getElementById(config.pageSizeId);
    const searchEl = document.getElementById(config.searchId);
    const refreshEl = document.getElementById(config.refreshId);
    const loadingEl = document.getElementById(config.loadingId);

    if (sizeEl) sizeEl.value = String(state.page_size);
    if (searchEl) searchEl.value = state.q;

    const requestRefresh = async () => {
      const params = new URLSearchParams({
        page: String(state.page),
        page_size: String(state.page_size),
        sort_by: state.sort_by,
        sort_order: state.sort_order,
        q: state.q,
      });
      if (loadingEl) loadingEl.style.display = 'flex';
      try {
        const resp = await fetch(config.api + '?' + params.toString(), { credentials: 'same-origin' });
        if (!resp.ok) return;
        const data = await resp.json();
        const items = data.items || [];
        const pagination = data.pagination || {};
        bodyEl.innerHTML = items.length
          ? items.map(item => config.renderRow(item, data)).join('')
          : `<tr><td colspan="${config.colspan || 1}"><div class="empty-state">暂无数据</div></td></tr>`;
        if (totalEl) totalEl.textContent = `第 ${pagination.page || 1} / ${pagination.total_pages || 1} 页，共 ${pagination.total || 0} 条`;
        if (pageEl) pageEl.textContent = `${pagination.page || 1} / ${pagination.total_pages || 1}`;
        if (prevEl) prevEl.disabled = !pagination.has_prev;
        if (nextEl) nextEl.disabled = !pagination.has_next;
        document.querySelectorAll(`[data-grid="${config.name}"][data-sort]`).forEach(node => {
          const field = node.getAttribute('data-sort');
          const icon = node.querySelector('.sort-arrow');
          if (icon) icon.textContent = sortArrow(data.sort_by, data.sort_order, field);
        });
        if (typeof config.onData === 'function') config.onData(data, state);
      } catch (e) {
      } finally {
        if (loadingEl) loadingEl.style.display = 'none';
      }
    };

    document.querySelectorAll(`[data-grid="${config.name}"][data-sort]`).forEach(node => {
      node.addEventListener('click', () => {
        const field = node.getAttribute('data-sort');
        state.sort_order = state.sort_by === field && state.sort_order === 'desc' ? 'asc' : 'desc';
        state.sort_by = field;
        state.page = 1;
        requestRefresh();
      });
    });
    prevEl?.addEventListener('click', () => {
      if (prevEl.disabled) return;
      state.page = Math.max(1, state.page - 1);
      requestRefresh();
    });
    nextEl?.addEventListener('click', () => {
      if (nextEl.disabled) return;
      state.page += 1;
      requestRefresh();
    });
    sizeEl?.addEventListener('change', () => {
      state.page_size = Number(sizeEl.value || 20);
      state.page = 1;
      requestRefresh();
    });
    let timer = null;
    searchEl?.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        state.q = searchEl.value.trim();
        state.page = 1;
        requestRefresh();
      }, 260);
    });
    refreshEl?.addEventListener('click', () => requestRefresh());

    requestRefresh();
    if (config.refreshMs) {
      setInterval(() => {
        if (!document.hidden) requestRefresh();
      }, config.refreshMs);
    }
  }

  window.PiGuardUI = {
    escapeHtml,
    sortArrow,
    mountGrid,
  };

  updateClock();
  refreshTopState();
  setInterval(updateClock, 1000);
  setInterval(refreshTopState, 5000);
})();
