(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const definitions = [
    ['proxy', '代理网络', 'Proxy', '⇄'], ['vpn', 'VPN 网络', 'Virtual private network', '◇'],
    ['tor', 'Tor 出口', 'Tor exit node', '◎'], ['hosting', '数据中心', 'Datacenter / hosting', '▤'],
    ['compromised', '受控设备', 'Compromised device', '⊡'], ['scraper', '自动采集', 'Scraper', '⌘'],
    ['anonymous', '匿名网络', 'Anonymous network', '◌']
  ];
  let report = null;
  let pendingAddress = null;
  let querySequence = 0;
  let runningController = null;
  let connectionSequence = 0;
  let toastTimer;
  const mask = ip => ip.includes(':') ? ip.split(':').slice(0, 2).join(':') + ':••••:••••' : ip.split('.').slice(0, 2).join('.') + '.•••.•••';
  const displayIP = ip => $('hide-ip').checked ? mask(ip) : ip;
  const locationText = loc => loc ? [...new Set([loc.country, loc.region, loc.city].filter(Boolean))].join(' · ') || '暂无位置数据' : '暂无位置数据';
  const text = (id, value) => { $(id).textContent = value ?? '—'; };
  function element(tag, cls, content) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (content !== undefined) node.textContent = content;
    return node;
  }
  function renderSignals(flags = {}) {
    $('risk-grid').replaceChildren(...definitions.map(([key, name, english, icon]) => {
      const value = flags[key];
      const item = element('article', 'risk-item');
      const body = element('div', 'signal-body');
      body.append(element('h3', '', name), element('p', '', english));
      item.append(element('span', 'signal-icon', icon), body, element('span', 'signal-state' + (value === true ? ' bad' : value === false ? ' good' : ''), value === true ? '已标记' : value === false ? '未发现' : '未知'));
      return item;
    }));
  }
  function renderSources(sources = []) {
    $('source-grid').replaceChildren(...['proxycheck.io', 'ipwho.is'].map(name => {
      const source = sources.find(s => s.name === name);
      const ok = source?.status === 'ok';
      const card = element('article', 'source-card');
      const title = element('div', 'source-title');
      const heading = element('h3');
      const link = element('a', '', name + ' ↗');
      link.href = name === 'proxycheck.io' ? 'https://proxycheck.io/' : 'https://ipwhois.io/';
      link.target = '_blank'; link.rel = 'noopener noreferrer'; heading.append(link);
      title.append(heading, element('span', 'source-status', source ? ok ? '● 查询成功' : '○ 暂不可用' : '○ 等待查询'));
      const facts = element('div', 'source-facts');
      const rows = ok ? [['查询地址', displayIP(report.ip)], ['地理位置', locationText(source.location)], ['网络归属', source.network?.org || '未知'], ['网络编号', source.network?.asn || '未知']] : [['状态说明', source?.message || '正在等待检测结果']];
      rows.forEach(([label, value]) => { const row = element('div'); row.append(element('span', '', label), element('strong', '', value)); facts.append(row); });
      const note = source?.warning || (name === 'proxycheck.io' ? '提供风险分数与网络特征，是本页风险判断的来源。' : '提供网络归属与地理位置，不参与纯净度评分。');
      card.append(title, facts, element('p', 'source-note', note));
      return card;
    }));
  }
  function renderReport() {
    if (!report) return;
    const d = report;
    text('result-ip', displayIP(d.ip));
    $('result-ip').classList.toggle('ipv6', d.ip.includes(':'));
    text('ip-version', d.ip.includes(':') ? 'IPv6' : 'IPv4');
    text('location-line', locationText(d.location));
    text('org', d.network?.org || '未知'); text('asn', d.network?.asn || '未知');
    const types = { Residential: '住宅网络', Business: '商业网络', Hosting: '机房网络', Wireless: '无线网络', Mobile: '移动网络', VPN: 'VPN 网络', SOCKS: '代理网络', HTTP: '代理网络', Compromised: '受控设备', TOR: 'Tor 网络' };
    text('network-type', d.flags.hosting === true ? '机房网络' : types[d.network?.type] || d.network?.type || '未知');
    text('timezone', d.location?.timezone || '未知');
    text('score', d.score === null ? '—' : d.score);
    const labels = { unknown: '数据不足', high: '风险较高', medium: '需要留意', low: '记录风险较低' };
    const colors = { unknown: '#a6b798', high: '#bc7659', medium: '#c3a15c', low: '#80a663' };
    text('risk-label', labels[d.level]);
    $('risk-label').style.color = colors[d.level];
    text('score-description', d.score === null ? '暂未取得风险分数，无法判断纯净度。' : `来源风险值 ${d.risk} / 100。请结合下方标记理解结果。`);
    $('gauge').style.setProperty('--score', d.score ?? 0);
    $('gauge').style.setProperty('--gauge-color', colors[d.level]);
    text('coverage', d.coverage); $('coverage-fill').style.width = `${d.coverage / d.total * 100}%`;
    text('source-count', `${d.sources.filter(s => s.status === 'ok').length} / 2`);
    const marked = Object.values(d.flags).filter(v => v === true).length;
    text('flag-count', d.coverage ? `${marked} 项` : '未知');
    text('data-status', d.coverage === d.total && d.score !== null ? '风险数据完整' : '部分数据缺失');
    text('report-state', d.score === null ? '数据不足' : '检测完成');
    text('checked-at', `${new Date(d.checkedAt).toLocaleTimeString('zh-CN', { hour12: false })} ${d.cached ? '· 近期结果' : '· 已更新'}`);
    text('interpretation', d.score === null ? '风险数据暂不可用，目前不能判断是否纯净。你仍可查看网络归属与位置，稍后再次检测。' : marked ? '已发现的标记仅代表数据源记录的网络特征，不等于恶意行为。机房和隐私工具也有正常用途，请结合用途判断。' : '当前数据源未发现上述风险标记。数据库可能存在延迟或遗漏，这不代表绝对安全，也不保证任何平台可用。');
    $('copy-ip').disabled = false;
    renderSignals(d.flags); renderSources(d.sources);
  }
  async function getJSON(url, signal) {
    const response = await fetch(url, { signal, headers: { Accept: 'application/json' }, cache: 'no-store' });
    let data;
    try { data = await response.json(); } catch { throw new Error('检测服务暂时不可用，请稍后重试'); }
    if (!response.ok || data.error) throw new Error(data.error || '检测服务暂时不可用，请稍后重试');
    return data;
  }
  function validAddress(ip) {
    if (ip.includes(':')) { try { return new URL(`http://[${ip}]/`).hostname.startsWith('['); } catch { return false; } }
    return /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(ip) && ip.split('.').every(n => Number(n) <= 255);
  }
  async function currentIP(signal) {
    for (const endpoint of ['https://api.ipify.org?format=json', 'https://api64.ipify.org?format=json', 'https://ipwho.is/']) {
      try {
        const timeout = AbortSignal.timeout(4500);
        const data = await getJSON(endpoint, AbortSignal.any([signal, timeout]));
        if (validAddress(data.ip || '')) return data.ip;
      } catch (e) { if (signal.aborted) throw e; }
    }
    throw new Error('暂时无法获取当前 IP，请手动输入后重试');
  }
  async function run(value) {
    const input = value.trim();
    if (input && !validAddress(input)) { text('query-error', '请输入有效的 IPv4 或 IPv6 地址，例如 8.8.8.8'); $('query-error').hidden = false; return; }
    runningController?.abort();
    const controller = new AbortController(); runningController = controller;
    const id = ++querySequence;
    $('query-error').hidden = true;
    $('submit').disabled = true;
    text('submit', '正在检测…'); text('report-state', '正在检测');
    $('results').setAttribute('aria-busy', 'true');
    text('checked-at', input ? '正在查询所选 IP…' : '正在获取当前 IP…');
    // Clear the previous result so it cannot be mistaken for the next query.
    report = null; pendingAddress = input || null; $('copy-ip').disabled = true;
    text('result-ip', input ? displayIP(input) : '正在获取…'); text('score', '—');
    text('risk-label', '等待检测'); text('score-description', '正在查找风险记录，通常需要几秒钟。');
    $('gauge').style.setProperty('--score', 0); text('coverage', '—'); $('coverage-fill').style.width = '0%';
    ['org', 'asn', 'network-type', 'timezone', 'source-count', 'flag-count'].forEach(key => text(key, '—'));
    text('data-status', '查询中'); text('location-line', '等待位置查询'); text('ip-version', '公网 IP');
    text('interpretation', '检测将查询第三方数据库。所查 IP 会发送给所列数据源；本工具不保存查询历史。');
    renderSignals(); renderSources();
    try {
      const address = input || await currentIP(controller.signal);
      if (id !== querySequence) return;
      pendingAddress = address;
      text('result-ip', displayIP(address));
      const data = await getJSON(`/api/check?ip=${encodeURIComponent(address)}`, AbortSignal.any([controller.signal, AbortSignal.timeout(18000)]));
      if (id !== querySequence) return;
      report = data;
      renderReport();
    } catch (error) {
      if (id !== querySequence || controller.signal.aborted) return;
      text('query-error', error.name === 'TimeoutError' ? '查询超时，请检查网络后重试' : error.message);
      $('query-error').hidden = false; text('report-state', '查询未完成'); text('checked-at', '可再次检测');
      text('risk-label', '暂时无法检测'); text('score-description', '本次查询未完成，请稍后重试。');
      text('data-status', '查询未完成');
      text('interpretation', '本次检测未完成，不能据此判断 IP 是否纯净。请检查地址或稍后重试。');
      renderSources([{ name: 'proxycheck.io', status: 'error', message: '本次查询未完成' }, { name: 'ipwho.is', status: 'error', message: '本次查询未完成' }]);
    } finally {
      if (id === querySequence) { $('submit').disabled = false; $('submit').replaceChildren(document.createTextNode('开始检测 '), element('span', '', '↗')); $('results').setAttribute('aria-busy', 'false'); }
    }
  }
  $('query-form').addEventListener('submit', e => { e.preventDefault(); run($('ip-input').value); });
  $('current-ip').addEventListener('click', () => { $('ip-input').value = ''; run(''); });
  $('hide-ip').addEventListener('change', () => {
    $('ip-input').type = $('hide-ip').checked ? 'password' : 'text';
    if (report) renderReport();
    else if (pendingAddress) text('result-ip', displayIP(pendingAddress));
  });
  $('copy-ip').addEventListener('click', async () => {
    if (!report) return;
    try { await navigator.clipboard.writeText(report.ip); text('toast', 'IP 地址已复制'); }
    catch { text('toast', '无法自动复制，请手动选择地址复制'); }
    $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 2300);
  });
  const sites = [['百度', 'https://www.baidu.com/favicon.ico'], ['网易云音乐', 'https://s1.music.126.net/style/favicon.ico'], ['GitHub', 'https://github.com/favicon.ico'], ['YouTube', 'https://www.youtube.com/favicon.ico']];
  function renderConnections() {
    $('connectivity-grid').replaceChildren(...sites.map(([name], i) => { const row = element('div', 'connection-item'); const state = element('span', '', '待检查'); state.id = `connection-${i}`; row.append(element('strong', '', name), state); return row; }));
  }
  $('check-connectivity').addEventListener('click', async () => {
    const id = ++connectionSequence;
    $('check-connectivity').disabled = true; text('check-connectivity', '正在检查…');
    await Promise.all(sites.map(([, url], i) => new Promise(resolve => {
      const state = $(`connection-${i}`); state.textContent = '检查中…'; state.className = '';
      const image = new Image(); let timer;
      const done = success => { clearTimeout(timer); image.onload = image.onerror = null; if (id === connectionSequence) { state.textContent = success ? '可以连接' : '未能确认'; state.className = success ? 'good' : ''; } resolve(); };
      image.onload = () => done(true); image.onerror = () => done(false); timer = setTimeout(() => done(false), 6000);
      image.referrerPolicy = 'no-referrer'; image.src = `${url}?t=${Date.now()}`;
    })));
    if (id === connectionSequence) { $('check-connectivity').disabled = false; text('check-connectivity', '重新检查 ↗'); }
  });
  renderSignals(); renderSources(); renderConnections();
  run('');
})();
