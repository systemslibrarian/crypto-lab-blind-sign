import './style.css';

const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
const panels = Array.from(document.querySelectorAll<HTMLElement>('.panel'));

for (const tab of tabs) {
  tab.addEventListener('click', () => {
    tabs.forEach((btn) => btn.classList.remove('active'));
    panels.forEach((panel) => panel.classList.remove('active'));
    tab.classList.add('active');
    const panel = document.getElementById(tab.dataset.panel ?? '');
    panel?.classList.add('active');
  });
}

const protocolPanel = document.getElementById('protocol');
if (protocolPanel) {
  protocolPanel.innerHTML = `
    <div class="card">
      <h2>Protocol Overview</h2>
      <p>Scaffold ready. Protocol exhibit implementation begins in Phase 6.</p>
    </div>
  `;
}
