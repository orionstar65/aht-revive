const trigger = document.getElementById('menu-toggle');
const nav = document.getElementById('main-nav');
if (trigger && nav) {
  trigger.addEventListener('click', () => {
    const opened = nav.classList.toggle('open');
    trigger.setAttribute('aria-expanded', String(opened));
    trigger.textContent = opened ? '×' : '☰';
  });
}
