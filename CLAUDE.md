# CLAUDE.md

Guidance for agents working in this repo. `DEVELOPMENT_GUIDE.md` has the
long-form dev setup; `README.md` the product overview.

## Project overview

BetGlobal is a peer-to-peer betting platform: Flask + Jinja2 + SQLAlchemy,
Flask-Security-Too for auth, Stripe for deposits/payouts. A single `app.py`
holds the routes; `models.py` the ORM and bet lifecycle helpers; `forms.py`
the registration form. Templates live in `templates/`, assets in `static/`.

- Dev database: Postgres in Docker by default (`docker-compose.dev.yml`,
  `setup_dev.py`). A SQLite `DATABASE_URL` in `.env.development` also works;
  use an absolute path (`sqlite:///C:/.../instance/bets_dev.db`) because
  Flask-SQLAlchemy resolves relative SQLite paths against the instance folder.
- Run: `python run_dev.py` (loads `.env.development`, creates tables, seeds
  `john@example.com` / `jane@example.com`, password `password123`; admin
  password `admin123`).
- Smoke test: `python -m pytest tests/test_app_smoke.py -q` renders every
  page (public, member, admin) against a throwaway SQLite database. Run it
  after any template or CSS change.

## Front end: the v3 "Ledger" design system

No framework, no build step. Three stylesheets under `static/css/`, loaded in
order by `templates/_layout.html`, plus `static/betglobal.js` and the bundled
`static/feather.min.js`. Fonts: Inter + JetBrains Mono from Google Fonts
(the only third-party origin; see the CSP in `app.py`).

### Files

| File | Holds |
|---|---|
| `static/css/tokens.css` | Every custom property on `:root`: warm-stone surfaces, navy/green brand, semantic pos/warn/neg/info, radii (`--r-item` 7, `--r-ctl` 9, `--r-pop` 12, `--r-card` 14), shadows (`--sh-ctl`, `--sh-card`, `--sh-pop`, `--sh-modal`, `--sh-focus`), type scale (`--fs-2xs` … `--fs-h1`, `--fs-display`), motion (`--dur-fast/base/slow`, `--ease-out/spring`), shell metrics (`--sidebar-w`, `--topbar-h`, `--gutter`). The dark palette is defined twice: under `@media (prefers-color-scheme: dark)` guarded by `:root:not([data-theme="light"])`, and under `:root[data-theme="dark"]`. |
| `static/css/components.css` | Reset, typography classes (`.display`, `.title-*`, `.lede*`, `.body*`, `.meta`, `.eyebrow`, `.hint`), layout utilities (`.wrap*`, `.pad*`, `.grid .g2-.g5`, `.row`, `.col`, `.spacer`, `.mt-*`, `.gap-*`), and components: `.btn` (+ `-primary` green, `-ink` navy, `-secondary`/`-ghost`, `-quiet`, `-danger`, `-soft`, `-on-dark`; sizes `-lg/-sm/-xs/-block/-icon`), `.icon-btn`, `.input/.select/.textarea`, `.input-affix`, `.check`, `.code-cell`, `.preset`, `.segmented`, `.card` (+ `-head/-body/-row/-foot`, `-warn`, `-tint`, `-navy`), `.tile`, `.avatar`, `.badge` (+ `badge-<status>` for every bet status), `.status-dot`, `.chip`, `.pill`, `.kpi` tiles (`.kpi-grid`, `.is-accent/-warn/-navy` underline), `.figure-strip`, `.dtable`, `.meter`, `.empty` (+ `.empty-dashed`), `.alert`/`.notice`, `.flash-stack` (toast column), `.modal-*`, `.pop`/`.pop-item`, `.steps`, keyframes and the reduced-motion guard. |
| `static/css/layout.css` | Shells and page patterns: `.site-header` + `.nav-link` + `.mobile-nav`, `.site-footer`, `.shell` grid with the `.sidebar` rail (wallet `.sb-balance` card, `.sb-nav`, `.sb-user`) and `.sidebar-admin` navy variant, the glass `.topbar` + `.usermenu`, `.searchbox`, `.filterbar`, `.bet-grid`/`.bet-card`, landing (`.hero`, `.bento`, `.band*`), auth (`.split`, `.split-aside`, `.centered-page`, `.staff-page`), content pages (`.content-shell`), admin (`.queue`, `.split-pane`, `.bars`), `.editor-layout` for create-bet, and the responsive rules (1180 / 960 / 720 px; 16 px gutters at phone width, no horizontal scroll). |
| `static/betglobal.js` | Modals (`BG.openModal/closeModal`, `data-modal-open/close`, shared confirm/notify/image dialogs with the legacy `showConfirmationModal` / `showNotificationModal` / `showImageModal` globals), `data-dismiss-alert`, `data-usermenu-toggle` (`#userMenuPanel`), `data-sidebar-toggle` + `.scrim`, `data-mobile-nav-toggle` (public header), `data-theme-toggle` (persists `bg-theme` in localStorage; `_layout.html` applies it before paint), `BG.toast`, `BG.setButtonLoading` (`aria-busy`), `data-preset-target/value`, `data-currency`, `data-auto-resize`. |

### Shells

- `templates/_layout.html`: the `<head>`, stylesheet links, theme bootstrap.
- `templates/landing_base.html`: public header/footer (signed-out visitors;
  landing, auth, how-it-works, fees, legal).
- `templates/base.html`: member shell (sidebar rail + topbar). Blocks:
  `page_title`, `page_subtitle`, `topbar_extra`, `content`, `scripts`.
- `templates/admin_base.html`: admin shell (navy rail). Blocks:
  `admin_title`, `admin_subtitle`, `content`, `scripts`.
- `templates/_flash.html`: flash messages as a toast stack (bottom-right;
  top on phones), auto-dismissed by JS. `templates/_content_page.html`:
  shared TOC + sections body for terms/privacy/contact.

### Rules

- Colours only through tokens; never a raw hex in a template or page CSS.
  Check both themes: the OS preference and the topbar toggle (`data-theme`).
- Page-specific inline scripts (bets list, dashboard, wallet, create bet,
  admin disputes, verify code) depend on element ids and `data-*` hooks;
  restyle around them, do not rename them.
- Icons are feather (`<i data-feather="...">`); size with `.i-12 … .i-20`
  utilities or the parent component's rule, not inline styles.
- Inspiration lineage: swejoblists' "interior-dev" port (warm neutrals,
  radii/shadow/motion tokens, `.pop`, `.meter`, toast stack, segmented
  control) and 21st.dev patterns (bento feature grid, gradient wallet card,
  glass topbar, dotted-grid hero, stat tiles with an accent underline).
