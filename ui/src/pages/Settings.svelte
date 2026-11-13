<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import Seg from "../lib/Seg.svelte";
  import Switch from "../lib/Switch.svelte";
  import { store, type Theme } from "../lib/store.svelte";
  import { dateTime, netCategoryLabel } from "../lib/format";
  import { i18n, t, type LangPref } from "../lib/i18n/index.svelte";

  const s = $derived(store.status!);

  function setOption(lan: boolean | null, learn: boolean | null) {
    store.act({ SetOptions: { lan_discovery: lan, learn_publishers: learn } }, t("toast.saved"));
  }

  const systemLangName = $derived(i18n.system === "de" ? "Deutsch" : "English");
</script>

<section class="page">
  <div class="page-head"><div><h1>{t("nav.settings")}</h1></div></div>

  <h2 style="margin-top:0">{t("settings.general")}</h2>
  <div class="card">
    <div class="setting">
      <div class="ic"><Icon name="globe" size={18} /></div>
      <div class="grow"><b>{t("settings.language")}</b><span class="faint">{t("settings.language.desc", { lang: systemLangName })}</span></div>
      <Seg
        label={t("settings.language")}
        options={[
          { value: "system", label: t("settings.system") },
          { value: "de", label: "Deutsch" },
          { value: "en", label: "English" },
        ] as { value: LangPref; label: string }[]}
        value={i18n.pref}
        onchange={(v) => store.setLanguage(v)} />
    </div>
    <div class="setting">
      <div class="ic"><Icon name="moon" size={18} /></div>
      <div class="grow"><b>{t("settings.theme")}</b><span class="faint">{t("settings.theme.desc")}</span></div>
      <Seg
        label={t("settings.theme")}
        options={[
          { value: "system", label: t("settings.system") },
          { value: "light", label: t("settings.theme.light") },
          { value: "dark", label: t("settings.theme.dark") },
        ] as { value: Theme; label: string }[]}
        value={store.theme}
        onchange={(v) => store.setTheme(v)} />
    </div>
    <div class="setting">
      <div class="ic"><Icon name="bell" size={18} /></div>
      <div class="grow"><b>{t("settings.notify")}</b><span class="faint">{t("settings.notify.desc")}</span></div>
      <Switch on={store.prefs.notifications} label={t("settings.notify")} onchange={(v) => store.setNotifications(v)} />
    </div>
    <div class="setting">
      <div class="ic"><Icon name="power" size={18} /></div>
      <div class="grow"><b>{t("settings.autostart")}</b><span class="faint">{t("settings.autostart.desc")}</span></div>
      <Switch on={store.prefs.autostart} label={t("settings.autostart")} onchange={(v) => store.setAutostart(v)} />
    </div>
  </div>

  <h2>{t("settings.security")}</h2>
  <div class="card">
    <div class="setting">
      <div class="ic"><Icon name="fingerprint" size={18} /></div>
      <div class="grow">
        <b>{t("settings.hello")}</b>
        <span class="faint">
          {#if s.hello_enrolled}
            {t("settings.hello.active")}
          {:else if store.helloSupported}
            {t("settings.hello.available")}
          {:else}
            {t("settings.hello.unavailable")}
          {/if}
        </span>
      </div>
      {#if s.hello_enrolled}
        <button class="btn ghost sm" onclick={() => store.removeHello()}>{t("common.disable")}</button>
      {:else if store.helloSupported}
        <button class="btn primary sm" onclick={() => store.enrollHello()}>{t("common.setUp")}</button>
      {/if}
    </div>
  </div>

  <h2>{t("overview.network")}</h2>
  <div class="card">
    <div class="setting">
      <div class="ic"><Icon name="wifi" size={18} /></div>
      <div class="grow">
        <b>{t("settings.lan")}</b>
        <span class="faint">{t("settings.lan.desc")}</span>
      </div>
      <Switch on={s.settings.lan_discovery} label={t("settings.lan")} onchange={(v) => setOption(v, null)} />
    </div>
    {#each s.networks as n (n.id)}
      <div class="setting">
        <div class="ic"><Icon name="globe" size={18} /></div>
        <div class="grow">
          <b>{n.name}</b>
          <span class="faint">
            {t("settings.net.connected", { category: netCategoryLabel(n.windows_category) })}{n.explicit ? ` · ${t("settings.net.explicit")}` : ""}
          </span>
        </div>
        {#if n.explicit}
          <button class="btn ghost sm" onclick={() => store.act({ SetNetworkTrust: { id: n.id, trusted: null } }, t("toast.followsWindows"))}>
            {t("settings.net.likeWindows")}
          </button>
        {/if}
        <Seg
          label={t("net.type")}
          options={[
            { value: "public", label: t("net.public") },
            { value: "home", label: t("net.home") },
          ]}
          value={n.trusted ? "home" : "public"}
          onchange={(v) => store.act({ SetNetworkTrust: { id: n.id, trusted: v === "home" } }, t("toast.saved"))} />
      </div>
    {/each}
  </div>

  <h2>{t("settings.learning")}</h2>
  <div class="card">
    <div class="setting">
      <div class="ic"><Icon name="learn" size={18} /></div>
      <div class="grow">
        <b>{t("settings.learn")}</b>
        <span class="faint">{t("settings.learn.desc")}</span>
      </div>
      <Switch on={s.settings.learn_publishers} label={t("settings.learn")} onchange={(v) => setOption(null, v)} />
    </div>
    {#each s.settings.learned_publishers as p (p)}
      <div class="setting">
        <div style="width:36px"></div>
        <div class="grow"><b style="font-weight:500">{p}</b><span class="faint">{t("settings.learned")}</span></div>
        <button class="btn ghost sm" onclick={() => store.act({ RemovePublisher: p }, t("toast.publisherRemoved", { publisher: p }))}>
          {t("common.remove")}
        </button>
      </div>
    {/each}
  </div>

  <h2>{t("settings.how")}</h2>
  <div class="card">
    <div class="setting">
      <div class="ic"><Icon name="fingerprint" size={18} /></div>
      <div class="grow"><b>{t("how.origin")}</b><span class="faint">{t("how.origin.desc")}</span></div>
    </div>
    <div class="setting">
      <div class="ic"><Icon name="alert" size={18} /></div>
      <div class="grow"><b>{t("how.tools")}</b><span class="faint">{t("how.tools.desc")}</span></div>
    </div>
    <div class="setting">
      <div class="ic"><Icon name="lock" size={18} /></div>
      <div class="grow"><b>{t("how.asym")}</b><span class="faint">{t("how.asym.desc")}</span></div>
    </div>
    <div class="setting">
      <div class="ic"><Icon name="refresh" size={18} /></div>
      <div class="grow"><b>{t("how.tamper")}</b><span class="faint">{t("how.tamper.desc")}</span></div>
    </div>
  </div>

  <h2>{t("settings.about")}</h2>
  <div class="card pad">
    <dl class="kv">
      <dt>{t("about.version")}</dt><dd>{s.version}</dd>
      <dt>{t("about.engine")}</dt>
      <dd>
        {#if s.engine_ok}
          <span class="state ok"><i></i>{t("about.engine.ok")}</span>
        {:else}
          <span class="state warn"><i></i>{s.engine_error ?? t("about.engine.na")}</span>
        {/if}
      </dd>
      <dt>{t("about.since")}</dt><dd>{dateTime(s.started)}</dd>
      <dt>{t("about.known")}</dt><dd>{s.apps_total}</dd>
    </dl>
  </div>
</section>
