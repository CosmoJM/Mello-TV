// Mello library admin. Talks to /api with the admin key kept in localStorage.
// All server data is inserted with textContent, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);

function status(text) { $("status").textContent = text; }

// Requests carry the session cookie automatically; the custom header proves
// they come from this page (the server rejects cookie requests without it).
async function request(method, path, body) {
  const headers = { "X-Mello-Request": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch("/api" + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  return { response, data };
}

async function api(method, path, body) {
  const { response, data } = await request(method, path, body);
  if (response.status === 401) {
    await route();
    throw new Error("Please sign in again.");
  }
  if (!response.ok) throw new Error((data && data.error) || response.statusText);
  return data;
}

function item(label, meta, buttonText, onClick) {
  const li = document.createElement("li");
  const text = document.createElement("div");
  text.textContent = label;
  if (meta) {
    const small = document.createElement("div");
    small.className = "meta";
    small.textContent = meta;
    text.append(small);
  }
  li.append(text);
  if (buttonText) {
    const button = document.createElement("button");
    button.textContent = buttonText;
    button.className = buttonText === "Remove" ? "secondary" : "";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await onClick(); } catch (e) { status(e.message); button.disabled = false; }
    });
    li.append(button);
  }
  return li;
}

function empty(list, text) {
  const li = document.createElement("li");
  li.className = "empty";
  li.textContent = text;
  list.replaceChildren(li);
}

let inLibrary = new Set();

async function loadLibrary() {
  const lib = await api("GET", "/library");
  const list = $("library");
  const rows = [];
  inLibrary = new Set();
  for (const [kind, map] of [["movie", lib.movies || {}], ["tv", lib.shows || {}]]) {
    for (const [id, entry] of Object.entries(map)) {
      inLibrary.add(kind + ":" + id);
      rows.push({ kind, id, title: entry.title || "TMDB " + id, added: entry.added_at });
    }
  }
  rows.sort((a, b) => (b.added || "").localeCompare(a.added || ""));
  if (!rows.length) return empty(list, "Nothing yet. Search above to add a title.");
  list.replaceChildren(...rows.map((row) =>
    item(row.title, row.kind === "tv" ? "Show" : "Movie", "Remove", async () => {
      await api("DELETE", `/library/${row.kind}/${row.id}`);
      status(`Removed ${row.title}.`);
      await loadLibrary();
    })));
}

async function search(q) {
  const list = $("results");
  empty(list, "Searching…");
  const { results } = await api("GET", "/search?q=" + encodeURIComponent(q));
  if (!results.length) return empty(list, "No matches.");
  list.replaceChildren(...results.slice(0, 12).map((r) => {
    const have = inLibrary.has(r.media_type + ":" + r.id);
    const meta = [r.media_type === "tv" ? "Show" : "Movie", r.year].filter(Boolean).join(" · ");
    return item(r.title, meta, have ? null : "Add", async () => {
      await api("POST", `/library/${r.media_type}/${r.id}`);
      status(`Added ${r.title}. Jellyfin will show it after the next scan.`);
      await loadLibrary();
      await search(q);
    });
  }));
}

async function refreshStatus() {
  const s = await api("GET", "/status");
  const sync = s.library.last_sync || {};
  const when = sync.finished_at ? new Date(sync.finished_at).toLocaleString() : "not yet";
  const issues = (sync.failures || []).length;
  status(`${s.library.movies} movies, ${s.library.shows} shows · last sync ${when}` +
    (issues ? ` · ${issues} issue(s)` : "") + (s.tmdb_configured ? "" : " · TMDB key missing"));
}

function view(name) {
  for (const id of ["setup", "login", "app"]) $(id).hidden = id !== name;
}

function showSetup(reset) {
  view("setup");
  $("setup-title").textContent = reset ? "Reset your login" : "Create your login";
  $("setup-cancel").hidden = !reset;
  status(reset ? "Enter the API key and choose a new password." : "First visit: set up a login.");
}

async function route() {
  const { data } = await request("GET", "/session");
  if (!data) return status("Cannot reach the server.");
  if (data.logged_in) {
    view("app");
    $("who").textContent = "Signed in as " + data.username;
    try { await refreshStatus(); await loadLibrary(); } catch (e) { status(e.message); }
  } else if (data.account_exists) {
    view("login");
    status("Sign in to manage the library.");
  } else {
    showSetup(false);
  }
}

$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("setup-pass").value !== $("setup-pass2").value) return status("The passwords do not match.");
  const button = event.submitter;
  if (button) button.disabled = true;
  const { response, data } = await request("POST", "/account", {
    api_key: $("setup-key").value.trim(),
    username: $("setup-user").value.trim(),
    password: $("setup-pass").value,
  });
  if (button) button.disabled = false;
  if (!response.ok) return status((data && data.error) || "Could not save the login.");
  for (const id of ["setup-key", "setup-pass", "setup-pass2"]) $(id).value = "";
  await route();
});
$("setup-cancel").addEventListener("click", () => route());
$("forgot").addEventListener("click", () => showSetup(true));

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  if (button) button.disabled = true;
  status("Signing in…");
  const { response, data } = await request("POST", "/login", {
    username: $("login-user").value.trim(),
    password: $("login-pass").value,
  });
  if (button) button.disabled = false;
  $("login-pass").value = "";
  if (!response.ok) return status((data && data.error) || "Sign in failed.");
  await route();
});
$("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  search($("q").value.trim()).catch((e) => status(e.message));
});
$("sync").addEventListener("click", async (event) => {
  event.target.disabled = true;
  status("Syncing…");
  try { await api("POST", "/library/sync"); await refreshStatus(); await loadLibrary(); }
  catch (e) { status(e.message); }
  event.target.disabled = false;
});
$("logout").addEventListener("click", async () => {
  await request("POST", "/logout");
  await route();
});

route();
