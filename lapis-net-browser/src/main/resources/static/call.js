// Lapis Net call remote control (V0.8.7b). Plain vanilla JS, no framework, no build step - fetch() and
// EventSource against the routes installed by CallApi.kt (installCallRoutes). This page is a REMOTE
// CONTROL: the audio runs inside the node's JVM, the browser holds no call truth of its own. Every
// visible thing is rebuilt from the single `state` object below; there is no optimistic update - a
// button only ever asks the node to do something, and the UI changes when the node's event arrives.
//
// Conventions shared with dm.js / mail.js (see their headers):
// - Promise/.then()-based, NEVER async/await, no optional chaining and no spread in calls - the headless-browser test
//   engine (CallXssRenderingTest) cannot parse that syntax.
// - XSS hygiene (CRITICAL): every peer-/node-derived string reaches the DOM through textContent only,
//   via the single setText() helper. There is NO innerHTML anywhere in this file. Fingerprints, ids and
//   end reasons are sender-controlled in principle and are treated as hostile text.
// - The start link carries the session token in the URL FRAGMENT (#t=...). It is removed from the
//   address bar immediately (history.replaceState) and exchanged for an HttpOnly cookie.

const MAX_HISTORY_ROWS = 50;
const EVENT_TYPES = ["incoming", "ringing", "connecting", "active", "ended", "blocked"];
// Why a call was silently blocked (V0.9.15). The reason is computed on THIS node only and never sent to the caller:
// they get neither RINGING nor REJECT. Enum names come from the node; unknown ones fall back to the generic text.
const BLOCK_REASON_LABELS = {
  VERITAS_BELOW_THRESHOLD: "Blockiert – Veritas unter Schwelle",
  KARMA_BELOW_THRESHOLD: "Blockiert – Karma unter Schwelle",
  DEPOSIT_MISSING: "Blockiert – Lightning-Deposit fehlt",
  POLICY: "Blockiert – Annahmeregel",
};
const BLOCK_FALLBACK_LABEL = "Blockiert – Annahmeregel";
// A neutral (not red) crossed-out handset, drawn in the muted text colour.
const BLOCKED_GLYPH_PATH =
  "M6.6 10.8a15.1 15.1 0 0 0 6.6 6.6l2.2-2.2a1 1 0 0 1 1-.25 11.4 11.4 0 0 0 3.6.57 1 1 0 0 1 1 1V20a1 1 0 0 1-1 1A17 17 0 0 1 3 4a1 1 0 0 1 1-1h3.5a1 1 0 0 1 1 1c0 1.25.2 2.45.57 3.6a1 1 0 0 1-.25 1zM3 3l18 18";
const STATE_LABELS = {
  incoming: "Eingehender Anruf",
  ringing: "Klingelt ...",
  connecting: "Verbindung wird aufgebaut ...",
  active: "Im Gespräch",
};
const OUTCOME_LABELS = {
  BLOCKED: "blockiert",
  DECLINED: "abgelehnt",
  BUSY: "besetzt",
  RING_TIMEOUT: "nicht angenommen",
  CONNECT_TIMEOUT: "Verbindung fehlgeschlagen",
  UNSUPPORTED_MEDIA: "nicht unterstützt",
  MALFORMED_SIGNAL: "Fehler",
  LOCAL_ERROR: "Fehler",
  REMOTE_HANGUP: "beendet (Gegenseite)",
  LOCAL_HANGUP: "beendet",
  NONE: "beendet",
};

/** The one state object everything is rendered from. */
const state = {
  available: null, // null = unknown yet
  calls: {}, // callId -> { callId, peer, fp, kind, unaccepted, activeSince }
  history: [], // newest first
  pending: {}, // callId -> true while a button click awaits its event
  message: "",
};

let reconnected = false;
// Secret path segment of all call routes (returned by POST /api/call/session); see CallSessionToken.scope.
let callScope = null;
const SCOPE_STORAGE_KEY = "lapisCallScope";
let timerHandle = null;

/** The ONE place any node-/peer-derived string is written into the DOM. */
function setText(el, value) {
  el.textContent = value == null ? "" : String(value);
}

function el(id) {
  return document.getElementById(id);
}

function shortFingerprint(fingerprint) {
  if (!fingerprint || fingerprint.length <= 16) return fingerprint || "";
  return fingerprint.slice(0, 8) + "…" + fingerprint.slice(-6);
}

function formatClock(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  const two = (n) => (n < 10 ? "0" + n : "" + n);
  return two(d.getHours()) + ":" + two(d.getMinutes());
}

function formatDuration(totalSeconds) {
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return (m < 10 ? "0" + m : "" + m) + ":" + (s < 10 ? "0" + s : "" + s);
}

function fetchJson(url, options) {
  return fetch(url, options).then((response) => {
    const contentType = response.headers.get("content-type") || "";
    const bodyPromise = contentType.indexOf("application/json") >= 0 ? response.json() : Promise.resolve(null);
    return bodyPromise.then((body) => {
      if (!response.ok) {
        const error = new Error(body && body.error ? body.error : "request failed: " + response.status);
        error.status = response.status;
        throw error;
      }
      return body;
    });
  });
}

function callUrl(path) {
  return "/api/call/" + callScope + "/" + path;
}

function loadStoredScope() {
  try {
    return window.sessionStorage.getItem(SCOPE_STORAGE_KEY);
  } catch (e) {
    return null;
  }
}

function storeScope(scope) {
  try {
    window.sessionStorage.setItem(SCOPE_STORAGE_KEY, scope);
  } catch (e) {
    // Without storage a reload needs the start link again; nothing else breaks.
  }
}

function postJson(url, payload) {
  return fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "same-origin",
  });
}

// ---------------------------------------------------------------------------------------------
// Reducer: the only code that mutates `state`.

function recordHistory(row) {
  state.history.unshift(row);
  if (state.history.length > MAX_HISTORY_ROWS) state.history.length = MAX_HISTORY_ROWS;
}

function applyStatus(status) {
  state.available = !!status.available;
  const previous = state.calls;
  state.calls = {};
  (status.active || []).forEach((snapshot) => {
    const kind = { INCOMING_RINGING: "incoming", OUTGOING_RINGING: "ringing", CONNECTING: "connecting", ACTIVE: "active" }[
      snapshot.state
    ];
    if (!kind) return;
    const known = previous[snapshot.callId];
    state.calls[snapshot.callId] = {
      callId: snapshot.callId,
      peer: snapshot.peer,
      fp: snapshot.peerFingerprint,
      kind: kind,
      unaccepted: known ? known.unaccepted : false,
      activeSince: kind === "active" ? (known && known.activeSince) || Date.now() : null,
    };
  });
  state.history = (status.history || []).slice(0, MAX_HISTORY_ROWS).map((row) => ({
    callId: row.callId,
    peer: row.peer,
    fp: row.peerFingerprint,
    outcome: row.outcome,
    at: row.atEpochSecond,
    blocked: !!row.blocked,
    blockReason: row.blockReason || null,
  }));
  state.pending = {};
}

function applyEvent(evt) {
  delete state.pending[evt.callId];
  if (evt.type === "blocked") {
    recordHistory({
      callId: evt.callId,
      peer: evt.peer,
      fp: evt.peerFingerprint,
      outcome: "BLOCKED",
      at: Math.floor(Date.now() / 1000),
      blocked: true,
      blockReason: evt.blockReason || null,
    });
    return;
  }
  if (evt.type === "ended") {
    delete state.calls[evt.callId];
    recordHistory({
      callId: evt.callId,
      peer: evt.peer,
      fp: evt.peerFingerprint,
      outcome: evt.reason || "NONE",
      at: Math.floor(Date.now() / 1000),
      blocked: false,
    });
    return;
  }
  const existing = state.calls[evt.callId];
  state.calls[evt.callId] = {
    callId: evt.callId,
    peer: evt.peer,
    fp: evt.peerFingerprint,
    kind: evt.type,
    unaccepted: !!evt.unaccepted || (existing ? existing.unaccepted : false),
    activeSince: evt.type === "active" ? (existing && existing.activeSince) || Date.now() : null,
  };
}

function callsOfKind(kinds) {
  return Object.keys(state.calls)
    .map((id) => state.calls[id])
    .filter((c) => kinds.indexOf(c.kind) >= 0);
}

// ---------------------------------------------------------------------------------------------
// Rendering: rebuilds every dynamic part from `state`.

function makeActionButton(label, className, callId, action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  setText(button, label);
  button.disabled = !!state.pending[callId];
  button.addEventListener("click", () => callAction(callId, action));
  return button;
}

function buildCard(call, ringing) {
  const card = el("call-card-template").content.firstElementChild.cloneNode(true);
  if (ringing) card.classList.add("call-card--ringing");
  setText(card.querySelector(".call-card-peer"), shortFingerprint(call.fp));
  const stateEl = card.querySelector(".call-card-state");
  setText(stateEl, STATE_LABELS[call.kind] || call.kind);
  if (call.kind === "active") {
    const timer = document.createElement("span");
    timer.className = "call-timer";
    timer.id = "call-timer";
    setText(timer, " " + formatDuration(Math.floor((Date.now() - call.activeSince) / 1000)));
    stateEl.appendChild(timer);
  }
  card.querySelector(".call-unaccepted").hidden = !call.unaccepted;
  const actions = card.querySelector(".call-card-actions");
  if (ringing) {
    // Decline FIRST in DOM order (and visually) - the safe action is never behind the risky one.
    actions.appendChild(makeActionButton("Ablehnen", "call-reject btn-secondary", call.callId, "reject"));
    actions.appendChild(makeActionButton("Annehmen", "call-accept", call.callId, "accept"));
  } else {
    actions.appendChild(makeActionButton("Auflegen", "call-hangup", call.callId, "hangup"));
  }
  return card;
}

/** Replaces every child of [parent] with [nodes] (no spread syntax: the headless test engine's parser
 * rejects it). */
function replaceContent(parent, nodes) {
  while (parent.firstChild) parent.removeChild(parent.firstChild);
  nodes.forEach((node) => parent.appendChild(node));
}

function render() {
  const unavailable = state.available === false;
  el("call-unavailable").hidden = !unavailable;
  el("call-place").hidden = unavailable;

  const message = el("call-message");
  setText(message, state.message);
  message.hidden = !state.message;

  const ringing = callsOfKind(["incoming"]);
  const ongoing = callsOfKind(["ringing", "connecting", "active"]);

  replaceContent(el("call-ringing-list"), ringing.map((c) => buildCard(c, true)));
  el("call-ringing").hidden = ringing.length === 0;
  replaceContent(el("call-active-list"), ongoing.map((c) => buildCard(c, false)));
  el("call-active").hidden = ongoing.length === 0;

  const historyEl = el("call-history");
  replaceContent(
    historyEl,
    state.history.map((row) => {
      const item = el("call-history-template").content.firstElementChild.cloneNode(true);
      setText(item.querySelector(".call-history-peer"), shortFingerprint(row.fp));
      if (row.blocked) {
        item.classList.add("call-history--blocked");
        item.querySelector(".call-history-path").setAttribute("d", BLOCKED_GLYPH_PATH);
        item.querySelector(".call-history-path").setAttribute("fill", "none");
        item.querySelector(".call-history-path").setAttribute("stroke", "currentColor");
        item.querySelector(".call-history-path").setAttribute("stroke-width", "1.6");
        setText(
          item.querySelector(".call-history-outcome"),
          (row.blockReason && BLOCK_REASON_LABELS[row.blockReason]) || BLOCK_FALLBACK_LABEL,
        );
        item.querySelector(".call-history-settings").hidden = false;
      } else {
        setText(item.querySelector(".call-history-outcome"), OUTCOME_LABELS[row.outcome] || row.outcome);
      }
      setText(item.querySelector(".call-history-time"), formatClock(row.at));
      return item;
    }),
  );
  el("call-history-empty").hidden = state.history.length > 0;

  document.title = ringing.length > 0 ? "Eingehender Anruf · Lapis Net" : "Lapis Net - Anrufe";
  updateTimerLoop(ongoing.some((c) => c.kind === "active"));
}

/** A single 1 s interval that only rewrites the timer text; stopped when no call is active. */
function updateTimerLoop(hasActive) {
  if (hasActive && timerHandle === null) {
    timerHandle = setInterval(() => {
      const timer = el("call-timer");
      const active = callsOfKind(["active"])[0];
      if (timer && active) setText(timer, " " + formatDuration(Math.floor((Date.now() - active.activeSince) / 1000)));
    }, 1000);
  } else if (!hasActive && timerHandle !== null) {
    clearInterval(timerHandle);
    timerHandle = null;
  }
}

function showMessage(text) {
  state.message = text || "";
  render();
}

// ---------------------------------------------------------------------------------------------
// Actions and data flow.

function callAction(callId, action) {
  if (state.pending[callId]) return Promise.resolve();
  state.pending[callId] = true;
  render();
  return postJson(callUrl(callId + "/" + action), {}).catch((error) => {
    delete state.pending[callId];
    showMessage("Aktion fehlgeschlagen: " + error.message);
  });
}

function handleCallEvent(evt) {
  applyEvent(evt);
  if (evt.type === "incoming") notifyIncoming(evt);
  render();
}

function notifyIncoming(evt) {
  try {
    if (typeof Notification !== "undefined" && Notification.permission === "granted" && document.hidden) {
      // Fingerprint only, plain text - never peer-controlled markup.
      new Notification("Eingehender Anruf", { body: shortFingerprint(evt.peerFingerprint) });
    }
  } catch (e) {
    // Notifications are a convenience; never let them break call handling.
  }
}

function loadStatus() {
  return fetchJson(callUrl("status"), { credentials: "same-origin" })
    .then((status) => {
      state.message = "";
      applyStatus(status);
      render();
    })
    .catch((error) => {
      if (error.status === 401) {
        showMessage("Bitte den Link aus der Knoten-Konsole öffnen.");
      } else if (error.status === 503) {
        state.available = false;
        render();
      } else {
        showMessage("Status konnte nicht geladen werden: " + error.message);
      }
      throw error;
    });
}

function openEventStream() {
  if (typeof EventSource === "undefined") return null;
  const source = new EventSource(callUrl("events"));
  EVENT_TYPES.forEach((type) => {
    source.addEventListener(type, (message) => {
      let evt;
      try {
        evt = JSON.parse(message.data);
      } catch (e) {
        return;
      }
      handleCallEvent(evt);
    });
  });
  source.onopen = () => {
    // After a drop, events may have been missed: re-read the truth from the node.
    if (reconnected) {
      reconnected = false;
      loadStatus().catch(() => {});
    }
  };
  source.onerror = () => {
    reconnected = true;
    if (source.readyState === 2) showMessage("Ereignisstrom getrennt - Seite neu laden oder Link erneut öffnen.");
  };
  return source;
}

function installHandlers() {
  el("call-place-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = el("call-place-peer");
    const peer = input.value.trim();
    if (!peer) return;
    postJson(callUrl("place"), { peer: peer })
      .then(() => {
        input.value = "";
        showMessage("");
      })
      .catch((error) => showMessage("Anruf fehlgeschlagen: " + error.message));
  });

  el("call-notify-enable").addEventListener("click", () => {
    // Permission is requested ONLY from this click, never on page load.
    if (typeof Notification === "undefined") return;
    Notification.requestPermission().then(() => {
      el("call-notify-optin").hidden = Notification.permission === "granted";
    });
  });
  if (typeof Notification === "undefined" || Notification.permission === "granted") {
    el("call-notify-optin").hidden = true;
  }

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== "Escape") return;
    const target = document.activeElement;
    const tag = target && target.tagName ? target.tagName.toLowerCase() : "";
    if (tag === "input" || tag === "textarea" || tag === "button" || (target && target.isContentEditable)) return;
    const ringing = callsOfKind(["incoming"]);
    if (ringing.length !== 1) return;
    event.preventDefault();
    callAction(ringing[0].callId, event.key === "Enter" ? "accept" : "reject");
  });
}

function start() {
  installHandlers();
  render();
  fetchJson("/api/identity")
    .then((identity) => setText(el("identity-fingerprint"), identity.fingerprint))
    .catch(() => {});

  callScope = loadStoredScope();
  let exchange = Promise.resolve();
  if (location.hash.indexOf("#t=") === 0) {
    const token = location.hash.slice(3);
    // Drop the secret from the address bar/history BEFORE anything else happens.
    history.replaceState(null, "", "/call.html");
    exchange = postJson("/api/call/session", { token: token })
      .then((session) => {
        callScope = session && /^[0-9a-f]{32}$/.test(session.scope) ? session.scope : null;
        if (callScope === null) throw new Error("invalid session response");
        storeScope(callScope);
      })
      .catch((error) => {
        showMessage("Link abgelaufen – neu aus Konsole öffnen.");
        throw error;
      });
  }
  exchange
    .then(() => {
      if (callScope === null) {
        showMessage("Bitte den Link aus der Knoten-Konsole öffnen.");
        throw new Error("no call session");
      }
    })
    .then(loadStatus)
    .then(() => {
      if (state.available) openEventStream();
    })
    .catch(() => {});
}

start();
