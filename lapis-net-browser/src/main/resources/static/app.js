// Lapis Net Minimal-Browser MVP client. Plain vanilla JS, no framework, no build step - fetch()
// against the JSON routes installed by BrowserApi.kt. XSS hygiene: every place that renders
// author/text/comment content into the DOM MUST use textContent, never innerHTML - untrusted post
// text and comments must never be interpreted as markup.

// Mirrors TimelineBuilder.DEFAULT_CREDIBILITY_FILTER_THRESHOLD_MICROS on the server - used here
// only to choose a badge color, not to decide filtering (the server already decided filteredOut
// via /api/timeline's own visible() call before this client ever sees the response).
const RESOLVED_HIGH_THRESHOLD_MICROS = 250000;

// Mirrors MAX_POST_BODY_BYTES on the server (PostAnnouncement.kt) - the server enforces this as
// UTF-8 *bytes*, not JS string .length (UTF-16 code units), so non-ASCII text must be measured via
// TextEncoder here too. Using .length instead would let a user type up to this many *characters*
// of e.g. multi-byte emoji/CJK text and still get rejected by the server with a confusing 400.
const MAX_POST_BODY_BYTES = 2048;

function utf8ByteLength(text) {
  return new TextEncoder().encode(text).length;
}

const identityFingerprintEl = document.getElementById("identity-fingerprint");
const peerCountEl = document.getElementById("peer-count");
const connectForm = document.getElementById("connect-form");
const connectMultiaddrInput = document.getElementById("connect-multiaddr");
const connectStatusEl = document.getElementById("connect-status");

// V0.4 connect panel (QR / deep-link key exchange, Part B) + self-trust-linking (Part C).
const connectUriDisplayEl = document.getElementById("connect-uri-display");
const connectUriCopyButton = document.getElementById("connect-uri-copy");
const connectUriCopyStatusEl = document.getElementById("connect-uri-copy-status");
const connectUriForm = document.getElementById("connect-uri-form");
const connectUriInputEl = document.getElementById("connect-uri-input");
const connectUriStatusEl = document.getElementById("connect-uri-status");
const connectUriResultEl = document.getElementById("connect-uri-result");
const connectUriResultPeerEl = document.getElementById("connect-uri-result-peer");
const connectUriRateButton = document.getElementById("connect-uri-rate-button");
const connectUriSelfLinkButton = document.getElementById("connect-uri-self-link-button");
const connectUriActionStatusEl = document.getElementById("connect-uri-action-status");
const connectUriRateForm = document.getElementById("connect-uri-rate-form");
const connectUriRateTargetInput = document.getElementById("connect-uri-rate-target");
const connectUriRateSlider = document.getElementById("connect-uri-rate-slider");
const connectUriRateSliderValueEl = document.getElementById("connect-uri-rate-slider-value");
const connectUriRateCommentInput = document.getElementById("connect-uri-rate-comment");
const connectUriRateStatusEl = document.getElementById("connect-uri-rate-status");

const composeTextEl = document.getElementById("compose-text");
const composeCountEl = document.getElementById("compose-count");
const composeSubmitButton = document.getElementById("compose-submit");
const composeStatusEl = document.getElementById("compose-status");
const includeFilteredCheckbox = document.getElementById("include-filtered");
const refreshButton = document.getElementById("refresh-button");
const timelineListEl = document.getElementById("timeline-list");
const timelineItemTemplate = document.getElementById("timeline-item-template");

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const message = body && body.error ? body.error : `request failed: ${response.status}`;
    throw new Error(message);
  }
  return body;
}

function formatRelativeTime(epochSeconds) {
  const deltaSeconds = Math.floor(Date.now() / 1000) - epochSeconds;
  if (deltaSeconds < 5) return "just now";
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`;
  const minutes = Math.floor(deltaSeconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function shortFingerprint(fingerprint) {
  if (fingerprint.length <= 16) return fingerprint;
  return `${fingerprint.slice(0, 8)}…${fingerprint.slice(-6)}`;
}

function credibilityBadgeText(post) {
  if (post.credibilityLevel === "NO_PATH") return "Unrated";
  const percent = Math.round((post.credibilityScoreMicros / 1000000) * 100);
  return post.credibilityScoreMicros >= RESOLVED_HIGH_THRESHOLD_MICROS
    ? `Trusted · ${percent}%`
    : `Low trust · ${percent}%`;
}

function credibilityBadgeClass(post) {
  // NO_PATH must always be visually distinct from a low RESOLVED score - never conflate "unknown"
  // with "distrusted". See CredibilityLevel's server-side doc comment for the full reasoning.
  if (post.credibilityLevel === "NO_PATH") return "no-path";
  return post.credibilityScoreMicros >= RESOLVED_HIGH_THRESHOLD_MICROS ? "resolved-high" : "resolved-low";
}

function ltrWeightText(post) {
  if (post.ltrRecordCount === 0 || post.ltrWeightMsat <= 0) return "No boosts yet";
  const sats = (post.ltrWeightMsat / 1000).toFixed(2);
  return `Boosted ${sats} sats by ${post.ltrRecordCount} supporter${post.ltrRecordCount === 1 ? "" : "s"}`;
}

// Pairs the raw number with a plain word, matching ltrWeightText()'s/credibilityBadgeText()'s
// established convention (e.g. "Trusted · 62%", "Boosted 2.50 sats by 3 supporters") - never a
// bare float. karmaScore is a personalized, Veritas-weighted number (see the server-side
// KarmaScoring doc comment) - it can legitimately be 0 even with real likes (e.g. from voters you
// have no trust path to), so it is shown alongside the raw like count, not instead of it.
function karmaText(post) {
  if (post.karmaVoteCount === 0) return "No likes yet";
  const likeWord = post.karmaVoteCount === 1 ? "like" : "likes";
  return `♥ ${post.karmaVoteCount} ${likeWord} · Karma ${post.karmaScore.toFixed(2)}`;
}

// Flashes [element] briefly to give felt confirmation that an action (posting, rating)
// succeeded, instead of a silent state swap - see the UI/UX design review's "Duarte" note.
function flashItem(element) {
  if (!element) return;
  element.classList.add("lapis-flash");
  element.addEventListener("animationend", () => element.classList.remove("lapis-flash"), { once: true });
}

async function loadIdentity() {
  try {
    const identity = await fetchJson("/api/identity");
    identityFingerprintEl.textContent = identity.fingerprint;
  } catch (error) {
    identityFingerprintEl.textContent = "identity unavailable";
  }
}

// V0.9.15 status panel. Every value is written through textContent; the node only ever sends enum-like strings,
// booleans and numbers here, never absolute paths.
async function loadNodeStatus() {
  try {
    const status = await fetchJson("/api/node/status");
    document.getElementById("node-status-dht").textContent = status.dhtFallback ? "active" : "off";
    document.getElementById("node-status-dht-note").textContent = status.dhtFallback
      ? "(DHT lookups reveal query timing and key interest to DHT peers; disable with --dht-fallback=false)"
      : "";
    document.getElementById("node-status-reachability").textContent = status.reachability;
    document.getElementById("node-status-relay").textContent = status.autoRelay
      ? (status.autoRelayRunning ? "running" : "enabled, not running") + " - " + status.relayReservations + " reservation(s)"
      : "off";
    document.getElementById("node-status-publish").textContent = status.publishRelayReliability ? "on" : "off";
    document.getElementById("node-status-acceptance-text").textContent =
      status.acceptanceGates.length === 0
        ? "No rule active: everybody is accepted."
        : "Active: " + status.acceptanceGates.join(", ");
    document.getElementById("node-status-mail-acceptance-text").textContent =
      status.mailAcceptanceGates.length === 0
        ? "No rule active: all mail is accepted."
        : "Active: " + status.mailAcceptanceGates.join(", ");
    const blocked = status.mailBlocked;
    const labels = {
      "veritas-below-threshold": "no Veritas path",
      "karma-below-threshold": "Karma too low",
      "all-active-gates-failed": "several rules",
      "policy": "other",
    };
    document.getElementById("node-status-mail-blocked").textContent =
      !blocked || blocked.total === 0
        ? "Blocked deliveries so far: 0"
        : "Blocked deliveries so far: " + blocked.total + " (" +
          Object.entries(blocked.byReason).map(([k, v]) => (labels[k] || "other") + ": " + v).join(", ") + ")";
    document.getElementById("node-status-config-file").textContent = status.configFile;
  } catch (error) {
    document.getElementById("node-status-dht").textContent = "unavailable";
  }
}

async function loadPeers() {
  try {
    const peers = await fetchJson("/api/peers");
    peerCountEl.textContent = `${peers.peers.length} peer${peers.peers.length === 1 ? "" : "s"}`;
  } catch (error) {
    peerCountEl.textContent = "peers unavailable";
  }
}

function renderTimelineItem(post) {
  const fragment = timelineItemTemplate.content.cloneNode(true);
  const li = fragment.querySelector(".timeline-item");

  li.querySelector(".timeline-author").textContent = shortFingerprint(post.author);
  li.querySelector(".timeline-timestamp").textContent = formatRelativeTime(post.publishedAtEpochSeconds);
  li.querySelector(".timeline-text").textContent = post.text;
  li.querySelector(".timeline-ltr").textContent = ltrWeightText(post);

  // Karma is visually and structurally its own row, separate from the credibility badge above -
  // it never implies sort order or truth, only a personalized like count/score (see the
  // server-side KarmaScoring doc comment). Kept as a persistently-visible one-click control
  // (never behind a collapsed <details>, unlike the trust-rating form below), matching the
  // fach-spec's "one click" design for a like.
  const karmaEl = li.querySelector(".timeline-karma");
  const likeButton = li.querySelector(".timeline-like-button");
  const likeStatus = li.querySelector(".timeline-like-status");
  karmaEl.textContent = karmaText(post);

  likeButton.addEventListener("click", async () => {
    likeButton.disabled = true;
    likeStatus.textContent = "liking…";
    try {
      await fetchJson("/api/karma", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetCid: post.cid }),
      });
      likeStatus.textContent = "liked";
      // Reuses the same flashItem/lapis-flash animation as posting/rating, for felt confirmation -
      // see flashItem's doc comment. loadTimeline() wipes and rebuilds the whole list immediately
      // after, so the pause below keeps the flash from being cut off.
      flashItem(li);
      await new Promise((resolve) => setTimeout(resolve, 500));
      await loadTimeline();
    } catch (error) {
      likeStatus.textContent = `failed: ${error.message}`;
      likeButton.disabled = false;
    }
  });

  const badge = li.querySelector(".timeline-credibility-badge");
  badge.textContent = credibilityBadgeText(post);
  badge.classList.add("credibility-badge", credibilityBadgeClass(post));
  // Static, developer-authored strings only - never user/peer content - so a plain title
  // assignment (not innerHTML) keeps the file's textContent-only XSS discipline intact.
  badge.title = post.credibilityLevel === "NO_PATH"
    ? "You have no trust path to this author yet - this is not a bad rating, just unknown."
    : "How much people you trust, directly or transitively, vouch for this author, from your point of view.";

  const trustForm = li.querySelector(".trust-form");
  const trustTargetInput = li.querySelector(".trust-target");
  const trustSlider = li.querySelector(".trust-slider");
  const trustSliderValue = li.querySelector(".trust-slider-value");
  const trustComment = li.querySelector(".trust-comment");
  const trustStatus = li.querySelector(".trust-status");

  trustTargetInput.value = post.authorPublicKeyHex;
  trustSlider.addEventListener("input", () => {
    trustSliderValue.textContent = `${trustSlider.value}%`;
  });

  trustForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    trustStatus.textContent = "submitting…";
    try {
      const trustMicros = Math.round((Number(trustSlider.value) / 100) * 1000000);
      await fetchJson("/api/trust", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetPublicKeyHex: trustTargetInput.value,
          trustMicros,
          comment: trustComment.value,
        }),
      });
      trustStatus.textContent = "saved";
      // loadTimeline() wipes and rebuilds the whole list immediately after - without this
      // pause the flash animation would be cut off almost as soon as it starts.
      flashItem(li);
      await new Promise((resolve) => setTimeout(resolve, 500));
      await loadTimeline();
    } catch (error) {
      trustStatus.textContent = `failed: ${error.message}`;
    }
  });

  return fragment;
}

async function loadTimeline() {
  const includeFiltered = includeFilteredCheckbox.checked;
  timelineListEl.textContent = "";
  try {
    const posts = await fetchJson(`/api/timeline?includeFiltered=${includeFiltered}`);
    if (posts.length === 0) {
      const empty = document.createElement("li");
      empty.textContent = "No posts yet.";
      timelineListEl.appendChild(empty);
      return;
    }
    for (const post of posts) {
      timelineListEl.appendChild(renderTimelineItem(post));
    }
  } catch (error) {
    const errorItem = document.createElement("li");
    errorItem.textContent = `failed to load timeline: ${error.message}`;
    timelineListEl.appendChild(errorItem);
  }
}

composeTextEl.addEventListener("input", () => {
  composeCountEl.textContent = `${utf8ByteLength(composeTextEl.value)} / ${MAX_POST_BODY_BYTES}`;
});

composeSubmitButton.addEventListener("click", async () => {
  const text = composeTextEl.value.trim();
  if (text.length === 0) return;
  if (utf8ByteLength(text) > MAX_POST_BODY_BYTES) {
    composeStatusEl.textContent = `failed: text must be at most ${MAX_POST_BODY_BYTES} UTF-8 bytes`;
    return;
  }
  composeStatusEl.textContent = "posting…";
  try {
    await fetchJson("/api/posts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    composeTextEl.value = "";
    composeCountEl.textContent = `0 / ${MAX_POST_BODY_BYTES}`;
    composeStatusEl.textContent = "posted";
    await loadTimeline();
    flashItem(timelineListEl.querySelector(".timeline-item"));
  } catch (error) {
    composeStatusEl.textContent = `failed: ${error.message}`;
  }
});

connectForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const multiaddr = connectMultiaddrInput.value.trim();
  if (multiaddr.length === 0) return;
  connectStatusEl.textContent = "connecting…";
  try {
    await fetchJson("/api/peers/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ multiaddr }),
    });
    connectStatusEl.textContent = "connected";
    connectMultiaddrInput.value = "";
    await loadPeers();
  } catch (error) {
    connectStatusEl.textContent = `failed: ${error.message}`;
  }
});

includeFilteredCheckbox.addEventListener("change", loadTimeline);
refreshButton.addEventListener("click", () => {
  loadTimeline();
  loadPeers();
});

// --- V0.4 connect panel: QR / deep-link key exchange (Part B) + self-trust-linking (Part C) ---

async function loadConnectInfo() {
  try {
    const info = await fetchJson("/api/connect/info");
    connectUriDisplayEl.value = info.uri;
  } catch (error) {
    connectUriDisplayEl.value = "";
    connectUriDisplayEl.placeholder = `connect link unavailable: ${error.message}`;
  }
}

connectUriCopyButton.addEventListener("click", async () => {
  if (!connectUriDisplayEl.value) return;
  try {
    await navigator.clipboard.writeText(connectUriDisplayEl.value);
    connectUriCopyStatusEl.textContent = "copied";
  } catch (error) {
    // Clipboard API can be unavailable (no secure context, no permission) - fall back to a
    // plain text-selection so the user can still copy manually via keyboard/right-click.
    connectUriDisplayEl.select();
    connectUriCopyStatusEl.textContent = "select-to-copy (clipboard unavailable)";
  }
});

// Resets the connect-uri-result panel back to its pre-connect state - shared by every path that
// starts a fresh "paste a link" attempt, so a previous connect's peer/rate-form never lingers
// stale on screen.
function resetConnectUriResult() {
  connectUriResultEl.hidden = true;
  connectUriResultPeerEl.textContent = "";
  connectUriActionStatusEl.textContent = "";
  connectUriRateForm.hidden = true;
  connectUriRateStatusEl.textContent = "";
}

connectUriForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const uri = connectUriInputEl.value.trim();
  if (uri.length === 0) return;
  connectUriStatusEl.textContent = "connecting…";
  resetConnectUriResult();
  try {
    const result = await fetchJson("/api/connect/uri", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uri }),
    });
    connectUriStatusEl.textContent = "connected";
    connectUriInputEl.value = "";
    await loadPeers();

    connectUriResultPeerEl.textContent = `Connected to ${shortFingerprint(result.peerId)}`;
    connectUriResultEl.hidden = false;
    connectUriResultEl.dataset.publicKeyHex = result.publicKeyHex;
    flashItem(connectUriResultEl);
  } catch (error) {
    connectUriStatusEl.textContent = `failed: ${error.message}`;
  }
});

connectUriRateButton.addEventListener("click", () => {
  const publicKeyHex = connectUriResultEl.dataset.publicKeyHex;
  if (!publicKeyHex) return;
  connectUriRateTargetInput.value = publicKeyHex;
  connectUriRateForm.hidden = !connectUriRateForm.hidden;
});

connectUriRateSlider.addEventListener("input", () => {
  connectUriRateSliderValueEl.textContent = `${connectUriRateSlider.value}%`;
});

connectUriRateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  connectUriRateStatusEl.textContent = "submitting…";
  try {
    const trustMicros = Math.round((Number(connectUriRateSlider.value) / 100) * 1000000);
    await fetchJson("/api/trust", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        targetPublicKeyHex: connectUriRateTargetInput.value,
        trustMicros,
        comment: connectUriRateCommentInput.value,
      }),
    });
    connectUriRateStatusEl.textContent = "saved";
    flashItem(connectUriResultEl);
  } catch (error) {
    connectUriRateStatusEl.textContent = `failed: ${error.message}`;
  }
});

connectUriSelfLinkButton.addEventListener("click", async () => {
  const publicKeyHex = connectUriResultEl.dataset.publicKeyHex;
  if (!publicKeyHex) return;
  connectUriSelfLinkButton.disabled = true;
  connectUriActionStatusEl.textContent = "linking…";
  try {
    await fetchJson("/api/self-link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targetPublicKeyHex: publicKeyHex, label: "device" }),
    });
    connectUriActionStatusEl.textContent = "linked";
    flashItem(connectUriResultEl);
    await loadTimeline();
  } catch (error) {
    connectUriActionStatusEl.textContent = `failed: ${error.message}`;
    connectUriSelfLinkButton.disabled = false;
  }
});

loadIdentity();
loadNodeStatus();
loadPeers();
loadTimeline();
loadConnectInfo();
