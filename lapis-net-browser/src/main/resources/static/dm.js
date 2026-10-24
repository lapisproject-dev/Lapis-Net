// Lapis Net DM client (V0.8.6b). Plain vanilla JS, no framework, no build step - fetch() against
// the JSON routes installed by DmApi.kt (installDmRoutes). Mirrors mail.js's established
// conventions in this module (see that file's own header comment for the reasoning behind each
// one, restated briefly here):
//
// - Promise/.then()-based, NEVER async/await - MailXssRenderingTest.kt's headless-browser test
//   engine cannot parse `async function` syntax at all; the same constraint applies to any future
//   DmXssRenderingTest.kt written against this file.
// - XSS hygiene (CRITICAL, non-negotiable - see DmApi.kt's file-header doc comment): every place
//   that renders body/attachment-name/peer-derived content into the DOM MUST use textContent,
//   never innerHTML. Every such assignment in this file goes through the single setText() helper
//   below - there is no other DOM-insertion path for sender-controlled content anywhere in this
//   file. Message bodies are shown as their VERBATIM plaintext inside a <pre> element with CSS
//   white-space: pre-wrap, so line breaks are preserved without any HTML interpretation.

const MAX_DM_BODY_BYTES = 32768;

// V0.10.0-F1 anonymity mode. Every text below is fixed in this file; nothing from the server response is ever shown
// for an error (only the code is looked up here), and everything is written through setText()/textContent.
const DM_ANONYMITY_NOTICE =
  "Anonymity mode: messages travel over circuits. The recipient sees who you are. Only people who are in anonymity mode as well can be reached, and there are no attachments.";
const DM_ATTACHMENT_NOTE = "Attachments are not available in anonymity mode.";
const DM_ERROR_TEXTS = {
  "recipient-not-reachable-anonymously":
    "This person cannot be reached anonymously. Nothing was sent.",
  "anonymity-not-ready": "Anonymity mode is not ready yet. Nothing was sent, please try again shortly.",
  "rate-limited": "Circuit builds are being rate limited. Nothing was sent, please try again later.",
  "message-too-large-anonymous": "This message is too long for anonymity mode (about 5 KB). Nothing was sent.",
  "attachments-unavailable-anonymous": "Attachments are not available in anonymity mode. Nothing was sent.",
  "dm-send-failed": "The message could not be sent.",
};
const DM_ERROR_FALLBACK = "The message could not be sent.";
const DM_DELIVERY_TEXTS = {
  direct: { SENT: "SENT", QUEUED_FOR_PICKUP: "QUEUED_FOR_PICKUP" },
  circuit: {
    SENT: "delivered through circuits",
    QUEUED_FOR_PICKUP: "queued: announced through relays until the recipient picks it up (up to 48 hours)",
  },
};
let anonymousMode = false;

function dmErrorText(error) {
  const code = error && error.message;
  return Object.prototype.hasOwnProperty.call(DM_ERROR_TEXTS, code) ? DM_ERROR_TEXTS[code] : DM_ERROR_FALLBACK;
}

function deliveryText(message) {
  const route = message.route === "circuit" ? "circuit" : "direct";
  const table = DM_DELIVERY_TEXTS[route];
  return Object.prototype.hasOwnProperty.call(table, message.deliveryState) ? table[message.deliveryState] : message.deliveryState;
}

function utf8ByteLength(text) {
  return new TextEncoder().encode(text).length;
}

/** The ONE place any sender-controlled string is written into the DOM. Always textContent, never
 * innerHTML - see this file's header comment. */
function setText(el, value) {
  el.textContent = value == null ? "" : value;
}

function fetchJson(url, options) {
  return fetch(url, options).then((response) => {
    const contentType = response.headers.get("content-type") || "";
    const bodyPromise = contentType.includes("application/json") ? response.json() : Promise.resolve(null);
    return bodyPromise.then((body) => {
      if (!response.ok) {
        const message = body && body.error ? body.error : `request failed: ${response.status}`;
        throw new Error(message);
      }
      return body;
    });
  });
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
  if (!fingerprint || fingerprint.length <= 16) return fingerprint || "";
  return `${fingerprint.slice(0, 8)}…${fingerprint.slice(-6)}`;
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

const identityFingerprintEl = document.getElementById("identity-fingerprint");

const openForm = document.getElementById("dm-open-form");
const openPeerEl = document.getElementById("dm-open-peer");

const refreshButton = document.getElementById("dm-refresh-button");
const conversationListEl = document.getElementById("dm-conversation-list");
const conversationItemTemplate = document.getElementById("dm-conversation-item-template");

const threadPanel = document.getElementById("dm-thread-panel");
const threadPeerEl = document.getElementById("dm-thread-peer");
const acceptBanner = document.getElementById("dm-accept-banner");
const acceptButton = document.getElementById("dm-accept-button");
const messageListEl = document.getElementById("dm-message-list");
const messageItemTemplate = document.getElementById("dm-message-item-template");
const messageAttachmentItemTemplate = document.getElementById("dm-message-attachment-item-template");

const composeForm = document.getElementById("dm-compose-form");
const composeBodyEl = document.getElementById("dm-compose-body");
const composeStatusEl = document.getElementById("dm-compose-status");
const composeAttachmentRowsEl = document.getElementById("dm-compose-attachment-rows");
const addAttachmentButton = document.getElementById("dm-add-attachment");
const attachmentRowTemplate = document.getElementById("dm-attachment-row-template");

let currentPeerHex = null;

function loadIdentity() {
  fetchJson("/api/identity")
    .then((identity) => setText(identityFingerprintEl, identity.fingerprint))
    .catch(() => setText(identityFingerprintEl, "identity unavailable"));
}

// --- conversation list ---

function renderConversationItem(conversation) {
  const fragment = conversationItemTemplate.content.cloneNode(true);
  const li = fragment.querySelector(".dm-conversation-item");
  setText(li.querySelector(".dm-conversation-peer"), shortFingerprint(conversation.peerFingerprint));
  setText(li.querySelector(".dm-conversation-time"), formatRelativeTime(conversation.lastMessage.epochSecond));
  const directionPrefix = conversation.lastMessage.direction === "outbound" ? "you: " : "";
  setText(li.querySelector(".dm-conversation-preview"), directionPrefix + conversation.lastMessage.body);
  const badge = li.querySelector(".dm-quarantine-badge");
  badge.hidden = !(conversation.lastMessage.quarantined && !conversation.accepted);
  li.classList.toggle("active", conversation.peerPublicKeyHex === currentPeerHex);
  li.addEventListener("click", () => openConversation(conversation.peerPublicKeyHex));
  return fragment;
}

function loadConversationList() {
  conversationListEl.textContent = "";
  fetchJson("/api/dm")
    .then((conversations) => {
      if (conversations.length === 0) {
        const empty = document.createElement("li");
        setText(empty, "No conversations yet.");
        conversationListEl.appendChild(empty);
        return;
      }
      for (const conversation of conversations) {
        conversationListEl.appendChild(renderConversationItem(conversation));
      }
    })
    .catch((error) => {
      const errorItem = document.createElement("li");
      setText(errorItem, `failed to load conversations: ${error.message}`);
      conversationListEl.appendChild(errorItem);
    });
}

// --- thread / message list ---

function attachmentDownloadHref(peerHex, cid) {
  return `/api/dm/attachment/${encodeURIComponent(peerHex)}/${encodeURIComponent(cid)}`;
}

function renderMessageAttachmentsInto(container, peerHex, attachments) {
  container.textContent = "";
  for (const attachment of attachments) {
    const fragment = messageAttachmentItemTemplate.content.cloneNode(true);
    const linkEl = fragment.querySelector(".dm-message-attachment-link");
    const metaEl = fragment.querySelector(".dm-message-attachment-meta");
    setText(linkEl, attachment.name);
    if (anonymousMode) {
      // no link and no automatic fetch: the blob would have to be requested from the sender's node directly
      linkEl.removeAttribute("href");
      linkEl.classList.add("dm-attachment-plain");
    } else {
      // DOM property assignment, never string-concatenated into markup - mirrors mail.js's
      // identical established pattern (see that file's header comment, rule 3).
      linkEl.href = attachmentDownloadHref(peerHex, attachment.cid);
    }
    setText(metaEl, anonymousMode ? `${attachment.size} bytes` : `${attachment.mime}, ${attachment.size} bytes`);
    container.appendChild(fragment);
  }
}

function renderMessageItem(peerHex, message) {
  const fragment = messageItemTemplate.content.cloneNode(true);
  const li = fragment.querySelector(".dm-message-item");
  li.classList.add(message.direction);
  setText(li.querySelector(".dm-message-direction"), message.direction === "outbound" ? "You" : "Them");
  setText(li.querySelector(".dm-message-time"), formatRelativeTime(message.epochSecond));
  const statusEl = li.querySelector(".dm-message-status");
  if (message.direction === "outbound") {
    setText(statusEl, deliveryText(message));
  } else {
    setText(statusEl, message.quarantined ? "quarantined" : "");
  }
  setText(li.querySelector(".dm-message-body"), message.body);
  renderMessageAttachmentsInto(li.querySelector(".dm-message-attachments"), peerHex, message.attachments);
  return fragment;
}

function loadThread(peerHex) {
  messageListEl.textContent = "";
  fetchJson(`/api/dm/${encodeURIComponent(peerHex)}`)
    .then((messages) => {
      const anyQuarantined = messages.some((m) => m.direction === "inbound" && m.quarantined);
      acceptBanner.classList.toggle("visible", anyQuarantined);
      for (const message of messages) {
        messageListEl.appendChild(renderMessageItem(peerHex, message));
      }
      messageListEl.scrollTop = messageListEl.scrollHeight;
    })
    .catch((error) => {
      const errorEl = document.createElement("li");
      setText(errorEl, `failed to load conversation: ${error.message}`);
      messageListEl.appendChild(errorEl);
    });
}

function openConversation(peerHex) {
  currentPeerHex = peerHex;
  setText(threadPeerEl, shortFingerprint(peerHex));
  threadPanel.hidden = false;
  loadThread(peerHex);
  loadConversationList();
  threadPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

openForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const peerHex = openPeerEl.value.trim();
  if (peerHex.length === 0) return;
  openConversation(peerHex);
});

refreshButton.addEventListener("click", () => {
  loadConversationList();
  if (currentPeerHex) loadThread(currentPeerHex);
});

acceptButton.addEventListener("click", () => {
  if (!currentPeerHex) return;
  fetchJson(`/api/dm/${encodeURIComponent(currentPeerHex)}/accept`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  })
    .then(() => {
      acceptBanner.classList.remove("visible");
      loadConversationList();
    })
    .catch((error) => {
      setText(composeStatusEl, `failed to accept: ${error.message}`);
    });
});

// --- compose ---

function addAttachmentRow() {
  const fragment = attachmentRowTemplate.content.cloneNode(true);
  const row = fragment.querySelector(".dm-attachment-row");
  row.querySelector(".dm-attachment-remove").addEventListener("click", () => row.remove());
  composeAttachmentRowsEl.appendChild(fragment);
}

addAttachmentButton.addEventListener("click", () => addAttachmentRow());

function collectAttachments() {
  const rows = Array.prototype.slice.call(composeAttachmentRowsEl.querySelectorAll(".dm-attachment-row"));
  const readPromises = rows.map((row) => {
    const fileInput = row.querySelector(".dm-attachment-file");
    const file = fileInput.files && fileInput.files[0];
    if (!file) return Promise.resolve(null);
    const mimeOverride = row.querySelector(".dm-attachment-mime").value.trim();
    return file.arrayBuffer().then((buffer) => ({
      name: file.name,
      mime: mimeOverride || file.type || "application/octet-stream",
      contentBase64: arrayBufferToBase64(buffer),
    }));
  });
  return Promise.all(readPromises).then((results) => results.filter((r) => r !== null));
}

composeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!currentPeerHex) {
    setText(composeStatusEl, "failed: open a conversation first");
    return;
  }
  if (utf8ByteLength(composeBodyEl.value) > MAX_DM_BODY_BYTES) {
    setText(composeStatusEl, `failed: body exceeds ${MAX_DM_BODY_BYTES} bytes`);
    return;
  }
  setText(composeStatusEl, "sending…");
  collectAttachments()
    .then((attachments) =>
      fetchJson(`/api/dm/${encodeURIComponent(currentPeerHex)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: composeBodyEl.value, attachments }),
      }),
    )
    .then(() => {
      setText(composeStatusEl, "sent");
      composeBodyEl.value = "";
      composeAttachmentRowsEl.textContent = "";
      loadThread(currentPeerHex);
      loadConversationList();
    })
    .catch((error) => {
      setText(composeStatusEl, anonymousMode ? dmErrorText(error) : `failed: ${error.message}`);
    });
});

// Anonymity mode is read once; the notice is fixed text and can not be dismissed, the attachment button is disabled.
function applyAnonymityMode() {
  return fetchJson("/api/node/status")
    .then((status) => {
      anonymousMode = status.anonymityMode === "on";
      const notice = document.getElementById("dm-anonymity-notice");
      const note = document.getElementById("dm-attachment-note");
      notice.hidden = !anonymousMode;
      note.hidden = !anonymousMode;
      if (anonymousMode) {
        setText(notice, DM_ANONYMITY_NOTICE);
        setText(note, DM_ATTACHMENT_NOTE);
        addAttachmentButton.disabled = true;
      }
    })
    .catch(() => {});
}

loadIdentity();
applyAnonymityMode().then(() => loadConversationList());
