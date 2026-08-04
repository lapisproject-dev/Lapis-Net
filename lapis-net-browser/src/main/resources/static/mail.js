// Lapis Net Mail client (V0.9.3). Plain vanilla JS, no framework, no build step - fetch() against
// the JSON routes installed by MailApi.kt (installMailRoutes).
//
// Deliberately Promise/.then()-based, NOT async/await: this codebase's headless-browser test
// (MailXssRenderingTest.kt, HtmlUnit) runs on an embedded Rhino-derived JS engine that parses
// Promises/fetch/arrow functions/template literals fine but does not parse `async function`/`await`
// syntax at all (confirmed empirically - `async function` fails with a parse error on that engine,
// even though the same engine's runtime fully supports the Promise type an async function would
// have returned anyway). Every network call below is therefore a plain Promise chain.
//
// XSS hygiene (CRITICAL, non-negotiable - see MailApi.kt's file-header doc comment and
// MailXssRenderingTest.kt, which tests this against the ACTUAL rendering code below, not a
// description of intent): every place that renders subject/body/attachment-name/sender-derived
// content into the DOM MUST use textContent, never innerHTML - untrusted mail content must never
// be interpreted as markup. Every such assignment in this file goes through the single setText()
// helper below - there is no other DOM-insertion path for user-controlled content anywhere in this
// file. Bodies are shown as their VERBATIM Markdown source (a deliberate V0.9.3 scope cut - no
// Markdown-to-HTML rendering yet, see MessageBody.kt's doc comment) inside a <pre> element with
// CSS white-space: pre-wrap, so line breaks are preserved without any HTML interpretation.

const MAX_MARKDOWN_BYTES = 32768;

function utf8ByteLength(text) {
  return new TextEncoder().encode(text).length;
}

/** The ONE place any user-controlled (or sender-derived) string is written into the DOM. Always
 * textContent, never innerHTML - see this file's header comment. */
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

const identityFingerprintEl = document.getElementById("identity-fingerprint");

const composeForm = document.getElementById("compose-form");
const composeRecipientsEl = document.getElementById("compose-recipients");
const composeSubjectEl = document.getElementById("compose-subject");
const composeBodyEl = document.getElementById("compose-body");
const composeCountEl = document.getElementById("compose-count");
const composeEncryptionEl = document.getElementById("compose-encryption");
const composeAttachmentRowsEl = document.getElementById("compose-attachment-rows");
const composeAddAttachmentButton = document.getElementById("compose-add-attachment");
const composeReplyToEl = document.getElementById("compose-reply-to");
const composeThreadRootEl = document.getElementById("compose-thread-root");
const composeReplyBannerEl = document.getElementById("compose-reply-banner");
const composeReplyTargetEl = document.getElementById("compose-reply-target");
const composeReplyClearButton = document.getElementById("compose-reply-clear");
const composeStatusEl = document.getElementById("compose-status");

const folderInboxButton = document.getElementById("folder-inbox-button");
const folderSentButton = document.getElementById("folder-sent-button");
const mailRefreshButton = document.getElementById("mail-refresh-button");
const mailListEl = document.getElementById("mail-list");
const mailItemTemplate = document.getElementById("mail-item-template");
const attachmentItemTemplate = document.getElementById("mail-attachment-item-template");
const attachmentRowTemplate = document.getElementById("mail-attachment-row-template");
const threadNodeTemplate = document.getElementById("thread-node-template");

const threadPanel = document.getElementById("thread-panel");
const threadViewEl = document.getElementById("thread-view");

let currentFolder = "inbox";

function loadIdentity() {
  fetchJson("/api/identity")
    .then((identity) => setText(identityFingerprintEl, identity.fingerprint))
    .catch(() => setText(identityFingerprintEl, "identity unavailable"));
}

// --- compose attachment rows ---

function addAttachmentRow() {
  const fragment = attachmentRowTemplate.content.cloneNode(true);
  const row = fragment.querySelector(".mail-attachment-row");
  row.querySelector(".mail-attachment-remove").addEventListener("click", () => row.remove());
  composeAttachmentRowsEl.appendChild(fragment);
}

composeAddAttachmentButton.addEventListener("click", () => addAttachmentRow());

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/** Resolves with the full [{name, mime, contentBase64, encrypt}, ...] array once every selected
 * file's bytes have been read - a `Promise.all` over one `arrayBuffer()` promise per attachment
 * row that actually has a file selected (see this file's header comment on why this is a Promise
 * chain, not `async`/`await`). */
function collectAttachments() {
  const rows = Array.prototype.slice.call(composeAttachmentRowsEl.querySelectorAll(".mail-attachment-row"));
  const readPromises = rows.map((row) => {
    const fileInput = row.querySelector(".mail-attachment-file");
    const file = fileInput.files && fileInput.files[0];
    if (!file) return Promise.resolve(null);
    const mimeOverride = row.querySelector(".mail-attachment-mime").value.trim();
    const encrypt = row.querySelector(".mail-attachment-encrypt").checked;
    return file.arrayBuffer().then((buffer) => ({
      name: file.name,
      mime: mimeOverride || file.type || "application/octet-stream",
      contentBase64: arrayBufferToBase64(buffer),
      encrypt,
    }));
  });
  return Promise.all(readPromises).then((results) => results.filter((r) => r !== null));
}

// --- rendering: shared by inbox/sent list items and thread nodes ---

function attachmentDownloadHref(cid) {
  return "/api/mail/attachment/" + encodeURIComponent(cid);
}

function renderAttachmentsInto(container, attachments) {
  container.textContent = "";
  for (const attachment of attachments) {
    const fragment = attachmentItemTemplate.content.cloneNode(true);
    const lockEl = fragment.querySelector(".mail-attachment-lock");
    const linkEl = fragment.querySelector(".mail-attachment-link");
    const metaEl = fragment.querySelector(".mail-attachment-meta");
    setText(lockEl, attachment.encrypted ? "🔒" : "");
    setText(linkEl, attachment.name);
    // DOM property assignment, never string-concatenated into markup - the value itself (cid) is
    // server-generated/CID-validated, not raw user text, so this is defense-in-depth on top of an
    // already-safe value (see this file's header comment, rule 3).
    linkEl.href = attachmentDownloadHref(attachment.cid);
    setText(metaEl, `${attachment.mime}, ${attachment.size} bytes`);
    container.appendChild(fragment);
  }
}

function fillSummaryInto(root, summary) {
  setText(root.querySelector(".mail-item-sender"), shortFingerprint(summary.sender));
  setText(root.querySelector(".mail-item-time"), formatRelativeTime(summary.sentAtEpochSeconds));
  setText(root.querySelector(".mail-item-encryption"), summary.encryption);
  const subjectEl = root.querySelector(".mail-subject");
  const bodyEl = root.querySelector(".mail-body-preview");
  setText(subjectEl, summary.subject);
  setText(bodyEl, summary.bodyPreview);
  if (summary.decryptionFailed) {
    subjectEl.classList.add("mail-decryption-failed");
    bodyEl.classList.add("mail-decryption-failed");
  }
  renderAttachmentsInto(root.querySelector(".mail-attachments"), summary.attachments);
}

function wireReplyButton(button, summary) {
  button.addEventListener("click", () => {
    composeReplyToEl.value = summary.cid;
    composeThreadRootEl.value = summary.threadRootCid || summary.cid;
    setText(composeReplyTargetEl, summary.subject);
    composeReplyBannerEl.hidden = false;
    composeSubjectEl.value = summary.subject.startsWith("Re: ") ? summary.subject : `Re: ${summary.subject}`;
    composeSubjectEl.focus();
  });
}

function renderMailItem(summary) {
  const fragment = mailItemTemplate.content.cloneNode(true);
  const li = fragment.querySelector(".mail-item");
  fillSummaryInto(li, summary);
  li.querySelector(".mail-view-thread-button").addEventListener("click", () => loadThread(summary.cid));
  wireReplyButton(li.querySelector(".mail-reply-button"), summary);
  return fragment;
}

function loadMailList() {
  mailListEl.textContent = "";
  const url = currentFolder === "sent" ? "/api/mail/sent" : "/api/mail";
  fetchJson(url)
    .then((items) => {
      if (items.length === 0) {
        const empty = document.createElement("li");
        setText(empty, currentFolder === "sent" ? "No sent mail yet." : "No mail yet.");
        mailListEl.appendChild(empty);
        return;
      }
      for (const item of items) {
        mailListEl.appendChild(renderMailItem(item));
      }
    })
    .catch((error) => {
      const errorItem = document.createElement("li");
      setText(errorItem, `failed to load mail: ${error.message}`);
      mailListEl.appendChild(errorItem);
    });
}

function renderThreadNode(node) {
  const fragment = threadNodeTemplate.content.cloneNode(true);
  const root = fragment.querySelector(".thread-node");
  fillSummaryInto(root, node.summary);
  wireReplyButton(root.querySelector(".mail-reply-button"), node.summary);
  const childrenEl = root.querySelector(".thread-node-children");
  for (const child of node.children) {
    childrenEl.appendChild(renderThreadNode(child));
  }
  return fragment;
}

function loadThread(cid) {
  threadViewEl.textContent = "";
  threadViewEl.classList.add("visible");
  fetchJson(`/api/mail/thread/${encodeURIComponent(cid)}`)
    .then((root) => {
      threadViewEl.appendChild(renderThreadNode(root));
      threadPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    })
    .catch((error) => {
      const errorEl = document.createElement("p");
      setText(errorEl, `failed to load thread: ${error.message}`);
      threadViewEl.appendChild(errorEl);
    });
}

// --- folder toggle ---

function setFolder(folder) {
  currentFolder = folder;
  folderInboxButton.classList.toggle("active", folder === "inbox");
  folderSentButton.classList.toggle("active", folder === "sent");
  loadMailList();
}

folderInboxButton.addEventListener("click", () => setFolder("inbox"));
folderSentButton.addEventListener("click", () => setFolder("sent"));
mailRefreshButton.addEventListener("click", () => loadMailList());

// --- compose ---

composeBodyEl.addEventListener("input", () => {
  setText(composeCountEl, `${utf8ByteLength(composeBodyEl.value)} / ${MAX_MARKDOWN_BYTES}`);
});

composeReplyClearButton.addEventListener("click", () => {
  composeReplyToEl.value = "";
  composeThreadRootEl.value = "";
  composeReplyBannerEl.hidden = true;
});

function parseRecipients(raw) {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

composeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const recipientsHex = parseRecipients(composeRecipientsEl.value);
  if (recipientsHex.length === 0) {
    composeStatusEl.textContent = "failed: at least one recipient is required";
    return;
  }
  composeStatusEl.textContent = "sending…";
  collectAttachments()
    .then((attachments) =>
      fetchJson("/api/mail", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          recipientsHex,
          subject: composeSubjectEl.value,
          body: composeBodyEl.value,
          attachments,
          encryption: composeEncryptionEl.value,
          replyToCid: composeReplyToEl.value || null,
          threadRootCid: composeThreadRootEl.value || null,
        }),
      }),
    )
    .then(() => {
      composeStatusEl.textContent = "sent";
      composeSubjectEl.value = "";
      composeBodyEl.value = "";
      composeAttachmentRowsEl.textContent = "";
      composeReplyToEl.value = "";
      composeThreadRootEl.value = "";
      composeReplyBannerEl.hidden = true;
      setText(composeCountEl, `0 / ${MAX_MARKDOWN_BYTES}`);
      if (currentFolder === "sent") {
        loadMailList();
      }
    })
    .catch((error) => {
      composeStatusEl.textContent = `failed: ${error.message}`;
    });
});

loadIdentity();
loadMailList();
