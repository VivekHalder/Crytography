// ECC Toolkit — frontend logic

const API = ""; // same origin; change if you serve frontend separately

// ---- helpers --------------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function setHidden(el, hidden) { el.hidden = !!hidden; }

function showError(elId, msg) {
  const el = $("#" + elId);
  el.textContent = msg;
  el.hidden = false;
}
function clearError(elId) {
  const el = $("#" + elId);
  el.textContent = "";
  el.hidden = true;
}

async function api(path, body) {
  const res = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `HTTP ${res.status}`);
  }
  return data;
}

function pretty(obj) {
  return typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

// ---- tab switching --------------------------------------------------------
$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    $$(".panel").forEach((p) => p.classList.remove("active"));
    $("#panel-" + tab).classList.add("active");
  });
});

// ---- copy buttons ---------------------------------------------------------
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const target = $("#" + btn.dataset.copy);
  if (!target) return;
  navigator.clipboard.writeText(target.textContent).then(() => {
    const original = btn.textContent;
    btn.textContent = "copied!";
    setTimeout(() => (btn.textContent = original), 1200);
  });
});

// ---- health check ---------------------------------------------------------
(async () => {
  const el = $("#health");
  try {
    const res = await fetch(API + "/api/health");
    const data = await res.json();
    if (data.sage_available) {
      el.textContent = `sage ✓  ·  ${data.sage_bin}`;
      el.classList.add("ok");
    } else {
      el.textContent = "sage NOT FOUND";
      el.classList.add("bad");
    }
  } catch (e) {
    el.textContent = "backend offline";
    el.classList.add("bad");
  }
})();

// ---- KEYGEN ---------------------------------------------------------------
const kgMode = $("#kg-mode");
function refreshKgMode() {
  const v = kgMode.value;
  $$(".mode-block").forEach((b) => setHidden(b, b.dataset.mode !== v));
}
kgMode.addEventListener("change", refreshKgMode);
refreshKgMode();

$("#kg-run").addEventListener("click", async () => {
  clearError("kg-err");
  const mode = parseInt(kgMode.value, 10);
  const body = { mode };

  try {
    if (mode === 0) {
      Object.assign(body, {
        base_field: $("#kg0-p").value.trim(),
        degree: parseInt($("#kg0-deg").value, 10),
        a1: $("#kg0-a1").value.trim(),
        a2: $("#kg0-a2").value.trim(),
        a3: $("#kg0-a3").value.trim(),
        a4: $("#kg0-a4").value.trim(),
        a6: $("#kg0-a6").value.trim(),
      });
      for (const k of ["base_field", "a1", "a2", "a3", "a4", "a6"]) {
        if (!body[k]) throw new Error(`Missing ${k}`);
      }
    } else if (mode === 1) {
      body.base_field = $("#kg1-p").value.trim();
      body.degree = parseInt($("#kg1-deg").value, 10);
      if (!body.base_field) throw new Error("Missing base_field");
    } else if (mode === 2) {
      body.curve_name = $("#kg2-name").value;
    } else if (mode === 3) {
      body.bits = parseInt($("#kg3-bits").value, 10);
      body.degree = parseInt($("#kg3-deg").value, 10);
    }
  } catch (err) {
    showError("kg-err", err.message);
    return;
  }

  const btn = $("#kg-run");
  const spin = $("#kg-spin");
  btn.disabled = true;
  spin.hidden = false;
  $("#kg-summary").textContent = "running…";
  $("#kg-pub").textContent = "—";
  $("#kg-priv").textContent = "—";

  try {
    const data = await api("/api/keygen", body);
    $("#kg-summary").textContent = data.summary || "(no summary)";
    $("#kg-pub").textContent = pretty(data.public_key);
    $("#kg-priv").textContent = pretty(data.private_key);

    // Auto-populate Encrypt and Decrypt panels
    $("#en-pub").value = pretty(data.public_key);
    $("#de-pub").value = pretty(data.public_key);
    $("#de-priv").value = pretty(data.private_key);
  } catch (err) {
    showError("kg-err", err.message);
    $("#kg-summary").textContent = "—";
  } finally {
    btn.disabled = false;
    spin.hidden = true;
  }
});

// ---- ENCRYPT --------------------------------------------------------------
const enMode = $("#en-mode");
function refreshEnMode() {
  const m = enMode.value;
  if (m === "1") {
    $("#en-msg-label").textContent = "Message (text)";
    $("#en-mode-hint").textContent =
      "Mode 1 splits the message into chunks sized for the curve's field. Field must be ≥ 16 bits, and degree must be 1.";
    $("#en-msg").placeholder = "the big brown fox jumped over the lazy dog";
  } else {
    $("#en-msg-label").textContent = "Points (one per line)";
    $("#en-mode-hint").textContent =
      "Mode 2 takes already-formed points on the curve. Format: (x : y : z) per line.";
    $("#en-msg").placeholder = "(12 : 2 : 1)\n(12 : 3 : 1)";
  }
}
enMode.addEventListener("change", refreshEnMode);
refreshEnMode();

$("#en-run").addEventListener("click", async () => {
  clearError("en-err");
  const mode = parseInt(enMode.value, 10);
  let pubObj;
  try {
    pubObj = JSON.parse($("#en-pub").value);
  } catch {
    showError("en-err", "Public key isn't valid JSON.");
    return;
  }
  const message = $("#en-msg").value;
  if (!message.trim()) {
    showError("en-err", "Message is empty.");
    return;
  }

  const btn = $("#en-run");
  const spin = $("#en-spin");
  btn.disabled = true;
  spin.hidden = false;
  $("#en-summary").textContent = "running…";
  $("#en-ct").textContent = "—";

  try {
    const data = await api("/api/encrypt", {
      mode,
      public_key_json: pubObj,
      message,
    });
    $("#en-summary").textContent = data.summary || "(no summary)";
    $("#en-ct").textContent = pretty(data.ciphertext);
    $("#de-ct").value = pretty(data.ciphertext); // flow into decrypt panel
  } catch (err) {
    showError("en-err", err.message);
    $("#en-summary").textContent = "—";
  } finally {
    btn.disabled = false;
    spin.hidden = true;
  }
});

// ---- DECRYPT --------------------------------------------------------------
$("#de-run").addEventListener("click", async () => {
  clearError("de-err");
  const mode = parseInt($("#de-mode").value, 10);

  let privObj, pubObj, ctObj;
  try { privObj = JSON.parse($("#de-priv").value); }
  catch { showError("de-err", "Private key isn't valid JSON."); return; }
  try { pubObj = JSON.parse($("#de-pub").value); }
  catch { showError("de-err", "Public key isn't valid JSON."); return; }
  try { ctObj = JSON.parse($("#de-ct").value); }
  catch { showError("de-err", "Ciphertext isn't valid JSON."); return; }

  const btn = $("#de-run");
  const spin = $("#de-spin");
  btn.disabled = true;
  spin.hidden = false;
  $("#de-out").textContent = "running…";

  try {
    const data = await api("/api/decrypt", {
      mode,
      private_key_json: privObj,
      public_key_json: pubObj,
      ciphertext_json: ctObj,
    });
    $("#de-out").textContent = data.output || "(no output)";
  } catch (err) {
    showError("de-err", err.message);
    $("#de-out").textContent = "—";
  } finally {
    btn.disabled = false;
    spin.hidden = true;
  }
});
