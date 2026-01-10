const dashboardState = {
  loading: false,
  knownServers: null,
  knownServersLoaded: false,
  latestApStatus: null,
  latestDnsStatus: null,
};

const upstreamState = {
  profiles: [],
  storedProfiles: [],
  systemProfiles: [],
  drift: null,
  selectedSsid: null,
  selectedIsSaved: false,
  loading: false,
  loadingCount: 0,
  statusText: "",
  statusValue: "",
  busyMessage: "",
};

const formState = {
  apBaseline: {
    ssid: "",
    password: "",
    subnet_octet: "",
    channel: "",
  },
  dnsBaseline: {
    redirect: "",
    target: "",
  },
};

const dashboardElements = {};

function cacheDashboardElements() {
  Object.assign(dashboardElements, {
    refreshApBtn: document.getElementById("refreshApBtn"),
    refreshDnsBtn: document.getElementById("refreshDnsBtn"),
    apStatus: document.getElementById("apStatus"),
    apSsid: document.getElementById("apSsid"),
    apOctet: document.getElementById("apOctet"),
    apChannel: document.getElementById("apChannel"),
    dnsStatus: document.getElementById("dnsStatus"),
    dnsRedirect: document.getElementById("dnsRedirect"),
    dnsTarget: document.getElementById("dnsTarget"),
    output: document.getElementById("output"),
    apForm: document.getElementById("apForm"),
    dnsForm: document.getElementById("dnsForm"),
    apSsidInput: document.getElementById("apSsidInput"),
    apPasswordInput: document.getElementById("apPasswordInput"),
    apPasswordToggle: document.getElementById("apPasswordToggle"),
    apOctetInput: document.getElementById("apOctetInput"),
    apChannelInput: document.getElementById("apChannelInput"),
    dnsRedirectInput: document.getElementById("dnsRedirectInput"),
    dnsTargetInput: document.getElementById("dnsTargetInput"),
    dnsKnownServers: document.getElementById("dnsKnownServers"),
    refreshKnownServersBtn: document.getElementById("refreshKnownServersBtn"),
    applyApBtn: document.getElementById("applyApBtn"),
    applyDnsBtn: document.getElementById("applyDnsBtn"),
    apChangeHint: document.getElementById("apChangeHint"),
    dnsChangeHint: document.getElementById("dnsChangeHint"),
    apDriftSummary: document.getElementById("apDriftSummary"),
    dnsDriftSummary: document.getElementById("dnsDriftSummary"),
    apNatHint: document.getElementById("apNatHint"),
    upstreamProfilesBody: document.getElementById("upstreamProfilesBody"),
    upstreamError: document.getElementById("upstreamError"),
    upstreamDrift: document.getElementById("upstreamDrift"),
    upstreamForm: document.getElementById("upstreamForm"),
    upstreamSsidInput: document.getElementById("upstreamSsidInput"),
    upstreamPasswordInput: document.getElementById("upstreamPasswordInput"),
    upstreamPasswordToggle: document.getElementById("upstreamPasswordToggle"),
    upstreamPriorityInput: document.getElementById("upstreamPriorityInput"),
    upstreamSecuritySelect: document.getElementById("upstreamSecuritySelect"),
    refreshUpstreamBtn: document.getElementById("refreshUpstreamBtn"),
    saveUpstreamBtn: document.getElementById("saveUpstreamBtn"),
    resetUpstreamBtn: document.getElementById("resetUpstreamBtn"),
    deleteUpstreamBtn: document.getElementById("deleteUpstreamBtn"),
    upstreamStatus: document.getElementById("upstreamStatus"),
    saveCurrentUpstreamBtn: document.getElementById("saveCurrentUpstreamBtn"),
  });
}

function setStateText(el, text, status) {
  if (!el) return;
  el.textContent = text;
  el.className = "value state";
  const normalized = (status || "").toString().toLowerCase();
  if (normalized === "ok") {
    el.classList.add("running");
  } else if (normalized === "error") {
    el.classList.add("stopped");
  } else if (normalized === "warning") {
    el.classList.add("warning");
  }
}

function normalizeTextValue(value) {
  return (value ?? "").toString().trim();
}

function normalizePasswordValue(value) {
  return value ?? "";
}

function normalizeNumberValue(value) {
  return normalizeTextValue(value);
}

function normalizeStatus(value) {
  return normalizeTextValue(value).toLowerCase();
}

function normalizeSsidKey(value) {
  return normalizeTextValue(value).toLowerCase();
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setPasswordVisibility(input, visible) {
  if (!input) return;
  input.type = visible ? "text" : "password";
}

function attachPasswordToggle(button, input) {
  if (!button || !input) return;
  let persistentVisible = false;

  const updateState = () => {
    setPasswordVisibility(input, persistentVisible);
    button.textContent = persistentVisible ? "🙈" : "👁";
    button.title = persistentVisible ? "Hide password" : "Show password";
    button.setAttribute("aria-pressed", persistentVisible.toString());
  };

  const releaseHold = () => {
    if (!persistentVisible) {
      setPasswordVisibility(input, false);
    }
  };

  button.addEventListener("click", () => {
    persistentVisible = !persistentVisible;
    updateState();
  });
  button.addEventListener("mousedown", () => setPasswordVisibility(input, true));
  ["mouseup", "mouseleave", "mouseout", "blur"].forEach((event) => {
    button.addEventListener(event, releaseHold);
  });

  updateState();
}

function setChangeIndicator(button, hint, hasChanges, label) {
  if (button) button.disabled = !hasChanges;
  if (hint) {
    hint.textContent = hasChanges ? label || "Unsaved changes" : "No changes";
    hint.classList.toggle("dirty", hasChanges);
  }
}

function updateApChangeState() {
  const { apSsidInput, apPasswordInput, apOctetInput, apChannelInput, applyApBtn, apChangeHint } =
    dashboardElements;
  const currentValues = {
    ssid: normalizeTextValue(apSsidInput?.value),
    password: normalizePasswordValue(apPasswordInput?.value),
    subnet_octet: normalizeNumberValue(apOctetInput?.value),
    channel: normalizeNumberValue(apChannelInput?.value),
  };
  const baseline = formState.apBaseline;
  const hasChanges =
    currentValues.ssid !== baseline.ssid ||
    currentValues.password !== baseline.password ||
    currentValues.subnet_octet !== baseline.subnet_octet ||
    currentValues.channel !== baseline.channel;
  setChangeIndicator(applyApBtn, apChangeHint, hasChanges);
}

function updateDnsChangeState() {
  const { dnsRedirectInput, dnsTargetInput, applyDnsBtn, dnsChangeHint } = dashboardElements;
  const currentValues = {
    redirect: normalizeTextValue(dnsRedirectInput?.value),
    target: normalizeTextValue(dnsTargetInput?.value),
  };
  const baseline = formState.dnsBaseline;
  const hasChanges = currentValues.redirect !== baseline.redirect || currentValues.target !== baseline.target;
  setChangeIndicator(applyDnsBtn, dnsChangeHint, hasChanges);
}

function updateFormChangeStates() {
  updateApChangeState();
  updateDnsChangeState();
}

function setApBaseline(apSummary) {
  formState.apBaseline = {
    ssid: normalizeTextValue(apSummary?.ssid),
    password: "",
    subnet_octet:
      apSummary?.subnet_octet !== undefined ? normalizeNumberValue(apSummary.subnet_octet) : "",
    channel: apSummary?.channel !== undefined ? normalizeNumberValue(apSummary.channel) : "",
  };
}

function setDnsBaseline(dnsSummary) {
  formState.dnsBaseline = {
    redirect: normalizeTextValue(dnsSummary?.redirect),
    target: normalizeTextValue(dnsSummary?.target),
  };
}

function setBaselines(apSummary, dnsSummary) {
  setApBaseline(apSummary);
  setDnsBaseline(dnsSummary);
  updateFormChangeStates();
}

function renderAp(summary, payload) {
  const { apStatus, apSsid, apOctet, apChannel } = dashboardElements;
  const statusValue = (payload?.status || "unknown").toString();
  setStateText(apStatus, statusValue, statusValue);
  if (apSsid) apSsid.textContent = summary?.ssid || "—";
  if (apOctet) apOctet.textContent = summary?.subnet_octet ?? "—";
  if (apChannel) apChannel.textContent = summary?.channel ?? "—";
}

function renderDns(summary, payload) {
  const { dnsStatus, dnsRedirect, dnsTarget } = dashboardElements;
  const statusValue = (payload?.status || "unknown").toString();
  setStateText(dnsStatus, statusValue, statusValue);
  if (dnsRedirect) dnsRedirect.textContent = summary?.redirect || "—";
  if (dnsTarget) dnsTarget.textContent = summary?.target || "—";
}

function getDriftSummaryText(section) {
  const statusValue = normalizeStatus(section?.status);
  const summaryText = normalizeTextValue(section?.mismatch_summary);
  if (summaryText) return `Drift detected: ${summaryText}`;
  if (statusValue === "warning") {
    return "Configuration drift detected. Reapply to sync stored and live settings.";
  }
  return "";
}

function renderDriftSummary(el, section) {
  if (!el) return;
  const displayText = getDriftSummaryText(section);
  const shouldShow = hasDrift(section) && !!displayText;
  if (shouldShow) {
    el.textContent = displayText;
    el.hidden = false;
    el.classList.toggle("warning", true);
  } else {
    el.textContent = "";
    el.hidden = true;
    el.classList.remove("warning");
  }
}

function renderMismatchSummaries(ap, dns) {
  const { apDriftSummary, dnsDriftSummary } = dashboardElements;
  renderDriftSummary(apDriftSummary, ap);
  renderDriftSummary(dnsDriftSummary, dns);
}

function renderNatRepairHint(natResult) {
  const { apNatHint } = dashboardElements;
  if (!apNatHint) return;

  const natStatus = normalizeStatus(natResult?.status);
  const guidance = normalizeTextValue(natResult?.guidance);
  const natMessage = normalizeTextValue(natResult?.message);
  const shouldShow =
    !!natResult &&
    (natResult?.repair_attempted || natStatus === "warning" || natStatus === "error" || natResult?.inspection_failed);

  if (shouldShow && (guidance || natMessage)) {
    apNatHint.textContent = guidance || natMessage;
    apNatHint.hidden = false;
    apNatHint.classList.toggle("warning", natStatus !== "ok");
  } else {
    apNatHint.textContent = "";
    apNatHint.hidden = true;
    apNatHint.classList.remove("warning");
  }
}

function hasDrift(section) {
  const statusValue = normalizeStatus(section?.status);
  const mismatchSummary = normalizeTextValue(section?.mismatch_summary);
  return statusValue === "warning" || !!mismatchSummary;
}

function getDriftConfirmMessage(section, label) {
  if (!hasDrift(section)) return "";
  const detail =
    getDriftSummaryText(section) ||
    "Configuration drift detected. Reapply to sync stored and live settings.";
  const prefix = label ? `${label} drift detected. ` : "";
  return `${prefix}${detail} Force apply to reconcile stored and live settings?`;
}

function extractStatusSections(payload) {
  const ap = payload?.ap || payload?.ap_status || {};
  const dns = payload?.dns || payload?.dns_status || {};
  return {
    ap,
    dns,
    apSummary: ap.ap_summary || ap,
    dnsSummary: dns.dns_summary || dns,
  };
}

function renderStatus(payload) {
  const sections = extractStatusSections(payload);
  renderAp(sections.apSummary, sections.ap);
  renderDns(sections.dnsSummary, sections.dns);
  renderMismatchSummaries(sections.ap, sections.dns);
  fillForms(sections.apSummary, sections.dnsSummary);
  return sections;
}

function cacheStatusSections(sections) {
  dashboardState.latestApStatus = sections?.ap || null;
  dashboardState.latestDnsStatus = sections?.dns || null;
}

function fillForms(apSummary, dnsSummary) {
  const {
    apSsidInput,
    apPasswordInput,
    apOctetInput,
    apChannelInput,
    dnsRedirectInput,
    dnsTargetInput,
    dnsKnownServers,
  } = dashboardElements;
  if (apSsidInput && apSummary?.ssid) apSsidInput.value = apSummary.ssid;
  if (apOctetInput && apSummary?.subnet_octet !== undefined) apOctetInput.value = apSummary.subnet_octet;
  if (apChannelInput && apSummary?.channel !== undefined) apChannelInput.value = apSummary.channel;
  if (apPasswordInput) apPasswordInput.value = "";
  if (dnsRedirectInput && dnsSummary?.redirect) dnsRedirectInput.value = dnsSummary.redirect;
  if (dnsTargetInput && dnsSummary?.target) dnsTargetInput.value = dnsSummary.target;
  if (dnsKnownServers) {
    const desiredRedirect = (dnsSummary?.redirect || "").toLowerCase();
    const matchingOption = Array.from(dnsKnownServers.options || []).find(
      (opt) => (opt.dataset.redirect || opt.value || "").toLowerCase() === desiredRedirect,
    );
    dnsKnownServers.value = matchingOption ? matchingOption.value : "";
  }

  setBaselines(apSummary || {}, dnsSummary || {});
}

function showOutput(data) {
  const { output } = dashboardElements;
  if (!output) return;
  output.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
}

function renderKnownServers(entries) {
  const { dnsKnownServers } = dashboardElements;
  if (!dnsKnownServers) return;

  dnsKnownServers.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = entries?.length ? "Select a known server…" : "No known servers available";
  placeholder.disabled = !entries?.length;
  placeholder.selected = true;
  dnsKnownServers.appendChild(placeholder);

  (entries || []).forEach((entry, index) => {
    const option = document.createElement("option");
    option.value = entry?.redirect || `known-${index}`;
    option.textContent = entry?.label || entry?.redirect || entry?.target || "Entry";
    option.dataset.redirect = entry?.redirect || "";
    option.dataset.target = entry?.target || "";
    option.dataset.defaultTarget = entry?.default_target || "";
    dnsKnownServers.appendChild(option);
  });

  if (entries?.length) {
    const desiredRedirect = (dashboardElements.dnsRedirectInput?.value || "").toLowerCase();
    const match = Array.from(dnsKnownServers.options || []).find(
      (opt) => (opt.dataset.redirect || opt.value || "").toLowerCase() === desiredRedirect,
    );
    dnsKnownServers.value = match ? match.value : "";
    dnsKnownServers.disabled = false;
  } else {
    dnsKnownServers.value = "";
    dnsKnownServers.disabled = true;
  }
}

async function fetchKnownServers(force = false) {
  if (dashboardState.knownServersLoaded && !force) {
    renderKnownServers(dashboardState.knownServers || []);
    return dashboardState.knownServers || [];
  }

  try {
    const res = await fetch("/dns/knownservers");
    if (!res.ok) {
      showOutput(`Known servers error ${res.status}`);
      renderKnownServers([]);
      return [];
    }
    const payload = await res.json();
    const entries = Array.isArray(payload?.entries)
      ? payload.entries
      : Array.isArray(payload?.servers)
        ? payload.servers
        : [];
    dashboardState.knownServers = entries;
    dashboardState.knownServersLoaded = true;
    renderKnownServers(entries);
    return entries;
  } catch (err) {
    showOutput(`Failed to load known servers: ${err}`);
    renderKnownServers([]);
    return [];
  }
}

function applyKnownServerSelection(selectedOption) {
  if (!selectedOption) return;
  const { dnsRedirectInput, dnsTargetInput } = dashboardElements;
  const redirect = selectedOption.dataset.redirect || selectedOption.value;
  const target = selectedOption.dataset.target || selectedOption.dataset.defaultTarget;
  if (dnsRedirectInput && redirect) dnsRedirectInput.value = redirect;
  if (dnsTargetInput && target) dnsTargetInput.value = target;
  updateDnsChangeState();
}

function handleKnownServerChange(event) {
  const selectedOption = event?.target?.selectedOptions?.[0];
  if (!selectedOption || !selectedOption.value) return;
  applyKnownServerSelection(selectedOption);
}

function setUpstreamError(message) {
  const { upstreamError } = dashboardElements;
  if (!upstreamError) return;
  const text = normalizeTextValue(message);
  upstreamError.textContent = text;
  upstreamError.hidden = !text;
}

function buildUpstreamErrorMessage(payload, fallback) {
  const fallbackText = normalizeTextValue(fallback);
  if (!payload || typeof payload !== "object") return fallbackText;
  const message = normalizeTextValue(payload?.message || payload?.stderr || payload?.error || fallbackText);
  const detail = payload?.detail || {};
  const hint = normalizeTextValue(detail?.hint);
  const agentSocket = normalizeTextValue(detail?.agent_socket);
  const isAgentIssue =
    !!hint || !!agentSocket || message.toLowerCase().includes("agent") || message.toLowerCase().includes("privilege");
  if (!isAgentIssue) return message;
  const guidance =
    hint ||
    "Start the agent service with: sudo systemctl start mcbridge-agent.service (and ensure it is enabled).";
  const parts = ["Agent privileges unavailable.", guidance];
  if (agentSocket) {
    parts.push(`Socket: ${agentSocket}.`);
  }
  return parts.join(" ");
}

function syncUpstreamPasswordMode() {
  const { upstreamPasswordInput } = dashboardElements;
  if (upstreamPasswordInput) {
    upstreamPasswordInput.placeholder = "Passphrase";
  }
}

function renderUpstreamDrift(drift, message, warnings) {
  const { upstreamDrift } = dashboardElements;
  if (!upstreamDrift) return;
  const parts = [];
  if (message) parts.push(message);
  if (drift?.missing_in_storage?.length) {
    parts.push(`System has ${drift.missing_in_storage.length} network(s) not yet saved.`);
    parts.push("System-only networks must be forgotten to remove them from the system.");
  }
  if (drift?.missing_in_system?.length) {
    parts.push(`${drift.missing_in_system.length} saved network(s) are not present on the system.`);
  }
  if (drift?.mismatched?.length) {
    parts.push(`${drift.mismatched.length} network(s) differ between saved and system config.`);
  }
  if (drift?.password_gaps?.length) {
    parts.push(`Passwords missing for ${drift.password_gaps.length} system network(s).`);
  }
  if (warnings?.length) {
    parts.push(`Warnings: ${warnings.join("; ")}`);
  }
  const text = parts.join(" ");
  upstreamDrift.hidden = !text;
  upstreamDrift.textContent = text;
  upstreamDrift.classList.toggle("warning", !!text);
}

function updateSaveCurrentButton() {
  const { saveCurrentUpstreamBtn } = dashboardElements;
  if (!saveCurrentUpstreamBtn) return;
  const drift = upstreamState.drift || {};
  const hasSystemProfiles = Array.isArray(upstreamState.systemProfiles) && upstreamState.systemProfiles.length > 0;
  const hasNewProfiles =
    (Array.isArray(drift.missing_in_storage) && drift.missing_in_storage.length > 0) ||
    (Array.isArray(drift.mismatched) && drift.mismatched.length > 0);
  const missingPasswords = Array.isArray(drift.password_gaps) && drift.password_gaps.length > 0;
  saveCurrentUpstreamBtn.disabled = !(hasSystemProfiles && hasNewProfiles && !missingPasswords);
  if (missingPasswords) {
    saveCurrentUpstreamBtn.title = "Cannot save current config while passwords are missing.";
  } else {
    saveCurrentUpstreamBtn.removeAttribute("title");
  }
}

function renderUpstreamStatus(payload) {
  const { upstreamStatus } = dashboardElements;
  const statusValue = payload?.status || "unknown";
  setStateText(upstreamStatus, statusValue, statusValue);
  upstreamState.statusText = statusValue;
  upstreamState.statusValue = statusValue;
  upstreamState.profiles = Array.isArray(payload?.profiles) ? payload.profiles : [];
  upstreamState.storedProfiles = Array.isArray(payload?.stored_profiles) ? payload.stored_profiles : [];
  upstreamState.systemProfiles = Array.isArray(payload?.system_profiles) ? payload.system_profiles : [];
  upstreamState.drift = payload?.drift || null;
  renderUpstreamProfiles(upstreamState.profiles);
  renderUpstreamDrift(payload?.drift, payload?.message, payload?.warnings);
  updateSaveCurrentButton();
}

function renderUpstreamProfiles(profiles) {
  const { upstreamProfilesBody } = dashboardElements;
  if (!upstreamProfilesBody) return;

  upstreamProfilesBody.innerHTML = "";
  const entries = Array.isArray(profiles) ? profiles : [];
  if (!entries.length) {
    const emptyRow = document.createElement("tr");
    const emptyCell = document.createElement("td");
    emptyCell.colSpan = 7;
    emptyCell.className = "muted";
    emptyCell.textContent = "No upstream networks detected. Refresh or add a network.";
    emptyRow.appendChild(emptyCell);
    upstreamProfilesBody.appendChild(emptyRow);
    return;
  }

  const availabilityLabels = {
    active: "Active",
    available: "Available",
    unavailable: "Unavailable",
  };

  entries.forEach((profile) => {
    const row = document.createElement("tr");
    row.dataset.ssid = profile?.ssid || "";
    const isBusy = upstreamState.loading;

    const ssidCell = document.createElement("td");
    ssidCell.textContent = profile?.ssid || "—";
    const priorityCell = document.createElement("td");
    priorityCell.textContent = profile?.priority ?? "—";
    const securityCell = document.createElement("td");
    securityCell.textContent = profile?.security || "—";

    const availabilityCell = document.createElement("td");
    const availabilityKey = normalizeTextValue(profile?.availability).toLowerCase();
    const availabilityBadge = document.createElement("span");
    availabilityBadge.className = "availability";
    if (availabilityKey) {
      availabilityBadge.classList.add(`availability--${availabilityKey}`);
    }
    availabilityBadge.textContent = availabilityLabels[availabilityKey] || "—";
    availabilityCell.appendChild(availabilityBadge);

    const signalCell = document.createElement("td");
    const rawSignal = profile?.signal_strength;
    const signalValue = Number.isFinite(rawSignal) ? rawSignal : parseFloat(rawSignal);
    if (!Number.isFinite(signalValue)) {
      signalCell.textContent = "—";
    } else {
      const clampedSignal = Math.max(0, Math.min(100, signalValue));
      const signalWrap = document.createElement("div");
      signalWrap.className = "signal-meter";
      const signalFill = document.createElement("div");
      signalFill.className = "signal-meter__fill";
      if (clampedSignal < 34) {
        signalFill.classList.add("signal-meter__fill--low");
      } else if (clampedSignal < 67) {
        signalFill.classList.add("signal-meter__fill--medium");
      } else {
        signalFill.classList.add("signal-meter__fill--high");
      }
      signalFill.style.width = `${Math.round(clampedSignal)}%`;
      signalFill.setAttribute("aria-label", `Signal strength ${Math.round(clampedSignal)}%`);
      const signalText = document.createElement("span");
      signalText.className = "signal-meter__label";
      signalText.textContent = `${Math.round(clampedSignal)}%`;
      signalWrap.appendChild(signalFill);
      signalWrap.appendChild(signalText);
      signalCell.appendChild(signalWrap);
    }

    const stateCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "badge";
    let badgeText = profile?.saved ? "Saved" : "System";
    if (profile?.source && !profile?.saved) {
      badgeText = profile.source;
    }
    if (profile?.drift) {
      badge.classList.add("warning");
      badgeText = profile?.saved ? "Drift" : `${badgeText} (drift)`;
    }
    if (profile?.password_missing) {
      badge.classList.add("danger");
      badgeText = `${badgeText} (password missing)`;
    }
    badge.textContent = badgeText;
    stateCell.appendChild(badge);

    const actionsCell = document.createElement("td");
    actionsCell.className = "table-actions";
    const activateBtn = document.createElement("button");
    activateBtn.type = "button";
    activateBtn.className = "secondary upstream-action";
    activateBtn.textContent = "Activate";
    const canActivate = availabilityKey === "available";
    activateBtn.disabled = isBusy || !canActivate;
    activateBtn.addEventListener("click", () => activateUpstreamNetwork(profile?.ssid, activateBtn));

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "secondary upstream-action";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => setUpstreamSelection(profile));

    const isSystemOnly = profile?.saved === false;
    const isActive = availabilityKey === "active";
    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "secondary danger upstream-action";
    deleteBtn.textContent = "Delete";
    deleteBtn.disabled = isBusy || !profile?.saved;
    deleteBtn.addEventListener("click", () => handleInlineUpstreamDelete(profile?.ssid));

    actionsCell.appendChild(activateBtn);
    actionsCell.appendChild(editBtn);
    if (isSystemOnly) {
      const forgetBtn = document.createElement("button");
      forgetBtn.type = "button";
      forgetBtn.className = "secondary danger upstream-action";
      forgetBtn.textContent = "Forget";
      forgetBtn.disabled = isBusy || isActive;
      forgetBtn.addEventListener("click", () => handleInlineUpstreamForget(profile?.ssid));
      actionsCell.appendChild(forgetBtn);
    } else {
      actionsCell.appendChild(deleteBtn);
    }

    row.appendChild(ssidCell);
    row.appendChild(priorityCell);
    row.appendChild(securityCell);
    row.appendChild(availabilityCell);
    row.appendChild(signalCell);
    row.appendChild(stateCell);
    row.appendChild(actionsCell);
    upstreamProfilesBody.appendChild(row);
  });
}

function setUpstreamSelection(profile) {
  const {
    upstreamSsidInput,
    upstreamPasswordInput,
    upstreamPriorityInput,
    upstreamSecuritySelect,
    saveUpstreamBtn,
    deleteUpstreamBtn,
  } = dashboardElements;

  upstreamState.selectedSsid = profile?.ssid || null;
  upstreamState.selectedIsSaved = !!profile?.saved;
  if (upstreamSsidInput) {
    upstreamSsidInput.value = profile?.ssid || "";
    upstreamSsidInput.readOnly = upstreamState.selectedIsSaved;
  }
  if (upstreamPasswordInput) upstreamPasswordInput.value = "";
  if (upstreamPriorityInput) upstreamPriorityInput.value = profile?.priority ?? "";
  if (upstreamSecuritySelect) upstreamSecuritySelect.value = profile?.security || "wpa2";
  syncUpstreamPasswordMode();
  if (saveUpstreamBtn) {
    if (upstreamState.selectedIsSaved) {
      saveUpstreamBtn.textContent = "Update network";
    } else if (upstreamState.selectedSsid) {
      saveUpstreamBtn.textContent = "Save network";
    } else {
      saveUpstreamBtn.textContent = "Add network";
    }
  }
  if (deleteUpstreamBtn) deleteUpstreamBtn.disabled = !upstreamState.selectedIsSaved;
}

function resetUpstreamForm() {
  setUpstreamSelection(null);
  setUpstreamError("");
  const { upstreamPasswordInput, upstreamPriorityInput } = dashboardElements;
  if (upstreamPasswordInput) upstreamPasswordInput.value = "";
  if (upstreamPriorityInput) upstreamPriorityInput.value = "";
  syncUpstreamPasswordMode();
}

function findUpstreamProfile(ssid) {
  const target = normalizeSsidKey(ssid || "");
  return upstreamState.profiles.find((entry) => normalizeSsidKey(entry?.ssid || "") === target);
}

function parseRequiredPriority(input) {
  const parsed = parseNumberField(input);
  if (parsed === null || Number.isNaN(parsed)) {
    throw new Error("Priority is required.");
  }
  if (parsed <= 0) {
    throw new Error("Priority must be a positive number.");
  }
  return parsed;
}

function getUpstreamFormPayload() {
  const { upstreamSsidInput, upstreamPasswordInput, upstreamPriorityInput, upstreamSecuritySelect } =
    dashboardElements;
  const ssid = normalizeTextValue(upstreamSsidInput?.value);
  if (!ssid) {
    throw new Error("SSID is required.");
  }

  const security = normalizeTextValue(upstreamSecuritySelect?.value) || "open";
  const password = upstreamPasswordInput?.value ?? "";
  const priority = parseRequiredPriority(upstreamPriorityInput);

  return { ssid, password, priority: Number(priority), security };
}

function setUpstreamBusy(isBusy, message) {
  const {
    upstreamStatus,
    upstreamSsidInput,
    upstreamPasswordInput,
    upstreamPasswordToggle,
    upstreamPriorityInput,
    upstreamSecuritySelect,
    refreshUpstreamBtn,
    saveUpstreamBtn,
    resetUpstreamBtn,
    deleteUpstreamBtn,
    saveCurrentUpstreamBtn,
  } = dashboardElements;

  if (isBusy) {
    upstreamState.loadingCount += 1;
    if (message) {
      upstreamState.busyMessage = message;
    }
  } else {
    upstreamState.loadingCount = Math.max(0, upstreamState.loadingCount - 1);
    if (upstreamState.loadingCount === 0) {
      upstreamState.busyMessage = "";
    }
  }

  const busy = upstreamState.loadingCount > 0;
  upstreamState.loading = busy;

  if (busy) {
    const statusMessage = upstreamState.busyMessage || message || "Working…";
    setStateText(upstreamStatus, statusMessage, "");
  } else {
    setStateText(upstreamStatus, upstreamState.statusText || "—", upstreamState.statusValue || "");
  }

  [
    upstreamSsidInput,
    upstreamPasswordInput,
    upstreamPasswordToggle,
    upstreamPriorityInput,
    upstreamSecuritySelect,
    refreshUpstreamBtn,
    saveUpstreamBtn,
    resetUpstreamBtn,
    deleteUpstreamBtn,
    saveCurrentUpstreamBtn,
  ].forEach((el) => {
    if (el) el.disabled = busy;
  });

  document.querySelectorAll(".upstream-action").forEach((button) => {
    if (button instanceof HTMLButtonElement) {
      button.disabled = busy || button.disabled;
    }
  });

  if (!busy) {
    renderUpstreamProfiles(upstreamState.profiles);
  }
}

async function fetchUpstreamStatus() {
  setUpstreamError("");
  setUpstreamBusy(true, "Loading…");
  try {
    const res = await fetch("/upstream/status");
    const payload = await res.json().catch(() => ({}));
    if (!res.ok || payload?.status === "error") {
      const message = buildUpstreamErrorMessage(payload, `Failed to load upstream networks (${res.status})`);
      setUpstreamError(message || `Failed to load upstream networks (${res.status})`);
      upstreamState.profiles = [];
      upstreamState.systemProfiles = [];
      upstreamState.drift = null;
      renderUpstreamProfiles([]);
      updateSaveCurrentButton();
      return;
    }
    renderUpstreamStatus(payload);
    if (payload?.warnings?.length) {
      setUpstreamError(payload.warnings.join("; "));
    }
  } catch (err) {
    setUpstreamError(`Unable to load upstream networks: ${err}`);
    upstreamState.profiles = [];
    upstreamState.systemProfiles = [];
    upstreamState.drift = null;
    renderUpstreamProfiles([]);
    updateSaveCurrentButton();
  } finally {
    setUpstreamBusy(false);
  }
}

async function applyUpstreamConfig() {
  setUpstreamBusy(true, "Applying upstream Wi-Fi…");
  setUpstreamError("");
  const controller = new AbortController();
  const timeoutMs = 20000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch("/upstream/apply", { method: "POST", signal: controller.signal });
    const payload = await res.json().catch(() => ({}));
    if (!res.ok || !payload?.job_id) {
      showOutput(payload);
      const message = buildUpstreamErrorMessage(payload, `Unable to apply upstream Wi-Fi (${res.status})`);
      setUpstreamError(message || `Unable to apply upstream Wi-Fi (${res.status})`);
      return false;
    }
    if (res.status === 202) {
      return await pollUpstreamApply(payload.job_id);
    }
    return await pollUpstreamApply(payload.job_id);
  } catch (err) {
    if (err?.name === "AbortError") {
      setUpstreamError("Upstream apply timed out. Please try again.");
      return false;
    }
    setUpstreamError(`Unable to apply upstream Wi-Fi: ${err}`);
    return false;
  } finally {
    clearTimeout(timeoutId);
    setUpstreamBusy(false);
  }
}

async function pollUpstreamApply(jobId) {
  const pollIntervalMs = 2000;
  const timeoutMs = 5 * 60 * 1000;
  const deadline = Date.now() + timeoutMs;

  while (true) {
    if (Date.now() > deadline) {
      setUpstreamError("Timed out waiting for upstream apply to finish.");
      return false;
    }
    await delay(pollIntervalMs);
    let res;
    let payload = {};
    try {
      res = await fetch(`/upstream/apply/status/${encodeURIComponent(jobId)}`);
      payload = await res.json().catch(() => ({}));
    } catch (err) {
      setUpstreamError(`Unable to check upstream apply status: ${err}`);
      return false;
    }

    if (!res.ok) {
      showOutput(payload);
      const message = buildUpstreamErrorMessage(payload, `Unable to check upstream apply status (${res.status})`);
      setUpstreamError(message || `Unable to check upstream apply status (${res.status})`);
      return false;
    }

    const state = normalizeStatus(payload?.state);
    if (!state || state === "running") {
      continue;
    }

    const resultPayload = payload?.payload || payload?.error || payload;
    if (resultPayload) {
      showOutput(resultPayload);
    }

    if (state === "completed") {
      if (payload?.payload?.warnings?.length) {
        setUpstreamError(payload.payload.warnings.join("; "));
      }
      await fetchUpstreamStatus();
      return true;
    }

    if (state === "error") {
      const message = buildUpstreamErrorMessage(
        resultPayload,
        "Unable to apply upstream Wi-Fi (unknown error)."
      );
      setUpstreamError(message || "Unable to apply upstream Wi-Fi (unknown error).");
      return false;
    }
  }
}

async function activateUpstreamNetwork(ssid, button) {
  if (upstreamState.loading) return false;
  const target = normalizeTextValue(ssid);
  if (!target) {
    setUpstreamError("SSID is required to activate.");
    return false;
  }
  const previousLabel = button?.textContent;
  if (button) {
    button.textContent = "Activating…";
  }
  setUpstreamBusy(true, `Activating ${target}…`);
  setUpstreamError("");
  try {
    const res = await fetch("/upstream/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid: target }),
    });
    const payload = await res.json().catch(() => ({}));
    showOutput(payload);
    if (!res.ok || payload?.status === "error") {
      const message = buildUpstreamErrorMessage(payload, `Unable to activate ${target} (${res.status})`);
      setUpstreamError(message || `Unable to activate ${target} (${res.status})`);
      return false;
    }
    if (payload?.warnings?.length) {
      setUpstreamError(payload.warnings.join("; "));
    }
    await fetchUpstreamStatus();
    return true;
  } catch (err) {
    setUpstreamError(`Unable to activate ${target}: ${err}`);
    return false;
  } finally {
    if (button) {
      button.textContent = previousLabel || "Activate";
    }
    setUpstreamBusy(false);
  }
}

async function saveUpstreamProfile(event) {
  event?.preventDefault();
  if (upstreamState.loading) return;
  setUpstreamBusy(true, "Saving upstream network…");
  setUpstreamError("");
  let payload;
  try {
    payload = getUpstreamFormPayload();
  } catch (err) {
    setUpstreamError(err.message);
    setUpstreamBusy(false);
    return;
  }

  const isUpdate = upstreamState.selectedIsSaved && upstreamState.selectedSsid;
  if (!isUpdate && payload.security.toLowerCase() !== "open" && !payload.password) {
    setUpstreamError("Password is required for secured networks.");
    setUpstreamBusy(false);
    return;
  }
  const body = {
    ...payload,
    ssid: isUpdate ? upstreamState.selectedSsid : payload.ssid,
  };
  if (isUpdate && !payload.password) {
    delete body.password;
  }
  const method = isUpdate ? "PATCH" : "POST";

  try {
    const res = await fetch("/upstream/profiles", {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const responsePayload = await res.json().catch(() => ({}));
    showOutput(responsePayload);
    if (!res.ok || responsePayload?.status === "error") {
      const message = buildUpstreamErrorMessage(
        responsePayload,
        `Unable to save upstream network (${res.status})`
      );
      setUpstreamError(message || `Unable to save upstream network (${res.status})`);
      return;
    }
    await applyUpstreamConfig();
    await fetchUpstreamStatus();
    resetUpstreamForm();
  } catch (err) {
    setUpstreamError(`Request failed: ${err}`);
  } finally {
    setUpstreamBusy(false);
  }
}

async function deleteUpstreamProfile(ssid) {
  if (upstreamState.loading) return;
  setUpstreamBusy(true, "Deleting upstream network…");
  const targetSsid = normalizeTextValue(ssid || upstreamState.selectedSsid);
  if (!targetSsid) {
    setUpstreamBusy(false);
    return;
  }
  const profile = findUpstreamProfile(targetSsid);
  if (profile && profile.saved === false) {
    setUpstreamError("Only saved upstream networks can be deleted.");
    setUpstreamBusy(false);
    return;
  }
  setUpstreamError("");

  try {
    const res = await fetch("/upstream/profiles", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid: targetSsid }),
    });
    const payload = await res.json().catch(() => ({}));
    showOutput(payload);
    if (!res.ok || payload?.status === "error") {
      const message = buildUpstreamErrorMessage(payload, `Failed to delete ${targetSsid} (${res.status})`);
      setUpstreamError(message || `Failed to delete ${targetSsid} (${res.status})`);
      return;
    }
    await applyUpstreamConfig();
    await fetchUpstreamStatus();
    resetUpstreamForm();
  } catch (err) {
    setUpstreamError(`Failed to delete upstream network: ${err}`);
  } finally {
    setUpstreamBusy(false);
  }
}

async function forgetUpstreamSystemProfile(ssid) {
  if (upstreamState.loading) return;
  setUpstreamBusy(true, "Forgetting system network…");
  const targetSsid = normalizeTextValue(ssid);
  if (!targetSsid) {
    setUpstreamBusy(false);
    return;
  }
  setUpstreamError("");

  try {
    const res = await fetch("/upstream/system/forget", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid: targetSsid }),
    });
    const payload = await res.json().catch(() => ({}));
    showOutput(payload);
    if (!res.ok || payload?.status === "error") {
      const message = buildUpstreamErrorMessage(payload, `Failed to forget ${targetSsid} (${res.status})`);
      setUpstreamError(message || `Failed to forget ${targetSsid} (${res.status})`);
      return;
    }
    if (payload?.warnings?.length) {
      setUpstreamError(payload.warnings.join("; "));
    }
    await fetchUpstreamStatus();
    resetUpstreamForm();
  } catch (err) {
    setUpstreamError(`Failed to forget system network: ${err}`);
  } finally {
    setUpstreamBusy(false);
  }
}

function handleInlineUpstreamDelete(ssid) {
  const target = normalizeTextValue(ssid);
  if (!target) return;
  const profile = findUpstreamProfile(target);
  if (profile && profile.saved === false) {
    setUpstreamError("Only saved upstream networks can be deleted.");
    return;
  }
  const confirmed = confirm(`Remove upstream network "${target}"?`);
  if (!confirmed) return;
  deleteUpstreamProfile(target);
}

function handleInlineUpstreamForget(ssid) {
  const target = normalizeTextValue(ssid);
  if (!target) return;
  const profile = findUpstreamProfile(target);
  if (profile?.availability === "active") {
    setUpstreamError("Cannot forget the active upstream connection.");
    return;
  }
  const confirmed = confirm(`Forget system network "${target}"?`);
  if (!confirmed) return;
  forgetUpstreamSystemProfile(target);
}

function handleUpstreamDelete(event) {
  event?.preventDefault();
  if (!upstreamState.selectedSsid || !upstreamState.selectedIsSaved) {
    setUpstreamError("Select a saved network to delete.");
    return;
  }
  handleInlineUpstreamDelete(upstreamState.selectedSsid);
}

async function persistCurrentUpstreamConfig() {
  if (upstreamState.loading) return;
  setUpstreamBusy(true, "Saving current upstream config…");
  setUpstreamError("");
  try {
    const res = await fetch("/upstream/save-current", { method: "POST" });
    const payload = await res.json().catch(() => ({}));
    showOutput(payload);
    if (!res.ok || payload?.status === "error") {
      const message = buildUpstreamErrorMessage(payload, `Failed to save current config (${res.status})`);
      setUpstreamError(message || `Failed to save current config (${res.status})`);
      return;
    }
    await applyUpstreamConfig();
    await fetchUpstreamStatus();
  } catch (err) {
    setUpstreamError(`Unable to save current config: ${err}`);
  } finally {
    setUpstreamBusy(false);
  }
}

async function fetchStatus() {
  const { apStatus, dnsStatus } = dashboardElements;
  setStateText(apStatus, "Loading…", "");
  setStateText(dnsStatus, "Loading…", "");
  try {
    const res = await fetch("/status");
    const contentType = res.headers.get("content-type") || "";
    const isJson = contentType.includes("application/json");
    const payload = isJson ? await res.json() : await res.text();

    if (!res.ok) {
      const isServerError = res.status >= 500;
      if (isServerError && payload) {
        const errorMessage =
          typeof payload === "object" && payload !== null ? payload.message || payload.error : null;
        const stderr = typeof payload === "object" && payload !== null ? payload.stderr : null;
        const errorParts = [];
        if (errorMessage) errorParts.push(errorMessage);
        if (stderr && stderr !== errorMessage) errorParts.push(stderr);
        if (!errorParts.length && typeof payload === "string") errorParts.push(payload);
        showOutput(errorParts.join("\n") || `Status error ${res.status}`);
      } else {
        showOutput(typeof payload === "string" ? payload : `Status error ${res.status}`);
      }
      return;
    }

    const sections = renderStatus(payload);
    cacheStatusSections(sections);
    handleDriftState(payload, sections);
    showOutput(payload);
  } catch (err) {
    showOutput(`Failed to load status: ${err}`);
  }
}

function parseNumberField(input) {
  if (!input) return null;
  const raw = input.value.trim();
  if (!raw) return null;
  const parsed = Number(raw);
  if (Number.isNaN(parsed)) {
    throw new Error(`${input.name || "field"} must be a number`);
  }
  return parsed;
}

async function submitAp(event) {
  event?.preventDefault();
  const {
    apSsidInput,
    apPasswordInput,
    apOctetInput,
    apChannelInput,
  } = dashboardElements;

  let subnetOctet = null;
  let channel = null;
  try {
    subnetOctet = parseNumberField(apOctetInput);
    channel = parseNumberField(apChannelInput);
  } catch (err) {
    alert(err.message);
    return;
  }

  const body = {};
  const ssid = apSsidInput?.value.trim();
  if (ssid) body.ssid = ssid;
  if (apPasswordInput) {
    const pwd = apPasswordInput.value;
    if (pwd !== "") body.password = pwd;
  }
  if (subnetOctet !== null) body.subnet_octet = subnetOctet;
  if (channel !== null) body.channel = channel;

  const apDriftMessage = getDriftConfirmMessage(dashboardState.latestApStatus, "AP");
  if (apDriftMessage) {
    const confirmed = confirm(apDriftMessage);
    if (!confirmed) return;
    body.force = true;
  }

  await postAndRender("/ap/update", body);
}

async function submitDns(event) {
  event?.preventDefault();
  const { dnsRedirectInput, dnsTargetInput } = dashboardElements;
  const body = {};
  const redirect = dnsRedirectInput?.value.trim();
  const target = dnsTargetInput?.value.trim();
  if (redirect) body.redirect = redirect;
  if (target) body.target = target;
  const dnsDriftMessage = getDriftConfirmMessage(dashboardState.latestDnsStatus, "DNS");
  if (dnsDriftMessage) {
    const confirmed = confirm(dnsDriftMessage);
    if (!confirmed) return;
    body.force = true;
  }
  await postAndRender("/dns/update", body);
}

function handleNatRepairHint(payload) {
  const natResult = payload?.iptables || payload?.changes?.iptables;
  if (!natResult) return;
  renderNatRepairHint(natResult);
}

async function postAndRender(url, body) {
  showOutput("Running…");
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const isJson = res.headers.get("content-type")?.includes("application/json");
    const payload = isJson ? await res.json() : await res.text();
    showOutput(payload);
    if (isJson) handleNatRepairHint(payload);
    if (res.ok) {
      await fetchStatus();
    }
  } catch (err) {
    showOutput(`Request failed: ${err}`);
  }
}

function handleDriftState(payload, sections) {
  const { applyApBtn, apChangeHint, applyDnsBtn, dnsChangeHint } = dashboardElements;
  const apDrift = hasDrift(sections?.ap);
  const dnsDrift = hasDrift(sections?.dns);

  if (apDrift) {
    setChangeIndicator(applyApBtn, apChangeHint, true, "Drift detected");
  }
  if (dnsDrift) {
    setChangeIndicator(applyDnsBtn, dnsChangeHint, true, "Drift detected");
  }
}

function bindEvents() {
  const {
    refreshApBtn,
    refreshDnsBtn,
    refreshKnownServersBtn,
    refreshUpstreamBtn,
    apForm,
    dnsForm,
    upstreamForm,
    dnsKnownServers,
    apSsidInput,
    apPasswordInput,
    apPasswordToggle,
    apOctetInput,
    apChannelInput,
    dnsRedirectInput,
    dnsTargetInput,
    resetUpstreamBtn,
    deleteUpstreamBtn,
    saveCurrentUpstreamBtn,
    upstreamPasswordToggle,
    upstreamPasswordInput,
  } = dashboardElements;
  refreshApBtn?.addEventListener("click", fetchStatus);
  refreshDnsBtn?.addEventListener("click", () => {
    fetchStatus();
    fetchKnownServers(true);
  });
  refreshKnownServersBtn?.addEventListener("click", () => fetchKnownServers(true));
  refreshUpstreamBtn?.addEventListener("click", () => fetchUpstreamStatus());
  dnsKnownServers?.addEventListener("change", handleKnownServerChange);
  apForm?.addEventListener("submit", submitAp);
  dnsForm?.addEventListener("submit", submitDns);
  upstreamForm?.addEventListener("submit", saveUpstreamProfile);
  resetUpstreamBtn?.addEventListener("click", resetUpstreamForm);
  deleteUpstreamBtn?.addEventListener("click", handleUpstreamDelete);
  saveCurrentUpstreamBtn?.addEventListener("click", persistCurrentUpstreamConfig);
  [apSsidInput, apPasswordInput, apOctetInput, apChannelInput].forEach((input) =>
    input?.addEventListener("input", updateApChangeState),
  );
  [dnsRedirectInput, dnsTargetInput].forEach((input) =>
    input?.addEventListener("input", updateDnsChangeState),
  );
  attachPasswordToggle(apPasswordToggle, apPasswordInput);
  attachPasswordToggle(upstreamPasswordToggle, upstreamPasswordInput);
}

function initDashboard() {
  cacheDashboardElements();
  renderKnownServers([]);
  renderUpstreamProfiles([]);
  bindEvents();
  syncUpstreamPasswordMode();
  updateFormChangeStates();
  fetchKnownServers();
  fetchUpstreamStatus();
  fetchStatus();
}

document.addEventListener("DOMContentLoaded", initDashboard);
