# mcbridge Upstream Connectivity, Recovery, and Diagnostics Plan

This document defines the next phase of work for `mcbridge`: making upstream Wi-Fi behaviour deterministic, recoverable in the field, and diagnosable without SSH.

It is intended to be:
- added to the repository as a design / implementation plan
- used as the source of truth for Codex implementation work
- granular enough to break into backlog items or issues

This plan assumes the current public repo state and install model:
- `mcbridge` is packaged as a Python project and can be installed system-wide
- `mcbridge init` performs one-time provisioning
- AP and DNS management are already first-class domains
- the privileged agent pattern already exists and is the correct mechanism for privileged actions
- the project currently targets Raspberry Pi NAT/router mode rather than true layer-2 bridging citeturn532027view0

---

## Problem Statement

`mcbridge` currently provides a good model for:

- Access Point configuration (`ap`)
- DNS overrides (`dns`)
- packaged install + one-time provisioning
- least-privilege runtime services

However, the *upstream Wi-Fi* experience is not yet robust enough for field installation and support.

In particular:

1. Upstream Wi-Fi profiles are not yet treated as **role-aware operating modes**.
2. The system lacks a clear **recovery path** when a destination-site network is unavailable or misconfigured.
3. The system lacks a deterministic **fallback sequence** across known networks.
4. Diagnostics are not strong enough to support a “recover using phone hotspot, inspect, retry” workflow.
5. Field deployment currently depends too much on SSH and manual intervention.

This plan addresses those gaps.

---

## Desired User Experience

The target operator workflow should be:

1. Install `mcbridge` on a new Pi.
2. During first-time setup, define:
   - a **Recovery / Setup** network (typically the operator’s phone hotspot)
   - a **Primary** network (the destination site / installed location)
   - an optional **Secondary** network (operator’s home/test network)
3. Power-cycle the device anywhere and have it reliably choose the best available upstream based on role and priority.
4. If something goes wrong:
   - turn on the phone hotspot
   - power-cycle the unit
   - the device reconnects to Recovery
   - access the web UI
   - enable diagnostics
   - retry without the hotspot
   - reconnect to the hotspot
   - inspect captured diagnostics

This is the core product goal.

---

## Network Roles

The upstream domain should move from “saved SSID list” to “saved SSID list with explicit roles”.

### 1. Recovery
Purpose:
- rescue path
- commissioning path
- diagnostics path
- remote support path in the field

Properties:
- highest priority by default
- always retained unless explicitly force-removed
- should be easy to connect back to after a failed install or failed reconnect
- usually the operator’s phone hotspot

### 2. Primary
Purpose:
- normal installed location
- preferred network for routine operation

Properties:
- selected destination-site network
- preferred whenever available and recovery mode is not explicitly active

### 3. Secondary
Purpose:
- support / staging / testing network
- alternate known-good environment
- e.g. the operator’s home network

Properties:
- lower priority than Primary
- retained for support and testing
- can be used when Primary is unavailable and Recovery is not active

---

## Behavioural Model

### Boot / reconnect selection
At boot or when forcing an upstream reconnect, the system should choose upstream connectivity using this model:

1. If Recovery is available and “recovery-prefer” is enabled → connect Recovery
2. Else if Primary is available → connect Primary
3. Else if Secondary is available → connect Secondary
4. Else if any enabled known network is available → connect highest-priority remaining profile
5. Else surface “no upstream available” status and keep AP/UI local where possible

### Recovery bias
Recovery should not always pre-empt Primary during normal operation, otherwise the device would constantly choose the phone hotspot when it exists.

Therefore:
- Recovery should be **highest logical priority**
- but only automatically preferred when:
  - explicit recovery mode is enabled, or
  - diagnostics mode is enabled, or
  - the system has failed to reach a healthy upstream for a defined interval

### Connectivity health
Health should not mean merely “associated to a Wi-Fi network”.
Health should mean:

- associated to upstream Wi-Fi
- has IP / route
- can reach a simple internet check target (or equivalent success criterion)

This is important because “connected but no working internet” is common in the field.

---

## Architecture Changes

### 1. Make upstream a first-class managed domain
The upstream module should follow the same pattern as AP and DNS:

- persist intent
- apply intent to system
- report status
- report drift / errors
- surface a structured result to both CLI and web UI

### 2. Treat NetworkManager as authoritative
The public repo and current runtime model already lean into NetworkManager for upstream handling, and that should be made explicit.

For this feature:
- NetworkManager is the active backend
- `wpa_supplicant` parsing may remain read-only import / discovery support
- `wpa_supplicant.conf` must not become an alternate source of truth

### 3. Keep the least-privilege model
Privileged operations must continue to flow through the agent/socket pattern or the established privileged helper model. No new direct-root code paths should be added in web or domain logic.

### 4. Add diagnostics as a first-class capability
Diagnostics should not be an afterthought or just log spam. They should be:
- requestable from the UI
- storable
- reviewable after reconnection to Recovery
- safe to collect from an appliance running as the service account

---

## Data Model Changes

The upstream config schema should be extended from “profiles with SSID/password/priority/security” to include role-aware and operational fields.

Recommended canonical shape:

```json
{
  "profiles": [
    {
      "ssid": "Lewis-iPhone",
      "password": "<hashed or prepared>",
      "priority": 100,
      "security": "wpa2",
      "role": "recovery",
      "enabled": true,
      "autoconnect": true
    },
    {
      "ssid": "FriendHouseWiFi",
      "password": "<hashed or prepared>",
      "priority": 80,
      "security": "wpa2",
      "role": "primary",
      "enabled": true,
      "autoconnect": true
    },
    {
      "ssid": "LewisHomeWiFi",
      "password": "<hashed or prepared>",
      "priority": 60,
      "security": "wpa2",
      "role": "secondary",
      "enabled": true,
      "autoconnect": true
    }
  ],
  "mode": {
    "prefer_recovery": false,
    "diagnostics_enabled": false
  }
}
```

### Notes
- `role` should be required for new data, but old profile JSON should be migrated safely.
- Recovery should be hard to remove accidentally.
- Priority still matters within or across roles, but role semantics must be explicit.

---

## Status Model

The upstream status view should answer:

- What networks are configured?
- What roles do they have?
- What network is currently active?
- What network was last selected by policy?
- Is internet reachability healthy?
- What were the last connection attempts and failures?
- Is the system currently in diagnostics / recovery preference mode?

This should be available to:
- CLI
- web UI
- diagnostics view

---

## Diagnostics Model

Diagnostics should support the following field workflow:

1. Operator enables diagnostics from the web UI while connected via Recovery
2. Operator disables Recovery hotspot and restarts / forces reconnect
3. Device attempts to connect to Primary or Secondary
4. Device captures upstream diagnostics during the attempt
5. Operator re-enables Recovery hotspot
6. Device reconnects to Recovery
7. Operator reads diagnostics in the web UI

### Diagnostics should capture at least:
- timestamped connection attempts
- candidate SSIDs considered
- selected network and why
- NetworkManager state before / after
- signal strength if available
- internet reachability check result
- stderr/stdout for relevant control commands (sanitised)
- last success / last failure reason per profile

### Diagnostics storage
Store under `/etc/mcbridge` in a structured form, e.g.:

```text
/etc/mcbridge/logs/upstream-diagnostics.json
```

or similar.

This should be:
- owned by the service account
- appendable or rotatable
- safe to read from the web UI

---

## CLI / UI Behaviour

### CLI additions
Recommended additions:

- `mcbridge upstream status`
- `mcbridge upstream update ...`
- `mcbridge upstream apply`
- `mcbridge upstream reconnect`
- `mcbridge upstream diagnostics enable`
- `mcbridge upstream diagnostics disable`
- `mcbridge upstream diagnostics show`

### UI additions
The upstream section of the web UI should support:
- role selection (Recovery / Primary / Secondary)
- enable/disable per profile
- add/update/delete profile
- save + apply
- force reconnect
- prefer Recovery toggle
- diagnostics enable/disable
- diagnostics view

---

## Init / Provisioning Enhancements

`mcbridge init` should be extended to seed role-aware upstream networks during first-time setup.

### Target init model
Example intended flow:

```bash
sudo mcbridge init \
  --ssid Minecraft \
  --password mypwd123 \
  --octet 168 \
  --channel 6 \
  --redirect play.enchanted.gg \
  --target brillbeast.asuscomm.com \
  --recovery-ssid Lewis-iPhone \
  --recovery-password <pwd> \
  --primary-ssid FriendHouseWiFi \
  --primary-password <pwd> \
  --secondary-ssid LewisHomeWiFi \
  --secondary-password <pwd>
```

### Behaviour
- Recovery is saved as role `recovery`
- Primary is saved as role `primary`
- Secondary is saved as role `secondary`
- The system is immediately usable in the field
- The operator can still add/change networks later

This is the preferred commissioning flow.

---

## Implementation Strategy

### Principle
Deliver in small, value-bearing increments.
Do not attempt a large redesign in one pass.

### Recommended sequence

#### Phase 1 — Schema and role support
- Extend upstream profile schema with `role`, `enabled`, `autoconnect`
- Implement migration for old profile JSON
- Add role-aware validation
- Make Recovery non-removable without force

#### Phase 2 — Upstream apply path
- Implement `apply_upstream()` using NetworkManager only
- Ensure persisted config actually becomes live system state
- Bring the preferred connection up
- Return structured results

#### Phase 3 — Agent integration
- Add upstream handlers to the agent allowlist/dispatch
- Ensure upstream apply/status/reconnect go through the agent
- Preserve least-privilege model

#### Phase 4 — UI save/apply
- Wire the upstream form so Save actually persists + applies
- Show active upstream and role-aware state
- Add reconnect action

#### Phase 5 — Diagnostics
- Add diagnostics mode flag
- Capture and persist upstream attempt data
- Add diagnostics view in the web UI

#### Phase 6 — Recovery workflow
- Add “prefer Recovery” / “enter recovery mode”
- Make recovery reconnect deterministic
- Add logic so recovery can be used as a field rescue path

#### Phase 7 — Init enhancements
- Extend `mcbridge init` for role-aware upstream seeding
- Document first-time setup patterns

#### Phase 8 — Docs / cleanup / tests
- Clean README issues (including unresolved merge markers currently visible in the public repo) citeturn532027view0
- Update docs for new upstream model
- Add tests around schema, apply, selection, and diagnostics

---

## Backlog Breakdown

### Epic A — Upstream Role Model
1. Add `role` field to upstream profile schema
2. Add `enabled` and `autoconnect`
3. Add schema migration for existing files
4. Add validation rules:
   - exactly zero or one recovery profile? decide and enforce
   - role values constrained
   - priority positive integer
5. Add force-protected removal for Recovery profile

### Epic B — Upstream Apply
1. Implement `apply_upstream()` in `upstream.py`
2. Create/update NetworkManager connections from persisted profiles
3. Set autoconnect and priority correctly
4. Bring selected connection up
5. Return structured apply result
6. Add unit tests for apply planning and result handling

### Epic C — Agent Support
1. Add upstream status/apply/reconnect handlers to agent
2. Ensure all `nmcli` calls go through agent path
3. Add tests for upstream agent dispatch
4. Preserve privilege boundaries

### Epic D — UI / API Integration
1. Wire upstream Save to persist + apply
2. Add role selector to upstream UI
3. Add “force reconnect” control
4. Show current upstream health and active role
5. Return errors clearly to operator

### Epic E — Diagnostics
1. Add diagnostics-enabled flag
2. Capture attempt logs and health checks
3. Persist diagnostics under `/etc/mcbridge/logs`
4. Add diagnostics API endpoint / web panel
5. Add retention/rotation behaviour

### Epic F — Recovery Workflow
1. Add “prefer Recovery” mode
2. Add reconnect-to-Recovery control
3. Add boot/reconnect selection logic using roles
4. Ensure Recovery wins only when intended
5. Add tests for selection logic

### Epic G — Init / Commissioning
1. Extend `mcbridge init` arguments to support role-aware upstream networks
2. Seed Recovery / Primary / Secondary during init
3. Add validation for partial combinations
4. Update install docs

### Epic H — Documentation / Cleanup
1. Resolve README merge conflict markers in public repo citeturn532027view0
2. Document upstream roles
3. Document field recovery workflow
4. Document diagnostics workflow
5. Update examples and screenshots if applicable

---

## Risks and Guardrails

### 1. Do not support multiple active backends
Do not try to actively manage both NetworkManager and `wpa_supplicant.conf`. Use one active backend only.

### 2. Do not let Recovery always override normal operation
Recovery must be a controlled fallback or recovery-preferred mode, not a permanently dominant SSID.

### 3. Do not bypass the privilege model
Upstream must not become a special case that skips the agent or helper pattern.

### 4. Do not overcomplicate with background automation too early
A simple reconnect/apply path plus explicit recovery mode is more valuable than an over-engineered watchdog in the first pass.

---

## Suggested Acceptance Criteria

The change is successful when all of the following are true:

1. A device can be commissioned with:
   - Recovery hotspot
   - Primary destination network
   - Secondary support/test network

2. Saving upstream networks from the web UI:
   - persists config
   - applies it to NetworkManager
   - updates actual active system state

3. The operator can:
   - force reconnect
   - enable diagnostics
   - reconnect using Recovery after a failed destination-site attempt

4. Diagnostics can be reviewed from the web UI after recovery

5. The least-privilege model remains intact

---

## Suggested Definition of Done

This feature area is done when:

- upstream Wi-Fi has parity with AP/DNS in persistence + apply behaviour
- Recovery / Primary / Secondary roles are implemented and visible
- field installation and recovery are practical without SSH
- diagnostics support the phone-hotspot recovery workflow
- docs and tests are updated accordingly

---

End of plan.
