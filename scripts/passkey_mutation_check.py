#!/usr/bin/env python3
"""Switch off each security check in the remote-passkey crates and confirm a
test fails.

A passing test suite shows the checks work when present. It does not show the
tests would notice if a check were removed. This script removes each check in
turn, in a temporary copy of the workspace, and runs the tests of the crate the
check lives in. A mutation that no test catches is reported as SURVIVED.

Covers signet-passkey (the protocol), signet-passkey-relay and
signet-passkey-desktop (the computer side).

The working tree is never modified. Run from anywhere:

    python3 -B scripts/passkey_mutation_check.py

Exit status is 0 when every mutation behaves as recorded below, 1 otherwise.
A pattern that no longer matches the source is an error, so the list cannot
silently stop testing something after a refactor or a reformat.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = Path("crates")
DEFAULT_CRATE = "signet-passkey"

# (what is switched off, file, text to find, replacement, test expected to fail)
# A bare file name is in signet-passkey/src; otherwise the path starts with the
# crate's folder. An expected test of None marks a known survivor, with the
# reason alongside.
MUTATIONS = [
    ("passkey signs only for its own site", "authenticator.rs",
     ".filter(|c| c.rp_id == request.rp_id)", ".filter(|_| true)",
     "a_passkey_never_signs_for_a_site_it_was_not_created_for"),
    ("request replay", "authenticator.rs",
     "return Err(PasskeyError::Replay);", "let _ = ();",
     "the_relay_cannot_replay_a_request"),
    ("envelope signature", "seal.rs",
     "sender.verify(\n        &signing_bytes(expected, &me, &payload),\n        &unb64(&signed.sig)?,\n    )?;", "",
     "claiming_the_paired_machine_s_identity_is_not_enough"),
    ("response names the exact request", "requester.rs",
     "p.pairing_id == pairing.id && p.digest == response.request_digest", "p.pairing_id == pairing.id",
     "an_answer_to_a_different_question_is_rejected"),
    ("request expiry", "authenticator.rs",
     "|| request.expires_at <= now\n", "\n",
     "a_late_or_long_lived_request_is_dropped"),
    ("request maximum lifetime", "authenticator.rs",
     "|| request.expires_at - request.created_at > MAX_REQUEST_TTL_SECS", "",
     "a_late_or_long_lived_request_is_dropped"),
    ("future-dated request", "authenticator.rs",
     "if request.created_at > now + CLOCK_SKEW_SECS\n            || ", "if ",
     "a_late_or_long_lived_request_is_dropped"),
    ("phone repeats the site-binding check", "authenticator.rs",
     "if bound.is_err() {", "if false {",
     "a_phishing_page_cannot_ask_for_another_site_s_passkey"),
    ("revoked pairing", "authenticator.rs",
     ".find(|p| p.id == envelope.pairing_id && !p.revoked && p.peer_role == Role::Requester)",
     ".find(|p| p.id == envelope.pairing_id && p.peer_role == Role::Requester)",
     "a_revoked_machine_gets_no_answer"),
    ("required user verification at sign-in", "authenticator.rs",
     '.ok_or(PasskeyError::Malformed("approved account"))?;\n                if uv_required && !user_verified {',
     '.ok_or(PasskeyError::Malformed("approved account"))?;\n                if false {',
     "approval_without_verification_does_not_satisfy_a_site_that_requires_it"),
    ("required user verification when creating", "authenticator.rs",
     "                    };\n                if uv_required && !user_verified {",
     "                    };\n                if false {",
     "approval_without_verification_does_not_create_a_passkey_for_a_site_that_requires_it"),
    ("verified flag only when verified", "authenticator.rs",
     "                if user_verified {\n                    flags |= FLAG_UV;\n                }\n                let auth_data = authenticator_data(\n",
     "                flags |= FLAG_UV;\n                let auth_data = authenticator_data(\n",
     "the_site_rejects_a_signature_the_owner_did_not_verify"),
    ("site's allow list", "authenticator.rs",
     "allow_credentials.is_empty() || allow_credentials.contains(&c.credential_id)", "true",
     "the_owner_chooses_between_accounts_and_sees_the_newest_passkey_for_each"),
    ("site's exclusion list", "authenticator.rs",
     "c.rp_id == request.rp_id && exclude_credentials.contains(&c.credential_id)", "false",
     "a_site_s_exclusion_list_and_algorithms_are_honored"),
    ("identifier belongs to the origin", "rp.rs",
     "if host != rp_id && !is_parent {", "if false {",
     "other_sites_are_refused"),
    ("identifier is not a public suffix", "rp.rs",
     "if psl::domain_str(rp_id).is_none() {", "if false {",
     "other_sites_are_refused"),
    ("origin is secure", "rp.rs",
     '_ => return Err(PasskeyError::SiteBinding("origin is not secure")),', "_ => {}",
     "insecure_or_malformed_origins_are_refused"),
    ("pairing reply made from the ticket", "pairing.rs",
     "if !bool::from(expected.ct_eq(&supplied)) {", "if false {",
     "pairing_needs_the_ticket"),
    ("pairing reply signed by the key it presents", "pairing.rs",
     '.map_err(|_| PasskeyError::Pairing("reply signature"))?;', ".ok();",
     "pairing_needs_the_ticket"),
    ("late answer", "requester.rs",
     "if now > pending.expires_at + CLOCK_SKEW_SECS {", "if false {",
     "an_answer_that_arrives_too_late_is_discarded"),
    ("answer accepted once", "requester.rs",
     "            .remove(&response.request_id)\n",
     "            .get(&response.request_id).map(|p| Pending { pairing_id: p.pairing_id.clone(), "
     "digest: p.digest.clone(), expires_at: p.expires_at, ceremony: p.ceremony, "
     "rp_id: p.rp_id.clone(), allow_credentials: p.allow_credentials.clone(), "
     "client_data_json: p.client_data_json.clone() })\n",
     "a_response_is_accepted_once_and_only_for_its_own_request"),
    ("answer has the shape that was asked for", "requester.rs",
     '            _ => Err(PasskeyError::Malformed("response does not match request")),',
     "            _ => Ok(Completed::Denied),",
     "the_computer_checks_the_answer_against_what_it_asked"),
    ("answer is for the site that was asked about", "requester.rs",
     "if parsed.rp_id_hash != sha256(pending.rp_id.as_bytes()) {", "if false {",
     "the_computer_checks_the_answer_against_what_it_asked"),
    ("answer uses a passkey the site asked for", "requester.rs",
     "&& !pending.allow_credentials.contains(&credential_id)", "&& false",
     "the_computer_checks_the_answer_against_what_it_asked"),
    ("answer claims the owner was present", "requester.rs",
     "if parsed.flags & need != need {", "if false {",
     "the_computer_checks_the_answer_against_what_it_asked"),
    # Known survivor. The sender's fingerprint in the HPKE context is a second
    # barrier: a message from the wrong sender already fails the signature
    # check, which the "envelope signature" mutation above covers.
    ("sender fingerprint in the HPKE context", "seal.rs",
     "        sender.fingerprint().as_bytes(),\n        to.fingerprint().as_bytes(),\n    ])\n}\n\nfn aad",
     "        to.fingerprint().as_bytes(),\n    ])\n}\n\nfn aad",
     None),

    # Pairing and relay addressing (signet-passkey).
    ("relay address bound into the pairing reply", "pairing.rs",
     'relay.unwrap_or("").as_bytes(),', 'b"",',
     "both_devices_must_have_read_the_same_relay_address"),
    ("ticket names only an acceptable relay", "pairing.rs",
     "if crate::relay::normalize_relay_url(relay)? != *relay {", "if false {",
     "a_ticket_cannot_name_a_relay_reached_without_tls"),
    ("plain http only for a relay on this machine", "relay.rs",
     '"http" if is_loopback(&host) => {}', '"http" => {}',
     "relay_addresses_are_normalized_and_restricted"),
    ("relay request signature", "relay.rs",
     "if !accepted {", "if false {",
     "a_signed_request_verifies_only_as_sent"),
    ("relay request freshness", "relay.rs",
     "if (now - self.timestamp).abs() > AUTH_WINDOW_SECS {", "if false {",
     "a_signed_request_verifies_only_as_sent"),

    # The relay's own rules (signet-passkey-relay).
    ("only listed senders may leave messages", "signet-passkey-relay/src/lib.rs",
     "if !mailbox.peers.contains(&caller.fingerprint) {", "if false {",
     "only_listed_senders_can_leave_messages"),
    ("only the owner reads a mailbox", "signet-passkey-relay/src/lib.rs",
     "if caller.fingerprint != owner {", "if false {",
     "only_the_owner_reads_a_mailbox"),
    ("replayed relay request", "signet-passkey-relay/src/lib.rs",
     "if inner.nonces.contains_key(&key) {", "if false {",
     "unsigned_altered_stale_and_replayed_requests_are_refused"),
    ("one device's request rate", "signet-passkey-relay/src/lib.rs",
     "if rate.1 > self.config.requests_per_minute {", "if false {",
     "one_device_cannot_flood_the_relay"),
    ("mailbox bounds", "signet-passkey-relay/src/lib.rs",
     "if from_sender >= shared.config.max_per_sender\n        || mailbox.queue.len() >= shared.config.max_per_mailbox\n    {",
     "if false {",
     "messages_expire_and_sizes_and_counts_are_bounded"),
    ("message size bound", "signet-passkey-relay/src/lib.rs",
     "if body.len() > shared.config.max_message_bytes {", "if false {",
     "messages_expire_and_sizes_and_counts_are_bounded"),
    ("message expiry", "signet-passkey-relay/src/lib.rs",
     ".retain(|message| message.expires_at > now && peers.contains(&message.from));",
     ".retain(|message| peers.contains(&message.from));",
     "messages_expire_and_sizes_and_counts_are_bounded"),
    ("a removed sender's queued messages are dropped", "signet-passkey-relay/src/lib.rs",
     ".retain(|message| message.expires_at > now && peers.contains(&message.from));",
     ".retain(|message| message.expires_at > now);",
     "a_sender_taken_off_the_list_loses_its_queued_messages"),
    ("a pairing reply cannot be replaced", "signet-passkey-relay/src/lib.rs",
     "if inner.rendezvous.contains_key(&id) {", "if false {",
     "a_pairing_reply_is_left_once_and_collected_once"),
    ("slot and address shape", "signet-passkey-relay/src/lib.rs",
     "if !is_id(&recipient) || query.slot.as_deref().is_some_and(|slot| !is_id(slot)) {", "if false {",
     "slots_keep_answers_for_different_waiters_apart"),

    # The computer side (signet-passkey-desktop).
    ("sign-ins go to the phone only for listed sites", "signet-passkey-desktop/src/flow.rs",
     "} else if !state.sites.contains(&rp_id) {", "} else if false {",
     "calls_that_are_not_for_the_phone_stay_with_the_browser"),
    ("autofill sign-in stays with the browser", "signet-passkey-desktop/src/flow.rs",
     'if request.mediation.as_deref() == Some("conditional") {', "if false {",
     "a_passkey_is_created_and_used_through_the_relay"),
    ("a request for a security key stays with the browser", "signet-passkey-desktop/src/flow.rs",
     "if create.wants_security_key {", "if false {",
     "calls_that_are_not_for_the_phone_stay_with_the_browser"),
    ("new passkeys switched off", "signet-passkey-desktop/src/flow.rs",
     "if !state.new_passkeys {", "if false {",
     "calls_that_are_not_for_the_phone_stay_with_the_browser"),
    ("one page's request rate", "signet-passkey-desktop/src/flow.rs",
     "if count >= MAX_PER_MINUTE {", "if false {",
     "one_page_cannot_flood_the_phone"),
    ("pairing saved only with the code on the phone", "signet-passkey-desktop/src/pair.rs",
     "if typed != expected {", "if false {",
     "a_wrong_code_saves_nothing"),
    ("machine key file is private", "signet-passkey-desktop/src/store.rs",
     "options.mode(0o600);", "options.mode(0o644);",
     "the_machine_key_is_readable_by_its_owner_only"),
    ("the machine key is never replaced", "signet-passkey-desktop/src/store.rs",
     "if self.dir.join(KEY_FILE).exists() {", "if false {",
     "a_store_keeps_one_identity_and_refuses_to_replace_it"),
    ("only one extension may start the program", "signet-passkey-desktop/src/browser.rs",
     "if !is_extension_id(extension_id) {", "if false {",
     "malformed_ids_and_relative_paths_are_refused"),
]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="signet-passkey-mutation-") as scratch:
        copy = Path(scratch) / "signet"
        # Copied without modification times, so every file is newer than
        # anything in the shared build folder. Otherwise cargo can reuse an
        # artifact a previous run built from a mutated file.
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("target", ".git"),
                        copy_function=shutil.copy)
        env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target" / "mutation"))

        def locate(file: str) -> tuple[str, Path]:
            if "/" not in file:
                return DEFAULT_CRATE, copy / CRATES / DEFAULT_CRATE / "src" / file
            return file.split("/", 1)[0], copy / CRATES / file

        def failing_tests(crate: str) -> set[str] | None:
            command = ["cargo", "test", "--locked", "-p", crate]
            result = subprocess.run(command, cwd=copy, env=env, capture_output=True, text=True)
            output = result.stdout + result.stderr
            if "could not compile" in output:
                return None
            return {name.split("::")[-1] for name in re.findall(r"^test (\S+) \.\.\. FAILED", output, re.M)}

        for crate in sorted({locate(m[1])[0] for m in MUTATIONS}):
            if failing_tests(crate) != set():
                print(f"{crate} does not pass its tests unmodified; nothing to measure.", file=sys.stderr)
                return 1

        unexpected = 0
        for name, file, old, new, expected in MUTATIONS:
            crate, path = locate(file)
            original = path.read_text()
            if original.count(old) != 1:
                print(f"ERROR     {name}: pattern matches {original.count(old)} times in {file}")
                unexpected += 1
                continue
            path.write_text(original.replace(old, new))
            failed = failing_tests(crate)
            path.write_text(original)
            if failed is None:
                print(f"ERROR     {name}: mutated source does not compile")
                unexpected += 1
            elif expected is None:
                status = "SURVIVED (expected)" if not failed else "killed (now covered; update this list)"
                unexpected += bool(failed)
                print(f"{status}  {name}")
            elif expected in failed:
                print(f"killed    {name}")
            else:
                print(f"SURVIVED  {name}: expected {expected} to fail; failed: {sorted(failed) or 'none'}")
                unexpected += 1
        total = len(MUTATIONS)
        survivors = sum(1 for m in MUTATIONS if m[4] is None)
        print(f"{total} mutations, {total - survivors} expected to be caught, {unexpected} unexpected results")
        return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
