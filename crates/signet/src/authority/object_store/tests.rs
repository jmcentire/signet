use super::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier, Mutex},
    thread,
};
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Inner>>);
#[derive(Default)]
struct Inner {
    objects: BTreeMap<String, Object>,
    fail_head: bool,
    lose_head_response: bool,
    puts: u64,
}
impl Store for Memory {
    fn get(&self, key: &str) -> Result<Option<Object>> {
        Ok(self.0.lock().unwrap().objects.get(key).cloned())
    }
    fn put(&self, key: &str, bytes: &[u8], condition: &Condition) -> Result<()> {
        let mut m = self.0.lock().unwrap();
        if key.ends_with("head.json") && m.fail_head {
            return Err(Error::Unavailable);
        }
        let old = m.objects.get(key);
        if match condition {
            Condition::Absent => old.is_some(),
            Condition::Matches(etag) => old.is_none_or(|o| &o.etag != etag),
        } {
            return Err(Error::Conflict);
        }
        m.puts += 1;
        let etag = format!("\"opaque-{}\"", m.puts);
        m.objects.insert(
            key.into(),
            Object {
                bytes: bytes.to_vec(),
                etag,
            },
        );
        if key.ends_with("head.json") && m.lose_head_response {
            m.lose_head_response = false;
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
fn store(m: Memory) -> Versioned<Memory> {
    Versioned::new(m, "a".repeat(64)).unwrap()
}
fn setup() -> (Memory, Versioned<Memory>) {
    let m = Memory::default();
    let s = store(m.clone());
    let c=s.initialize(&json!({"policy_revision":1,"grants":{"one":{"consumed":false}},"executions":{},"rules":{}})).unwrap();
    s.commit(&c).unwrap();
    (m, s)
}
#[test]
fn concurrent_consumption_commits_exactly_one_reservation_and_loser_never_executes() {
    let (m, _) = setup();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|worker| {
            let s = store(m.clone());
            let barrier = barrier.clone();
            thread::spawn(move || {
                let current = s.load::<Value>().unwrap();
                assert_eq!(current.state["grants"]["one"]["consumed"], false);
                let mut next = current.state.clone();
                next["grants"]["one"]["consumed"] = json!(true);
                next["executions"]["quote-one"] =
                    json!({"state":"reserved","worker":worker,"idempotency_key":"quote-one"});
                let candidate = s.prepare(&current, &next).unwrap();
                barrier.wait();
                match s.commit(&candidate) {
                    Ok(CommitOutcome::CommittedNow) => 1,
                    Ok(CommitOutcome::Recovered) => 0,
                    Err(Error::Conflict) => 0,
                    other => panic!("unexpected: {other:?}"),
                }
            })
        })
        .collect();
    let executions: u32 = workers.into_iter().map(|w| w.join().unwrap()).sum();
    assert_eq!(executions, 1);
    let committed = store(m).load::<Value>().unwrap();
    assert_eq!(committed.state["grants"]["one"]["consumed"], true);
    assert_eq!(committed.state["executions"].as_object().unwrap().len(), 1);
}
#[test]
fn canonical_content_hash_deduplicates_order_and_rejects_floats() {
    let m = Memory::default();
    let s = store(m.clone());
    let one = s.initialize(&json!({"z":1,"a":{"y":2,"b":"é"}})).unwrap();
    let two = s
        .initialize(&serde_json::from_str::<Value>(r#"{"a":{"b":"é","y":2},"z":1}"#).unwrap())
        .unwrap();
    assert_eq!(one.version(), two.version());
    s.commit(&one).unwrap();
    s.commit(&two).unwrap();
    assert_eq!(m.0.lock().unwrap().objects.len(), 2);
    assert!(s.initialize(&json!({"float":1.5})).is_err());
}
#[test]
fn orphan_snapshot_never_becomes_authoritative_and_retry_recovers_lost_response() {
    let (m, s) = setup();
    let base = s.load::<Value>().unwrap();
    let candidate = s.prepare(&base, &json!({"updated":true})).unwrap();
    m.0.lock().unwrap().fail_head = true;
    assert_eq!(s.commit(&candidate), Err(Error::Unavailable));
    assert_eq!(s.recover(&candidate).unwrap(), Recovery::NotCommitted);
    assert_eq!(s.load::<Value>().unwrap().revision(), base.revision());
    m.0.lock().unwrap().fail_head = false;
    m.0.lock().unwrap().lose_head_response = true;
    assert_eq!(s.commit(&candidate), Err(Error::Unavailable));
    // A later writer can advance head before the first caller recovers.
    let next = s.load::<Value>().unwrap();
    let later = s.prepare(&next, &json!({"later":true})).unwrap();
    s.commit(&later).unwrap();
    assert_eq!(s.recover(&candidate).unwrap(), Recovery::Committed);
    s.commit(&candidate).unwrap();
    assert_eq!(s.load::<Value>().unwrap().version(), later.version());
}
#[test]
fn historical_read_cannot_reset_revision_or_revive_spent_grants() {
    let (_, s) = setup();
    let old = s.load::<Value>().unwrap();
    let mut spent = old.state.clone();
    spent["grants"]["one"]["consumed"] = json!(true);
    spent["policy_revision"] = json!(2);
    let c = s.prepare(&old, &spent).unwrap();
    s.commit(&c).unwrap();
    let historical: Value = s.read_version(old.version()).unwrap();
    assert_eq!(historical["grants"]["one"]["consumed"], false);
    let stale = s.prepare(&old, &old.state).unwrap();
    assert_eq!(s.commit(&stale), Err(Error::Conflict));
    // Restore POLICY content only, after owner approval against the current revision.
    let current = s.load::<Value>().unwrap();
    let mut restored = current.state.clone();
    restored["rules"] = historical["rules"].clone();
    restored["policy_revision"] = json!(3);
    let restore = s.prepare(&current, &restored).unwrap();
    s.commit(&restore).unwrap();
    let final_state = s.load::<Value>().unwrap();
    assert_eq!(final_state.state["grants"]["one"]["consumed"], true);
    assert_eq!(final_state.revision(), 2);
    assert_ne!(final_state.version(), old.version());
}
#[test]
fn immutable_bytes_hash_and_user_scope_are_checked() {
    let (m, s) = setup();
    let base = s.load::<Value>().unwrap();
    let candidate = s.prepare(&base, &json!({"x":1})).unwrap();
    m.put(
        &s.version_key(candidate.version()),
        b"tampered",
        &Condition::Absent,
    )
    .unwrap();
    assert_eq!(s.commit(&candidate), Err(Error::Integrity));
    let other = Versioned::new(m.clone(), "b".repeat(64)).unwrap();
    assert_eq!(other.commit(&candidate), Err(Error::Integrity));
    m.0.lock()
        .unwrap()
        .objects
        .get_mut(&s.version_key(base.version()))
        .unwrap()
        .bytes
        .push(b' ');
    assert!(matches!(s.load::<Value>(), Err(Error::Integrity)));
}
#[test]
fn retention_requires_age_and_newer_count_and_preserves_active_pins_and_references() {
    use retention::*;
    use std::collections::BTreeSet;
    let versions: Vec<_> = (0..5)
        .map(|i| Version {
            hash: i.to_string(),
            written_at: i,
        })
        .collect();
    let pins = BTreeSet::from(["1".into()]);
    assert_eq!(eligible(&versions, 4, 2, "4", &pins), vec!["0", "2"]);
    assert!(eligible(&versions, 0, 0, "4", &pins).is_empty());
    assert!(eligible(&versions, 9, 5, "4", &pins).is_empty());
}
#[test]
fn r2_wire_preconditions_preserve_opaque_etag_and_fail_closed() {
    struct Wire;
    impl r2::Transport for Wire {
        fn send(&self, r: r2::Request) -> Result<r2::Response> {
            assert_eq!(r.headers["cache-control"], "no-store");
            match r.method {
                "GET" => Ok(r2::Response {
                    status: 200,
                    etag: Some("\"opaque\"".into()),
                    body: b"{}".to_vec(),
                }),
                "PUT" => {
                    assert_eq!(r.headers["if-match"], "\"opaque\"");
                    Ok(r2::Response {
                        status: 412,
                        etag: None,
                        body: vec![],
                    })
                }
                _ => panic!(),
            }
        }
    }
    let store = r2::R2(Wire);
    let object = store.get("synthetic").unwrap().unwrap();
    assert_eq!(
        store.put("synthetic", b"{}", &Condition::Matches(object.etag)),
        Err(Error::Conflict)
    );
}

#[test]
fn identical_candidates_recover_without_granting_a_second_dispatch() {
    let (_, s) = setup();
    let a = s.load::<Value>().unwrap();
    let b = s.load::<Value>().unwrap();
    let mut next = a.state.clone();
    next["grants"]["one"]["consumed"] = json!(true);
    next["executions"]["one"] = json!({"state":"reserved","idempotency_key":"quote-one"});
    let first = s.prepare(&a, &next).unwrap();
    let second = s.prepare(&b, &next).unwrap();
    assert_eq!(first.version(), second.version());
    assert_eq!(s.commit(&first).unwrap(), CommitOutcome::CommittedNow);
    assert_eq!(s.commit(&second).unwrap(), CommitOutcome::Recovered);
}
#[test]
fn loaded_bases_are_bound_to_their_user_even_with_matching_object_etags() {
    let (_, a) = setup();
    let base = a.load::<Value>().unwrap();
    let b = Versioned::new(Memory::default(), "b".repeat(64)).unwrap();
    assert!(matches!(
        b.prepare(&base, &json!({"wrong_user":true})),
        Err(Error::Integrity)
    ));
}
