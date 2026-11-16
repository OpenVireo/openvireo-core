//! Runs `vectors/merge-fixtures/*.json` (results recorded from the desktop
//! `SyncEngine::mergeDatabases()`) through the port, as the SDK's `merge-fixtures.test.ts` does:
//! conflicts computed before merging, then the merged projection, with both sides' entries and groups
//! equal.

mod common;

use std::collections::BTreeMap;

use common::{build, normalize, project};
use ov_merge::{conflicting_fields, merge, merge_in_place};
use ov_testkit::{merge_fixtures, utc_seconds};

#[test]
fn all_merge_fixtures_pass() {
    let fixtures = merge_fixtures();
    assert_eq!(fixtures.len(), 14, "expected the 14 recorded fixtures");
    let mut failures = Vec::new();
    for (name, fx) in &fixtures {
        let mut local = build(&fx.local);
        let mut remote = build(&fx.remote);
        let base = fx.base.as_ref().map(build);
        let now = utc_seconds(&fx.now);

        // Conflicts are computed before merging, like SyncEngine does
        let mut conflicts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        if let Some(base) = &base {
            for e in &local.root.entries {
                let r = remote.root.entries.iter().find(|x| x.uuid == e.uuid).map(|x| (x, &remote));
                let b = base.root.entries.iter().find(|x| x.uuid == e.uuid).map(|x| (x, base));
                let c = conflicting_fields(Some((e, &local)), r, b);
                if !c.is_empty() {
                    conflicts.insert(e.uuid.hyphenated().to_string(), c);
                }
            }
        }
        if conflicts != fx.expected.conflicts {
            failures.push(format!("{name}: conflicts {conflicts:?}, want {:?}", fx.expected.conflicts));
        }

        let (merged, _) = merge(base.as_ref(), &local, &remote, now);
        let report = merge_in_place(&mut local, &mut remote, base.as_ref(), now);
        assert_eq!(merged, local, "{name}: merge() returns merge_in_place's local copy");
        let reported: BTreeMap<String, Vec<String>> =
            report.conflicts.iter().map(|c| (c.uuid.hyphenated().to_string(), c.fields.clone())).collect();
        if reported != fx.expected.conflicts {
            failures.push(format!("{name}: report conflicts {reported:?}, want {:?}", fx.expected.conflicts));
        }

        let got = project(&local);
        // Like TestMergeFixtures.cpp: both sides' entries and groups end up equal (deleted objects
        // are local's)
        let theirs = project(&remote);
        if theirs.entries != got.entries || theirs.groups != got.groups {
            failures.push(format!(
                "{name}: remote differs from local\n local {:#?} {:#?}\nremote {:#?} {:#?}",
                got.entries, got.groups, theirs.entries, theirs.groups
            ));
        }
        let want = normalize(&fx.expected.result);
        if got != want {
            failures.push(format!("{name}: result\n got {got:#?}\nwant {want:#?}"));
        }
        println!("{name}: ok={}", failures.iter().all(|f| !f.starts_with(name.as_str())));
    }
    assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n\n"));
}
