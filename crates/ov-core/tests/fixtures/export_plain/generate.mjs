// The web app's exportDatabaseSubset (openvireo-web src/context/KeePassContext.tsx @ ea7f557), run on the
// data set crates/ov-core/tests/contract_v18.rs builds, to record the exact bytes it writes.
import { writeFileSync } from 'node:fs';
const out = process.argv[2];
const groups = [
  { uuid: 'root', name: 'Home' },
  { uuid: 'work', name: 'Work' },
  { uuid: 'servers', name: 'Servers' },
];
const entries = [
  { groupUuid: 'root', title: 'Mail "personal"', username: 'me@example.com', passwordValue: 'p,w"1', url: 'https://mail.example.com/a/b', notes: 'line1\nline2' },
  { groupUuid: 'root', title: '(Untitled Entry)', username: '', passwordValue: 'x', url: '', notes: 'tab\there \u0001 ctl' },
  { groupUuid: 'work', title: 'VPN', username: 'ops', passwordValue: 'ü✓ 🔑', url: '', notes: '</script>   \\ end' },
  { groupUuid: 'servers', title: 'db', username: 'root', passwordValue: 's3cr3t\\', url: 'ssh://db', notes: '' },
];
const selectedGroupUuids = groups.map((g) => g.uuid);
const exportData = [];
const traverse = (group) => {
  if (selectedGroupUuids.includes(group.uuid)) {
    entries.filter((e) => e.groupUuid === group.uuid).forEach((e) => {
      exportData.push({ folder: group.name, title: e.title, username: e.username, passwordValue: e.passwordValue, url: e.url, notes: e.notes });
    });
  }
};
groups.forEach(traverse);
writeFileSync(`${out}/expected.json`, JSON.stringify(exportData, null, 2));
const headers = ['Folder', 'Title', 'Username', 'Password', 'URL', 'Notes'];
const escape = (val) => `"${(val || '').replace(/"/g, '""')}"`;
const rows = exportData.map((e) => [escape(e.folder), escape(e.title), escape(e.username), escape(e.passwordValue), escape(e.url), escape(e.notes)].join(','));
writeFileSync(`${out}/expected.csv`, [headers.join(','), ...rows].join('\n'));
