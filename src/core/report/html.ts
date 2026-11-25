// The HTML report (09, chapter 3): one self-contained file that works offline (P-05, NF-08). The
// run data is embedded as JSON and rendered by an inline script; nothing is loaded from outside.
import { ruleManifest } from '../manifest/rules.ts';
import type { BuiltInRule } from '../rules/index.ts';
import type { RunReport } from '../types/index.ts';

export interface HtmlRule {
  id: string;
  title: string;
  group: string;
  cwe: number[];
  owasp?: string;
  why: string;
  fix: string;
  falsePositives: string;
  enabled: boolean;
}

/** JSON inside <script>: no "</script>", no line separators that break the script. */
export function embedJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

const CSS = `:root{--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;--bg:#f6f7f9;--surface:#fff;--sunken:#f1f3f6;--line:#e4e7ec;--fg:#101828;--fg-2:#475467;--fg-3:#5d6979;--accent:#4f46e5;--accent-soft:#eef0ff;--ok:#067647;--ok-soft:#e6f6ee;--warn:#a14c05;--warn-soft:#fef4e4;--bad:#b42318;--bad-soft:#fef3f2;--mute:#5d6979;--mute-soft:#eef0f3;--r:8px;--sh:0 1px 2px rgb(16 24 40/5%)}
@media (prefers-color-scheme:dark){:root{--bg:#0b0d12;--surface:#12151c;--sunken:#0f1218;--line:#262b36;--fg:#eef1f6;--fg-2:#a9b0bf;--fg-3:#8e97a8;--accent:#8b93ff;--accent-soft:#1d2040;--ok:#47cd89;--ok-soft:#0f2a1d;--warn:#fdb022;--warn-soft:#2d2210;--bad:#f97066;--bad-soft:#2d1214;--mute:#8e97a8;--mute-soft:#1a1e27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 var(--sans)}
header,main{max-width:1200px;margin:0 auto;padding:16px}h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh);padding:12px 16px;margin-bottom:12px}
.meta{color:var(--fg-2);font-size:13px}.counters{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.counter{border-radius:var(--r);padding:6px 10px;background:var(--sunken)}.counter b{font-size:18px;margin-right:4px}
.outcome{display:inline-block;border-radius:999px;padding:2px 10px;font-weight:600}.ok{background:var(--ok-soft);color:var(--ok)}.bad{background:var(--bad-soft);color:var(--bad)}.warn{background:var(--warn-soft);color:var(--warn)}.mute{background:var(--mute-soft);color:var(--mute)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center}select,input{font:inherit;color:inherit;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:4px 8px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--fg-3);font-weight:600;font-size:12px}
tr.row{cursor:pointer}tr.row:hover{background:var(--sunken)}tr.group td{background:var(--sunken);font-weight:600}
.pill{border-radius:999px;padding:0 8px;font-size:12px;white-space:nowrap}.sev-critical,.sev-high{background:var(--bad-soft);color:var(--bad)}.sev-medium{background:var(--warn-soft);color:var(--warn)}.sev-low,.sev-info{background:var(--mute-soft);color:var(--mute)}
code,pre{font-family:var(--mono);font-size:12px}pre{background:var(--sunken);border-radius:6px;padding:8px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.detail{display:none}.detail.open{display:table-row}.detail td{background:var(--surface)}.first{font-weight:600}
.box{border-left:4px solid var(--warn);background:var(--warn-soft)}ul{margin:4px 0;padding-left:20px}button{font:inherit;border:1px solid var(--line);background:var(--surface);color:inherit;border-radius:6px;padding:2px 8px;cursor:pointer}`;

const SCRIPT = `(function(){
var D=JSON.parse(document.getElementById('pw-sec-data').textContent);var R=D.report;var RULES=D.rules;
var SEV=['critical','high','medium','low','info'];var CONF=['high','medium','low'];
function e(t){return String(t==null?'':t).replace(/[&<>"']/g,function(c){return'&#'+c.charCodeAt(0)+';'})}
function md(t){return e(t).replace(/\`([^\`]+)\`/g,'<code>$1</code>').replace(/\\*\\*([^*]+)\\*\\*/g,'<b>$1</b>').split('\\n').map(function(l){return/^- /.test(l)?'<li>'+l.slice(2)+'</li>':l===''?'<br>':'<div>'+l+'</div>'}).join('').replace(/(<li>.*?<\\/li>)+/g,'<ul>$&</ul>')}
function el(id){return document.getElementById(id)}
var o=R.outcome;var cls=o.code===0?'ok':o.code===4?'warn':'bad';
var cnt=function(c,b){return R.findings.filter(function(f){return f.classification===c&&(b===undefined||f.blocking===b)}).length};
el('head').innerHTML='<h1>Security scan <span class="outcome '+cls+'">'+e(o.name)+' · code '+o.code+'</span></h1><div class="meta">mode '+e(R.mode)+(R.env?' · env '+e(R.env):'')+' · passive only · scope '+e(R.scope.origins.join(', ')||'(none)')+' · playwright-security-scan '+e(R.pkgVersion)+' · Playwright '+e(R.playwrightVersion)+' · '+e(R.startedAt)+' → '+e(R.finishedAt)+'</div><div class="counters">'+[['new, blocking',cnt('new',true),'bad'],['new, non-blocking',cnt('new',false),'warn'],['accepted',cnt('accepted')+cnt('wontfix')+cnt('false-positive'),'mute'],['expired',cnt('expired'),'bad'],['resolved',R.resolved.length,'ok']].map(function(c){return'<span class="counter '+c[2]+'"><b>'+c[1]+'</b>'+c[0]+'</span>'}).join('')+'</div>';
var origins={};R.findings.forEach(function(f){origins[f.location.origin]=1});
function opts(id,vals){el(id).innerHTML='<option value="">all</option>'+vals.map(function(v){return'<option>'+e(v)+'</option>'}).join('')}
opts('f-class',['new','expired','accepted','wontfix','false-positive']);opts('f-sev',SEV);opts('f-conf',CONF);opts('f-group',Object.keys(RULES).map(function(k){return RULES[k].group}).filter(function(v,i,a){return a.indexOf(v)===i}).sort());opts('f-origin',Object.keys(origins).sort());
var rank={new:0,expired:1};function order(f){return f.blocking?0:f.classification==='expired'?1:f.classification==='new'?2:3}
function testName(t){return e(t.file)+':'+t.line+' › '+e(t.titlePath.join(' › '))}
function detail(f){var r=RULES[f.ruleId]||{};var entry={};entry[f.fingerprint]={ruleId:f.ruleId,subject:f.subject,severity:f.severity,status:'accepted',note:'',until:'',addedAt:new Date().toISOString().slice(0,10)};
return'<div><b>'+e(f.message)+'</b></div><div class="meta">'+e(f.severity)+'/'+e(f.confidence)+' · '+(r.cwe||[]).map(function(c){return'CWE-'+c+' (cwe.mitre.org/data/definitions/'+c+'.html)'}).join(', ')+(r.owasp?' · OWASP '+e(r.owasp):'')+' · sources: '+e(f.sources.join(', '))+' · '+f.occurrences+' occurrences</div>'
+(f.baseline?'<div class="meta">baseline: '+e(f.baseline.status)+(f.baseline.note?' — '+e(f.baseline.note):'')+(f.baseline.until?' · until '+e(f.baseline.until):'')+(f.baseline.expiresInDays!=null?' · expires in '+f.baseline.expiresInDays+' days':'')+'</div>':'')
+'<h3>Evidence</h3>'+(f.evidence.length?'<pre>'+f.evidence.map(function(v){return e(v.kind+(v.name?' '+v.name:'')+': '+v.snippet)}).join('\\n')+'</pre>':'<div class="meta">none</div>')
+'<h3>Tests</h3><ul><li class="first">'+testName(f.firstSeen)+(f.firstSeen.step?' › '+e(f.firstSeen.step):'')+' (first seen)</li>'+(f.tests.length>1?'<li>and '+(f.tests.length-1)+' more tests</li>':'')+'</ul>'
+'<h3>Why</h3>'+md(r.why||'')+'<h3>Fix</h3>'+md(r.fix||'')+'<h3>False positives</h3>'+md(r.falsePositives||'')
+'<h3>Accept</h3><div class="meta">Add to security-baseline.json, fill in "note" (and "until" or remove it), commit after review:</div><pre>'+e(JSON.stringify(entry,null,2))+'</pre>'}
function render(){var c=el('f-class').value,s=el('f-sev').value,cf=el('f-conf').value,g=el('f-group').value,or=el('f-origin').value,t=el('f-test').value.toLowerCase(),by=el('f-by').value;
var list=R.findings.filter(function(f){var r=RULES[f.ruleId]||{};return(!c||f.classification===c)&&(!s||f.severity===s)&&(!cf||f.confidence===cf)&&(!g||r.group===g)&&(!or||f.location.origin===or)&&(!t||(f.firstSeen.file+' '+f.firstSeen.titlePath.join(' ')).toLowerCase().indexOf(t)>=0)});
list.sort(function(a,b){return order(a)-order(b)||SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||(a.fingerprint<b.fingerprint?-1:1)});
var key=function(f){return by==='origin'?f.location.origin:by==='endpoint'?(f.location.endpointKey||f.subject):f.ruleId};var groups={};list.forEach(function(f){(groups[key(f)]=groups[key(f)]||[]).push(f)});
var h='';Object.keys(groups).sort(function(a,b){return order(groups[a][0])-order(groups[b][0])||(a<b?-1:1)}).forEach(function(k){h+='<tr class="group"><td colspan="7">'+e(k)+(by==='rule'&&RULES[k]?' — '+e(RULES[k].title):'')+' ('+groups[k].length+')</td></tr>';groups[k].forEach(function(f){var i=R.findings.indexOf(f);
h+='<tr class="row" data-i="'+i+'"><td><span class="pill sev-'+f.severity+'">'+f.severity+'</span></td><td>'+f.confidence+'</td><td>'+e(f.ruleId)+'</td><td>'+e(f.subject)+(f.discriminator?' <span class="meta">('+e(f.discriminator)+')</span>':'')+'</td><td>'+f.occurrences+'</td><td>'+f.tests.length+'</td><td><span class="outcome '+(f.blocking?'bad':f.classification==='new'?'warn':'mute')+'">'+e(f.classification)+(f.blocking?' · blocking':'')+'</span></td></tr><tr class="detail" id="d'+i+'"><td colspan="7">'+detail(f)+'</td></tr>'})});
el('rows').innerHTML=h||'<tr><td colspan="7" class="meta">No findings match the filters.</td></tr>';el('shown').textContent=list.length+' of '+R.findings.length}
['f-class','f-sev','f-conf','f-group','f-origin','f-test','f-by'].forEach(function(id){el(id).addEventListener('input',render)});
el('rows').addEventListener('click',function(ev){var tr=ev.target.closest('tr.row');if(tr)el('d'+tr.getAttribute('data-i')).classList.toggle('open')});
render();
var C=R.coverage;var noInput=Object.keys(RULES).filter(function(k){return RULES[k].enabled&&!C.rulesRun[k]});
el('coverage').innerHTML='<div>'+C.responses+' responses in scope ('+C.apiResponses+' from API tests), '+C.outOfScope+' out of scope, '+C.documents+' documents; bodies analysed '+C.bodiesAnalyzed+', skipped: '+(Object.keys(C.bodiesSkipped).map(function(k){return e(k)+' '+C.bodiesSkipped[k]}).join(', ')||'none')+'</div>'
+'<h3>Origins</h3><ul>'+Object.keys(C.origins).map(function(k){return'<li>'+e(k)+' — '+C.origins[k].responses+' responses, '+C.origins[k].documents+' documents</li>'}).join('')+'</ul>'
+'<h3>Endpoints ('+Object.keys(C.endpoints).length+')</h3><table><tr><th>endpoint</th><th>responses</th></tr>'+Object.keys(C.endpoints).map(function(k){return'<tr><td><code>'+e(k)+'</code></td><td>'+C.endpoints[k]+'</td></tr>'}).join('')+'</table>'
+'<h3>Tests without traffic in scope ('+R.testsWithoutTraffic.length+')</h3>'+(R.testsWithoutTraffic.length?'<div class="meta">A context created by hand and not passed to security.track() is not scanned.</div><ul>'+R.testsWithoutTraffic.map(function(t){return'<li>'+testName(t)+'</li>'}).join('')+'</ul>':'<div class="meta">none</div>')
+'<h3>Rules that had nothing to check ('+noInput.length+')</h3><div class="meta">'+(noInput.map(e).join(', ')||'none')+'</div>'
+(R.resolved.length?'<h3>Resolved baseline entries ('+R.resolved.length+')</h3><ul>'+R.resolved.map(function(r){return'<li><code>'+e(r.fingerprint)+'</code></li>'}).join('')+'</ul><div class="meta">Run PW_SEC_MODE=baseline to remove them.</div>':'')
+(R.notCovered.length?'<h3>Baseline entries not covered by this run ('+R.notCovered.length+')</h3><ul>'+R.notCovered.map(function(r){return'<li><code>'+e(r.fingerprint)+'</code></li>'}).join('')+'</ul>':'');
el('diag').innerHTML=R.diagnostics.length?'<ul>'+R.diagnostics.map(function(d){return'<li><span class="outcome '+(d.level==='error'?'bad':d.level==='warn'?'warn':'mute')+'">'+e(d.level)+'</span> <code>'+e(d.code)+'</code> '+e(d.message)+'</li>'}).join('')+'</ul>':'<div class="meta">none</div>';
})();`;

/** The whole report page (09, chapter 3). */
export function renderHtml(
  report: RunReport,
  rules: readonly BuiltInRule[],
  enabled: ReadonlySet<string>,
): string {
  const used = new Set([...report.findings.map((f) => f.ruleId), ...enabled]);
  const docs: Record<string, HtmlRule> = {};
  for (const rule of rules) {
    if (!used.has(rule.id)) continue;
    const m = ruleManifest(rule.id);
    docs[rule.id] = {
      id: rule.id,
      title: rule.docs.title,
      group: m?.group ?? 'browser',
      cwe: m?.cwe ?? [],
      ...(m?.owasp === undefined ? {} : { owasp: m.owasp }),
      why: rule.docs.why,
      fix: rule.docs.fix,
      falsePositives: rule.docs.falsePositives,
      enabled: enabled.has(rule.id),
    };
  }
  const data = embedJson({ report, rules: docs });
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security scan · ${report.outcome.name}</title>
<style>${CSS}</style>
</head>
<body>
<header><div class="card" id="head"></div></header>
<main>
<noscript><div class="card">This report needs JavaScript; the same data is in report.json.</div></noscript>
<div class="card box"><b>What this scan does not cover.</b> It is passive: it only looks at the traffic of your tests. It does not send attacks (no injection or authorization tests), does not see endpoints your tests never call, WebSockets or Server-Sent Events, and does not judge business logic. It does not replace a penetration test. Active checks are planned for later versions.</div>
<h2>Findings <span class="meta" id="shown"></span></h2>
<div class="card filters">
<label>classification <select id="f-class"></select></label>
<label>severity <select id="f-sev"></select></label>
<label>confidence <select id="f-conf"></select></label>
<label>rule group <select id="f-group"></select></label>
<label>origin <select id="f-origin"></select></label>
<label>test <input id="f-test" placeholder="file or title"></label>
<label>group by <select id="f-by"><option value="rule">rule</option><option value="origin">origin</option><option value="endpoint">endpoint</option></select></label>
</div>
<div class="card"><table><thead><tr><th>severity</th><th>confidence</th><th>rule</th><th>subject</th><th>occurrences</th><th>tests</th><th>classification</th></tr></thead><tbody id="rows"></tbody></table></div>
<h2>Coverage</h2>
<div class="card" id="coverage"></div>
<h2>Diagnostics</h2>
<div class="card" id="diag"></div>
</main>
<script type="application/json" id="pw-sec-data">${data}</script>
<script>${SCRIPT}</script>
</body>
</html>
`;
}
