// The init script of the browser collector (05-REQ-20, 05-REQ-22): it only listens to
// securitypolicyviolation and reports through the binding; it changes no DOM, prototype or
// application global (P-04). Must stay under 2 KB.

/** Source of the init script for the binding `binding`. */
export function cspListenerScript(binding: string): string {
  return `(()=>{try{if(typeof document==='undefined')return;var b=${JSON.stringify(binding)};document.addEventListener('securitypolicyviolation',function(e){try{var f=window[b];if(typeof f==='function')f({directive:String(e.effectiveDirective||e.violatedDirective||''),blocked:String(e.blockedURI||''),disposition:String(e.disposition||''),documentURI:String(e.documentURI||'')});}catch(_){}},true);}catch(_){}})();`;
}

/** Reads Web Storage of the page (05-REQ-23); runs in the page. */
export function readStorage(): {
  origin: string;
  local: [string, string][];
  session: [string, string][];
} {
  const read = (storage: Storage): [string, string][] => {
    const entries: [string, string][] = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key !== null) entries.push([key, storage.getItem(key) ?? '']);
    }
    return entries;
  };
  let local: [string, string][] = [];
  let session: [string, string][] = [];
  try {
    local = read(window.localStorage);
  } catch {
    // storage blocked (sandbox, opaque origin)
  }
  try {
    session = read(window.sessionStorage);
  } catch {
    // storage blocked
  }
  return { origin: window.location.origin, local, session };
}
