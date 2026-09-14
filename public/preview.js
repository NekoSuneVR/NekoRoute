import { esc, countryLabel, countryName, regions, createNodePager } from '/common.js?v=0500-20260914T1510';

const $ = s => document.querySelector(s);
const value = (s, fallback = '') => $(s)?.value ?? fallback;
const setText = (s, text) => { const el=$(s); if(el) el.textContent=text; };
const setHtml = (s, html) => { const el=$(s); if(el) el.innerHTML=html; };
let stats = null;
let session = null;
let history = [];
let historyIndex = -1;
let frameWatchdog = null;

function fillFilters() {
  setHtml('#regionSelect','<option value="">All regions</option>'+regions.map(r=>`<option>${esc(r)}</option>`).join(''));
  const countries=Object.entries(stats?.byCountry||{}).sort((a,b)=>countryName(a[0]).localeCompare(countryName(b[0])));
  setHtml('#countrySelect','<option value="">All countries</option>'+countries.map(([c,n])=>`<option value="${esc(c)}">${esc(countryLabel(c))} · ${n}</option>`).join(''));
}

const nodePager=createNodePager({
  select:$('#nodeSelect'),previous:$('#nodePrev'),next:$('#nodeNext'),label:$('#nodePage'),pageSize:50,
  getFilters:()=>({region:value('#regionSelect'),country:value('#countrySelect'),protocol:value('#protocolSelect')})
});
const loadNodes=(reset=true)=>nodePager.load({reset});

function updateHistoryButtons(){const back=$('#backBtn'),forward=$('#forwardBtn'),reload=$('#reloadBtn');if(back)back.disabled=historyIndex<=0;if(forward)forward.disabled=historyIndex<0||historyIndex>=history.length-1;if(reload)reload.disabled=!session||historyIndex<0;}
function frameUrl(url){return `/api/preview/${encodeURIComponent(session.sessionId)}?url=${encodeURIComponent(url)}`;}
function navigate(url,{push=true}={}){
  if(!session)return;
  const input=$('#urlInput');
  if(input)input.value=url;
  if(push){history=history.slice(0,historyIndex+1);history.push(url);historyIndex=history.length-1;}
  setText('#frameStatus','Loading through proxy…');
  const frame=$('#previewFrame');
  if(frame){
    // srcdoc overrides src in browsers. Remove the placeholder before the first real navigation.
    frame.removeAttribute('srcdoc');
    frame.src=frameUrl(url);
  }
  if(frameWatchdog)clearTimeout(frameWatchdog);
  frameWatchdog=setTimeout(()=>{
    setText('#frameStatus','Proxy is taking too long — try another node or use Auto / best healthy node.');
  },15000);
  updateHistoryButtons();
}

async function createSession(){
  const body={url:value('#urlInput'),region:value('#regionSelect')||undefined,country:value('#countrySelect')||undefined,protocol:value('#protocolSelect')||undefined,nodeRef:value('#nodeSelect')||undefined};
  const res=await fetch('/api/preview-session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const data=await res.json();if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`);
  session=data;history=[];historyIndex=-1;const n=data.node||{};
  setHtml('#routeInfo',`${esc(countryLabel(n.country))} · ${esc(n.region)} · <span class="font-mono">${esc(n.protocol)}</span> · ${esc(n.city||'Unknown')} · ${n.latencyMs??'—'} ms${Number(n.latencyMs||0)>10000?' · <span class="text-amber-300">very slow node</span>':''}`);
  navigate(data.url,{push:true});
}

for(const id of ['regionSelect','countrySelect','protocolSelect'])$('#'+id)?.addEventListener('change',()=>loadNodes(true));
$('#goBtn')?.addEventListener('click',async()=>{const btn=$('#goBtn');if(btn){btn.disabled=true;btn.textContent='Opening…';}try{await createSession();}catch(error){setText('#routeInfo',error.message);setText('#frameStatus','Preview failed');}finally{if(btn){btn.disabled=false;btn.textContent='Open';}}});
$('#urlInput')?.addEventListener('keydown',event=>{if(event.key==='Enter')$('#goBtn')?.click();});

$('#realFirefoxBtn')?.addEventListener('click',()=>{const q=new URLSearchParams({url:value('#urlInput')});const region=value('#regionSelect'),country=value('#countrySelect'),protocol=value('#protocolSelect');if(region)q.set('region',region);if(country)q.set('country',country);if(protocol)q.set('protocol',protocol);location.href='/browser?'+q.toString();});
$('#backBtn')?.addEventListener('click',()=>{if(historyIndex>0){historyIndex--;navigate(history[historyIndex],{push:false});}});
$('#forwardBtn')?.addEventListener('click',()=>{if(historyIndex<history.length-1){historyIndex++;navigate(history[historyIndex],{push:false});}});
$('#reloadBtn')?.addEventListener('click',()=>{if(historyIndex>=0)navigate(history[historyIndex],{push:false});});
$('#previewFrame')?.addEventListener('load',()=>{if(frameWatchdog){clearTimeout(frameWatchdog);frameWatchdog=null;}setText('#frameStatus',session?`Proxied preview active · session expires ${new Date(session.expiresAt).toLocaleTimeString()}`:'Proxy preview');});
window.addEventListener('message',event=>{const frame=$('#previewFrame');if(!frame||event.source!==frame.contentWindow)return;if(event.data?.type==='nekoroute-preview-nav'&&typeof event.data.url==='string')navigate(event.data.url,{push:true});});

async function init(){const statsRes=await fetch('/api/stats');stats=await statsRes.json();fillFilters();await loadNodes(true);updateHistoryButtons();}
init().catch(error=>setText('#routeInfo',error.message));
