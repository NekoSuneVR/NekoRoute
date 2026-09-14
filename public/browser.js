import { esc, countryLabel, countryName, regions, createNodePager } from '/common.js?v=0504-20260914T1510';

const $=s=>document.querySelector(s);const value=(s,f='')=>$(s)?.value??f;let stats=null;let bridgeReady=false;
function fillFilters(){
  $('#regionSelect').innerHTML='<option value="">All regions</option>'+regions.map(r=>`<option>${esc(r)}</option>`).join('');
  const countries=Object.entries(stats?.byCountry||{}).sort((a,b)=>countryName(a[0]).localeCompare(countryName(b[0])));
  $('#countrySelect').innerHTML='<option value="">All countries</option>'+countries.map(([c,n])=>`<option value="${esc(c)}">${esc(countryLabel(c))} · ${n}</option>`).join('');
}
const nodePager=createNodePager({select:$('#nodeSelect'),previous:$('#nodePrev'),next:$('#nodeNext'),label:$('#nodePage'),pageSize:50,getFilters:()=>({region:value('#regionSelect'),country:value('#countrySelect'),protocol:value('#protocolSelect')})});
const loadNodes=(reset=true)=>nodePager.load({reset});
function setBridge(ok,text){bridgeReady=ok;$('#bridgeStatus').textContent=text;$('#bridgeStatus').className=`mt-1 font-black ${ok?'text-emerald-300':'text-amber-300'}`;$('#openFirefoxBtn').disabled=!ok;}
window.addEventListener('message',event=>{
  if(event.source!==window)return;
  if(event.data?.source==='nekoroute-firefox-bridge'&&event.data?.type==='NEKOROUTE_BRIDGE_READY'){
    setBridge(true,'Connected');$('#bridgeDetail').textContent='The Firefox Bridge is installed and allowed for this NekoRoute origin.';
  }
  if(event.data?.source==='nekoroute-firefox-bridge'&&event.data?.type==='NEKOROUTE_BRIDGE_RESULT'){
    const d=event.data;
    if(d.ok){$('#routeInfo').textContent=`Opened local Firefox tab · ${d.nodeLabel||'selected proxy'}`;}else{$('#routeInfo').textContent=d.error||'Firefox Bridge failed';}
  }
});
for(const id of ['regionSelect','countrySelect','protocolSelect'])$('#'+id)?.addEventListener('change',()=>loadNodes(true));
$('#openFirefoxBtn')?.addEventListener('click',async()=>{
  const btn=$('#openFirefoxBtn');btn.disabled=true;btn.textContent='Opening…';
  try{
    const body={url:value('#urlInput'),region:value('#regionSelect')||undefined,country:value('#countrySelect')||undefined,protocol:value('#protocolSelect')||undefined,nodeRef:value('#nodeSelect')||undefined};
    const res=await fetch('/api/v1/browser-ticket',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const data=await res.json();if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`);
    $('#routeInfo').innerHTML=`Ticket ready · ${esc(countryLabel(data.node?.country))} · ${esc(data.node?.protocol||'')} · ${data.node?.latencyMs??'—'} ms`;
    window.postMessage({source:'nekoroute-web',type:'NEKOROUTE_OPEN_FIREFOX',ticketUrl:new URL(data.ticketUrl,location.origin).toString()},location.origin);
  }catch(e){$('#routeInfo').textContent=e.message;}finally{btn.disabled=!bridgeReady;btn.textContent='Open in Firefox';}
});
$('#urlInput')?.addEventListener('keydown',e=>{if(e.key==='Enter'&&bridgeReady)$('#openFirefoxBtn')?.click();});
async function init(){stats=await(await fetch('/api/stats')).json();fillFilters();const params=new URLSearchParams(location.search);if(params.get('url'))$('#urlInput').value=params.get('url');for(const [id,key] of [['regionSelect','region'],['countrySelect','country'],['protocolSelect','protocol']]){const v=params.get(key);if(v&&$('#'+id))$('#'+id).value=v;}await loadNodes(true);setBridge(false,'Extension not detected');setTimeout(()=>window.postMessage({source:'nekoroute-web',type:'NEKOROUTE_BRIDGE_PING'},location.origin),100);}
init().catch(e=>{$('#routeInfo').textContent=e.message;});
