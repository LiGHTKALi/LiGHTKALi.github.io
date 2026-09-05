(function() {
  if (window.location.protocol === 'file:') {
    document.documentElement.innerHTML = '<h1 style="color:#c00;font-family:sans-serif;text-align:center;margin-top:2em;">Kali Light does not support file:// protocol</h1><p style="font-family:sans-serif;text-align:center;">Please serve this application over HTTP/HTTPS using a web server (e.g., "python -m http.server").</p>';
    window.stop();
  }
})();
(function(){
  if(window.top!==window.self){
    document.documentElement.innerHTML='<h1 style="font-family:sans-serif;text-align:center;margin-top:3em;">LIGHT KALI cannot run inside a frame.</h1>';
    try{window.top.location=window.location.href;}catch(e){}
  }
})();
['dragover','drop'].forEach(type=>document.addEventListener(type,e=>e.preventDefault()));
document.addEventListener('click',e=>{
  const a=e.target.closest('a[target="_blank"]');
  if(a){
    const rel=(a.getAttribute('rel')||'').split(/\s+/);
    if(!rel.includes('noopener'))rel.push('noopener');
    if(!rel.includes('noreferrer'))rel.push('noreferrer');
    a.setAttribute('rel',rel.join(' ').trim());
  }
},true);