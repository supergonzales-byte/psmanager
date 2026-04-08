const fs   = require('fs')
const path = require('path')

const COL_DEFS = [
    { key: 'Hostname', label: 'Hostname',   mandatory: true  },
    { key: 'IP',       label: 'IP',         mandatory: false },
    { key: 'MAC',      label: 'MAC',        mandatory: false },
    { key: 'Marque',   label: 'Marque',     mandatory: false },
    { key: 'Modele',   label: 'Modèle',     mandatory: false },
    { key: 'Serial',   label: 'N° Série',   mandatory: false },
    { key: 'RAM',      label: 'RAM',        mandatory: false },
    { key: 'Disque',   label: 'Disque',     mandatory: false },
    { key: 'Type',     label: 'Type',       mandatory: false },
    { key: 'GPU',      label: 'GPU',        mandatory: false },
    { key: 'CPU',      label: 'Processeur', mandatory: false },
    { key: 'Bios',     label: 'BIOS',       mandatory: false },
    { key: 'WinVer',   label: 'Windows',    mandatory: false },
    { key: 'Date',     label: 'Date scan',  mandatory: false },
]

function parseParcLine(line) {
    const p = line.split('|')
    if (p.length < 12) return null
    return {
        Hostname: p[0]  || '',
        IP      : p[1]  || '',
        Marque  : p[2]  || '',
        Modele  : p[3]  || '',
        Serial  : p[4]  || '',
        WinVer  : p[5]  || '',
        RAM     : p[6]  || '',
        Disque  : p[7]  || '',
        Type    : p[8]  || '',
        GPU     : p[9]  || '',
        Date    : p[10] || '',
        Bios    : p[11] || '',
        MAC     : p[12] || '',
        TypeRAM : p[13] || '',
        CPU     : p[14] || '',
    }
}

function getSoftHtml(hostname, logBaseDir) {
    const sf = path.join(logBaseDir, `${hostname}.txt`)
    if (!fs.existsSync(sf)) return "<div class='error-message'>Fichier logiciel manquant</div>"
    const lines = fs.readFileSync(sf, 'utf-8').split('\n').map(l => l.trim()).filter(l => l)
    if (!lines.length) return "<div class='error-message'>Aucun logiciel trouvé</div>"
    let h = "<div class='software-list' style='max-height:300px;overflow-y:auto;'>"
    for (const sl of lines) {
        const parts = sl.split('|')
        const name  = parts[0] || sl
        const ver   = parts[1] || ''
        h += `<div class='software-item' data-software='${name.replace(/'/g,"&#39;")}'>
            <span class='software-name'>${name}</span>
            <span class='software-version'>${ver}</span></div>`
    }
    h += "</div>"
    return h
}

function generateReport(parcFile, logBaseDir, selectedCols) {
    if (!fs.existsSync(parcFile)) throw new Error(`parc.txt introuvable : ${parcFile}`)
    const lines = fs.readFileSync(parcFile, 'utf-8').split('\n').map(l => l.trim()).filter(l => l)
    if (!lines.length) throw new Error('parc.txt est vide')

    const pcs = lines.map(parseParcLine).filter(Boolean)

    // Grouper par 2ème segment du hostname
    const grouped = {}
    for (const pc of pcs) {
        const parts = pc.Hostname.split('-')
        const groupe = parts.length >= 3 ? parts[1] : 'INCONNU'
        if (!grouped[groupe]) grouped[groupe] = []
        grouped[groupe].push(pc)
    }

    const cols     = selectedCols
    const colIndex = {}
    cols.forEach((k, i) => colIndex[k] = i)
    const nbCols   = cols.length

    const hasMar  = cols.includes('Marque')
    const hasMod  = cols.includes('Modele')
    const hasGpu  = cols.includes('GPU')
    const hasDate = cols.includes('Date')

    let filterHtml = ''
    if (hasMar)  filterHtml += `<input id='filter-marque'  class='filter-input' placeholder='Filtrer par marque...'  data-col-key='Marque'>\n`
    if (hasMod)  filterHtml += `<input id='filter-modele'  class='filter-input' placeholder='Filtrer par modèle...'  data-col-key='Modele'>\n`
    if (hasGpu)  filterHtml += `<input id='filter-gpu'     class='filter-input' placeholder='Filtrer par GPU...'     data-col-key='GPU'>\n`
    filterHtml += `<input id='filter-salle'    class='filter-input' placeholder='Filtrer par salle...'>\n`
    filterHtml += `<input id='filter-logiciel' class='filter-input' placeholder='Filtrer par logiciel...'>\n`
    if (hasDate) filterHtml += `<input type='date' id='filter-date' class='filter-input' title='Postes scannés avant cette date'>\n<button id='reset-date' class='btn-reset'>Réinitialiser date</button>\n`

    let html = `<!DOCTYPE html>
<html lang='fr'>
<head>
<meta charset='UTF-8'>
<title>Inventaire Des Postes</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
<link href='https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap' rel='stylesheet'>
<style>
:root{--bg-dark:#1a1d29;--bg-darker:#13151f;--bg-card:#1f2937;--accent:#3b82f6;--accent-light:#60a5fa;--text-primary:#f3f4f6;--text-secondary:#9ca3af;--border:#374151;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Roboto',sans-serif;background-color:var(--bg-dark);color:var(--text-primary);min-height:100vh;padding:2rem 0;}
.container-fluid{max-width:1600px;margin:0 auto;padding:0 2rem;}
h1{text-align:center;font-weight:700;font-size:2.5rem;color:var(--text-primary);margin-bottom:.5rem;letter-spacing:-.5px;}
h1::after{content:'';display:block;width:80px;height:4px;background:var(--accent);margin:1rem auto;}
.filter-section{background-color:var(--bg-card);border-radius:12px;padding:1.5rem;margin-bottom:2rem;display:flex;flex-wrap:wrap;gap:1rem;justify-content:center;border:1px solid var(--border);}
.filter-input{background-color:var(--bg-darker);border:1px solid var(--border);color:var(--text-primary);padding:.75rem 1rem;border-radius:8px;transition:all .2s;font-size:.95rem;}
.filter-input:focus{color:var(--text-primary);background-color:var(--bg-darker);border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(59,130,246,.1);}
.filter-input::placeholder{color:var(--text-secondary);}
.btn-reset{background-color:var(--accent);border:none;color:white;padding:.75rem 1.5rem;border-radius:8px;font-weight:500;cursor:pointer;transition:all .2s;}
.btn-reset:hover{background-color:var(--accent-light);transform:translateY(-1px);}
#summary{background-color:var(--bg-card);border:1px solid var(--border);border-left:4px solid var(--accent);color:var(--text-primary);text-align:center;font-weight:600;font-size:1.1rem;padding:1rem;border-radius:8px;margin-bottom:2rem;display:none;}
.salle-section{background-color:var(--bg-card);border-radius:12px;padding:2rem;margin-bottom:2rem;border:1px solid var(--border);}
.salle-title{font-size:1.5rem;font-weight:700;color:var(--text-primary);margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:2px solid var(--border);}
.table{background-color:var(--bg-darker);border-radius:8px;overflow:hidden;width:100%;border-collapse:separate;border-spacing:0;}
thead{background-color:var(--bg-card);}
thead th{color:var(--text-primary);font-weight:600;text-transform:uppercase;font-size:.85rem;letter-spacing:.5px;padding:1rem;border-bottom:2px solid var(--accent);}
tbody tr{border-bottom:1px solid var(--border);transition:all .2s;}
tbody tr:hover{background-color:rgba(59,130,246,.05);}
tbody td{padding:1rem;color:var(--text-primary);font-size:.95rem;}
.badge-marque{color:white;padding:.35rem .75rem;border-radius:6px;font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.5px;display:inline-block;}
.badge-marque.dell{background-color:#0076cf;}
.badge-marque.lenovo{background-color:#e01408;}
.badge-marque.hp{background-color:#003984;}
.badge-marque.other{background-color:#000;}
.serial a{color:var(--accent-light);text-decoration:none;}
.serial a:hover{color:var(--accent);text-decoration:underline;}
.software-row{background-color:var(--bg-card);display:none;}
.software-row td{padding:1rem !important;}
.software-item{display:flex;justify-content:space-between;padding:.4rem .75rem;margin-bottom:.25rem;background-color:var(--bg-darker);border-radius:4px;border-left:2px solid transparent;transition:all .2s;font-size:.85rem;}
.software-item:hover{background-color:#262b3a;border-left-color:var(--accent);}
.software-highlight{background-color:rgba(245,249,20,.15);border-left-color:var(--accent) !important;}
.software-name{color:var(--text-primary);font-weight:500;}
.software-version{color:var(--text-secondary);font-weight:600;font-size:.8rem;}
.error-message{color:var(--accent-light);font-style:italic;text-align:center;}
.hostname-link{cursor:pointer;color:var(--accent-light);font-weight:600;transition:color .2s;}
.hostname-link:hover{color:var(--accent);}
::-webkit-scrollbar{width:10px;}
::-webkit-scrollbar-track{background:var(--bg-darker);border-radius:10px;}
::-webkit-scrollbar-thumb{background:var(--accent);border-radius:10px;}
</style>
</head>
<body>
<div class='container-fluid py-4'>
<h1>Inventaire Des Postes</h1>
<div class='filter-section'>${filterHtml}</div>
<div id='summary'>Total de postes : <span id='total-count'>0</span></div>\n`

    for (const [salle, pcList] of Object.entries(grouped).sort()) {
        const sorted = [...pcList].sort((a,b) => a.Hostname.localeCompare(b.Hostname))
        html += `<div class='salle-section' data-salle='${salle}'>
<div class='salle-title'>${salle} — ${sorted.length} poste(s)</div>
<table class='table table-dark table-hover table-sm'><thead><tr>`
        for (const key of cols) {
            const def = COL_DEFS.find(c => c.key === key)
            html += `<th>${def ? def.label : key}</th>`
        }
        html += `</tr></thead><tbody>\n`

        for (const pc of sorted) {
            const marqueUp = pc.Marque.toUpperCase()
            const serialHtml = marqueUp.includes('LENOVO') && pc.Serial
                ? `<a href='https://pcsupport.lenovo.com/fr/fr/products/${pc.Serial}/warranty' target='_blank'>${pc.Serial}</a>`
                : pc.Serial
            const gpuHtml = pc.GPU.split(';').join('<br>')

            html += `<tr>\n`
            for (const key of cols) {
                if      (key === 'Hostname') html += `<td><span class='hostname-link'>${pc.Hostname}</span></td>\n`
                else if (key === 'Marque')   html += `<td><span class='badge badge-marque'>${marqueUp}</span></td>\n`
                else if (key === 'Serial')   html += `<td class='serial'>${serialHtml}</td>\n`
                else if (key === 'RAM')      html += `<td class='specs'>${pc.RAM} GB</td>\n`
                else if (key === 'Disque')   html += `<td class='specs'>${pc.Disque} GB</td>\n`
                else if (key === 'GPU')      html += `<td class='gpu-list'>${gpuHtml}</td>\n`
                else if (key === 'Date')     html += `<td data-date='${pc.Date}'>${pc.Date}</td>\n`
                else                         html += `<td>${pc[key] || ''}</td>\n`
            }
            html += `</tr>\n`
            html += `<tr class='software-row'><td colspan='${nbCols}'>${getSoftHtml(pc.Hostname, logBaseDir)}</td></tr>\n`
        }
        html += `</tbody></table></div>\n`
    }

    const colIndexJson   = JSON.stringify(colIndex)
    const marqueVal      = hasMar  ? `document.getElementById('filter-marque').value.toLowerCase()` : `''`
    const modeleVal      = hasMod  ? `document.getElementById('filter-modele').value.toLowerCase()` : `''`
    const gpuVal         = hasGpu  ? `document.getElementById('filter-gpu').value.toLowerCase()`    : `''`
    const dateVal        = hasDate ? `document.getElementById('filter-date').value?new Date(document.getElementById('filter-date').value):null` : `null`
    const dateFilterIds  = hasDate ? `,'filter-date'` : ''
    const marqueFilterId = hasMar  ? `,'filter-marque'` : ''
    const modeleFilterId = hasMod  ? `,'filter-modele'` : ''
    const gpuFilterId    = hasGpu  ? `,'filter-gpu'`    : ''
    const dateReset      = hasDate ? `document.getElementById('reset-date').addEventListener('click',()=>{document.getElementById('filter-date').value='';filterTable();});` : ''

    html += `<script>
const colIndex=${colIndexJson};
document.querySelectorAll('.badge-marque').forEach(b=>{let m=b.textContent.toUpperCase();if(m.includes('DELL'))b.classList.add('dell');else if(m==='LENOVO')b.classList.add('lenovo');else if(m.includes('HEWLETT')||m==='HP')b.classList.add('hp');else b.classList.add('other');});
document.querySelectorAll('.hostname-link').forEach(el=>{el.addEventListener('click',()=>{let next=el.closest('tr').nextElementSibling;if(next&&next.classList.contains('software-row')){next.style.display=next.style.display==='table-row'?'none':'table-row';}});});
function getCellText(cells,key){if(colIndex[key]===undefined)return '';let c=cells[colIndex[key]];return c?c.textContent.toLowerCase():'';}
function filterTable(){
  let marque=${marqueVal},modele=${modeleVal},gpu=${gpuVal};
  let salle=document.getElementById('filter-salle').value.toLowerCase();
  let logiciel=document.getElementById('filter-logiciel').value.toLowerCase();
  let dateInput=${dateVal};
  let sections=document.querySelectorAll('.salle-section');
  let total=0;
  sections.forEach(section=>{
    let salleTitle=section.getAttribute('data-salle').toLowerCase();
    let rows=section.querySelectorAll('tbody tr:not(.software-row)');
    let visibleCount=0;
    rows.forEach(row=>{
      let cells=row.querySelectorAll('td');
      let dateMatch=true;
      if(dateInput&&colIndex['Date']!==undefined){let dateCell=cells[colIndex['Date']];let rowDateStr=dateCell?dateCell.getAttribute('data-date'):'';let dateParts=rowDateStr?rowDateStr.split(' ')[0].split('/'):'';let rowDate=dateParts.length===3?new Date(dateParts[2]+'-'+dateParts[1]+'-'+dateParts[0]):null;dateMatch=rowDate&&rowDate<=dateInput;}
      let softwareMatch=true;
      if(logiciel){let softRow=row.nextElementSibling;if(softRow&&softRow.classList.contains('software-row')){let softItems=softRow.querySelectorAll('.software-item');softwareMatch=false;softItems.forEach(item=>{let softName=item.getAttribute('data-software').toLowerCase();if(softName.includes(logiciel)){softwareMatch=true;item.classList.add('software-highlight');}else item.classList.remove('software-highlight');});}else softwareMatch=false;}
      else{let softRow=row.nextElementSibling;if(softRow&&softRow.classList.contains('software-row'))softRow.querySelectorAll('.software-item').forEach(item=>item.classList.remove('software-highlight'));}
      let match=getCellText(cells,'Marque').includes(marque)&&getCellText(cells,'Modele').includes(modele)&&getCellText(cells,'GPU').includes(gpu)&&salleTitle.includes(salle)&&dateMatch&&softwareMatch;
      row.style.display=match?'':'none';
      let next=row.nextElementSibling;if(next&&next.classList.contains('software-row'))next.style.display='none';
      if(match)visibleCount++;
    });
    section.style.display=visibleCount>0?'':'none';
    total+=visibleCount;
  });
  document.getElementById('summary').style.display='block';
  document.getElementById('total-count').textContent=total;
}
['filter-salle','filter-logiciel'${dateFilterIds}${marqueFilterId}${modeleFilterId}${gpuFilterId}].forEach(id=>{let el=document.getElementById(id);if(el)el.addEventListener('input',filterTable);});
${dateReset}
let initTotal=document.querySelectorAll('tbody tr:not(.software-row)').length;
document.getElementById('summary').style.display='block';
document.getElementById('total-count').textContent=initTotal;
<\/script>
</div></body></html>`

    return html
}

module.exports = { generateReport, COL_DEFS }
