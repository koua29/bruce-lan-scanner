// ============================================================================
//  Lan Scanner  -  Bruce / LilyGO T-Embed CC1101
//  Author: koua29
// ----------------------------------------------------------------------------
//  A tiny TCP port scanner + host discovery for the Bruce JS interpreter.
//
//  WHY IT WORKS THIS WAY: the BJS interpreter exposes NO raw TCP socket, only
//  wifi.httpFetch() (an HTTPClient). So we probe each host:port with an HTTP
//  GET and classify the port by HOW the connection behaves:
//
//    * httpFetch returns an object      -> OPEN  (real HTTP, shows status code)
//    * error "no HTTP server"           -> OPEN  (TCP accepted, non-HTTP service)
//    * error "read timeout" / "lost"    -> OPEN  (accepted then silent, e.g. ssh)
//    * error "connection refused", FAST -> CLOSED (host sent RST => host is UP)
//    * error "connection refused", SLOW -> no answer (host down / filtered)
//
//  Limits: HTTPS ports are probed as plain HTTP (still detects the open TCP).
//  Down hosts cost one connect-timeout each, so subnet sweeps are slow -> keep
//  the range small and press ESC between hosts to abort.
// ============================================================================

// ---- tunables --------------------------------------------------------------
var CLOSED_MAX_MS = 1500;   // "refused" faster than this = CLOSED (host up)
var OPEN_FAST_MS  = 2600;   // accepted-then-dropped under this = OPEN

var PORTS = [
  [21,"ftp"],   [22,"ssh"],   [23,"telnet"], [25,"smtp"],  [53,"dns"],
  [80,"http"],  [110,"pop3"], [135,"msrpc"], [139,"netbios"],[143,"imap"],
  [443,"https"],[445,"smb"],  [554,"rtsp"],  [1883,"mqtt"],[3000,"http-dev"],
  [3306,"mysql"],[3389,"rdp"],[5000,"upnp"], [5900,"vnc"], [7547,"tr069"],
  [8080,"http-alt"],[8443,"https-alt"],[8888,"http-alt"],[9100,"printer"],[32400,"plex"]
];
// "TCP ping" ports for host discovery. ONE port only on purpose: httpFetch uses
// WiFiClient whose connect timeout (~30s) is NOT settable from JS, so every DEAD
// IP blocks that long. A live host still answers in <1s (RST or accept), so one
// probe is enough to flag it "up". More ports here = 30s x N wasted per dead IP.
var DISCOVER_PORTS = [80];

// ---- tiny screen helpers ---------------------------------------------------
function C(r,g,b){ return display.color(r,g,b); }
var CW = C(255,255,255), CG = C(0,255,90), CR = C(255,70,70),
    CY = C(255,200,0),   CB = C(80,160,255), CGY = C(140,140,140);

function W(){ return display.width(); }
function H(){ return display.height(); }
function clear(){ display.fill(C(0,0,0)); }
function at(x,y,txt,col){ display.setTextColor(col); display.drawString(""+txt, x, y); }
function header(t){
  clear();
  display.setTextSize(2); at(6,4,t,CB);
  display.setTextSize(1); display.drawFastHLine(0,26,W(),CGY);
}
// cancel = long-press ESC OR a short encoder click (T-Embed has no real ESC key).
// NB: only polled BETWEEN probes; a dead IP blocks ~30s and can't be interrupted.
function esc(){ return keyboard.getEscPress() || keyboard.getSelPress(); }
function purgeKeys(){ for (var i=0;i<6;i++){ keyboard.getAnyPress(); delay(8); } }

// ---- graphics / pictos -----------------------------------------------------
function magnifier(x, y, col){             // small search glass
  display.drawCircle(x, y, 7, col);
  display.drawCircle(x, y, 6, col);
  display.drawWideLine(x+5, y+5, x+11, y+11, 3, col);
}
function radar(cx, cy, r, ang, col){       // sweeping radar, ang in radians
  display.drawCircle(cx, cy, r, CGY);
  display.drawCircle(cx, cy, Math.round(r*0.62), CGY);
  display.drawFastHLine(cx-r, cy, 2*r, CGY);
  display.drawFastVLine(cx, cy-r, 2*r, CGY);
  var x = cx + Math.round(r * Math.cos(ang));
  var y = cy + Math.round(r * Math.sin(ang));
  display.drawWideLine(cx, cy, x, y, 2, col);
  display.drawFillCircle(cx, cy, 2, col);
}
function checkIcon(cx, cy, s, col){        // big tick
  display.drawWideLine(cx-s, cy, cx-Math.round(s*0.25), cy+s, 4, col);
  display.drawWideLine(cx-Math.round(s*0.25), cy+s, cx+s, cy-s, 4, col);
}

// small 14px row pictos, drawn top-left at (x,y), text sits at y+1
function icoLockOpen(x, y, col){           // open padlock -> OPEN port
  display.drawRoundRect(x+1, y+5, 10, 8, 2, col);   // body
  display.drawFastVLine(x+6, y+8, 3, col);           // keyhole
  display.drawCircle(x+4, y+3, 3, col);              // open shackle (up-left)
  display.drawFastVLine(x+7, y+3, 2, col);
}
function icoHost(x, y, col){               // monitor -> host up
  display.drawRect(x, y+2, 12, 8, col);
  display.drawFastVLine(x+6, y+10, 2, col);          // stand
  display.drawFastHLine(x+3, y+12, 6, col);          // base
}
function icoWarn(x, y, col){               // triangle ! -> warning
  display.drawTriangle(x+6, y, x, y+12, x+12, y+12, col);
  display.drawFastVLine(x+6, y+4, 4, col);
  display.drawPixel(x+6, y+10, col);
}
function icoInfo(x, y, col){               // i -> info
  display.drawCircle(x+6, y+6, 5, col);
  display.drawPixel(x+6, y+3, col);
  display.drawFastVLine(x+6, y+5, 4, col);
}
function dot(x, y, col){ display.drawFillCircle(x+6, y+6, 4, col); }
function icoScan(x, y, col){               // magnifier -> Port Scan
  display.drawCircle(x+5, y+5, 4, col);
  display.drawWideLine(x+8, y+8, x+12, y+12, 2, col);
}
function icoNet(x, y, col){                // linked nodes -> Host Discovery
  display.drawLine(x+6, y+6, x+1, y+1, col);
  display.drawLine(x+6, y+6, x+11, y+1, col);
  display.drawLine(x+6, y+6, x+1, y+11, col);
  display.drawLine(x+6, y+6, x+11, y+11, col);
  display.drawFillCircle(x+6, y+6, 2, col);
  display.drawFillCircle(x+1, y+1, 1, col);
  display.drawFillCircle(x+11, y+1, 1, col);
  display.drawFillCircle(x+1, y+11, 1, col);
  display.drawFillCircle(x+11, y+11, 1, col);
}
function icoQuit(x, y, col){               // power symbol -> Quit
  display.drawCircle(x+6, y+7, 5, col);
  display.drawFastVLine(x+6, y+1, 6, col);
}
function icoEdit(x, y, col){               // keyboard -> manual IP entry
  display.drawRoundRect(x, y+3, 13, 8, 2, col);
  display.drawPixel(x+3, y+6, col);
  display.drawPixel(x+6, y+6, col);
  display.drawPixel(x+9, y+6, col);
  display.drawFastHLine(x+4, y+8, 5, col);
}
function icoBack(x, y, col){               // left arrow -> cancel/back
  display.drawWideLine(x+11, y+6, x+1, y+6, 2, col);
  display.drawWideLine(x+1, y+6, x+5, y+2, 2, col);
  display.drawWideLine(x+1, y+6, x+5, y+10, 2, col);
}
function drawIcon(kind, x, y, col){
  if (kind === "open")      icoLockOpen(x, y, col);
  else if (kind === "host") icoHost(x, y, col);
  else if (kind === "warn") icoWarn(x, y, col);
  else if (kind === "info") icoInfo(x, y, col);
  else if (kind === "closed") dot(x, y, col);
  else if (kind === "scan") icoScan(x, y, col);
  else if (kind === "net")  icoNet(x, y, col);
  else if (kind === "quit") icoQuit(x, y, col);
  else if (kind === "edit") icoEdit(x, y, col);
  else if (kind === "back") icoBack(x, y, col);
}

// intro splash
function splashScreen(){
  clear();
  var cx = Math.round(W()/2);
  radar(cx, 52, 30, 0.9, CG);
  display.setTextSize(2);
  var t = "LAN SCANNER";
  at(cx - t.length*6, 94, t, CB);
  display.setTextSize(1);
  at(cx - 51, 118, "network recon tool", CGY);
  delay(1100);
}

// live "scanning..." frame, drawn BEFORE each (blocking) probe
function scanFrame(title, target, sub, cur, total, found, step){
  header(title);
  magnifier(18, 42, CY);
  at(34, 36, "SCANNING...", CY);
  at(34, 52, "please wait", CGY);
  radar(W()-38, 66, 26, step*0.7, CG);
  at(6, 74, target, CW);
  at(6, 90, sub, CGY);
  var y0 = H() - 34;
  display.drawRoundRect(6, y0, W()-12, 12, 3, CGY);
  var w = Math.round((W()-16) * cur / total);
  if (w > 0) display.drawFillRect(8, y0+2, w, 8, CB);
  at(6, y0+16, cur + "/" + total, CGY);
  display.drawFillCircle(W()-72, y0+20, 4, CG);
  at(W()-64, y0+16, "found " + found, CG);
  at(W()-72, 6, "click=stop", CGY);
}
// completion splash
function doneFrame(title, count, label){
  header(title);
  var col = count > 0 ? CG : CY;
  checkIcon(Math.round(W()/2), 56, 20, col);
  display.setTextSize(2);
  var msg = count + " " + label;
  at(Math.round(W()/2) - msg.length*6, 92, msg, col);
  display.setTextSize(1);
  at(Math.round(W()/2) - 40, 120, "SEL to see list", CGY);
  delay(900);
}

// ---- wifi ------------------------------------------------------------------
function ensureWifi(){
  if (wifi.connected()) return true;
  header("Lan Scanner"); at(6,34,"Connecting Wi-Fi...",CW);
  var ok = wifi.connectDialog();
  return ok && wifi.connected();
}
function ipBase(){                       // "192.168.1.42" -> "192.168.1."
  var ip = "" + wifi.getIPAddress();
  var p = ip.lastIndexOf(".");
  return (p > 0) ? ip.substring(0, p+1) : "";
}

// ---- the core probe --------------------------------------------------------
function probe(ip, port){
  var url = "http://" + ip + ":" + port + "/";
  var t0 = Date.now();
  try {
    var r = wifi.httpFetch(url, { method:"GET" });
    return { st:"open", note:"HTTP "+r.status, ms:(Date.now()-t0) };
  } catch(e){
    var dt = Date.now() - t0;
    var m = (""+e).toLowerCase();
    // TCP could NOT be established -> port closed (fast RST) or host down (slow).
    if (m.indexOf("refused") >= 0 || m.indexOf("not connected") >= 0)
      return (dt <= CLOSED_MAX_MS) ? { st:"closed", ms:dt } : { st:"none", ms:dt };
    // ANY other error means the TCP handshake succeeded -> the port IS open
    // (e.g. HTTPS/TLS port probed as plain HTTP -> "connection lost"/"no HTTP server").
    var note = (m.indexOf("no http") >= 0) ? "tcp"
             : (m.indexOf("timeout") >= 0) ? "silent"
             : (m.indexOf("lost")    >= 0) ? "tls?" : "open";
    return { st:"open", note:note, ms:dt };
  }
}

// ---- mode 1: scan one host -------------------------------------------------
// liveness pre-check: a manually typed IP may be DOWN, and each dead port would
// block ~30s (25 ports = ~12 min, non-interruptible). We first TCP-ping a couple
// of ports; if nothing answers the host is treated as down and we bail out.
function hostUp(ip){
  header("Port Scan");
  magnifier(18, 42, CY);
  at(34, 40, "checking host...", CY);
  at(6, 66, ip, CW);
  at(6, 88, "please wait (<60s)", CGY);
  at(6, H()-11, "a dead IP takes up to 60s", CGY);
  var ports = [80, 443];                 // any TCP answer (open or RST) => host is up
  for (var i=0; i<ports.length; i++){
    var r = probe(ip, ports[i]);
    if (r.st === "open" || r.st === "closed") return true;
  }
  return false;
}
function scanHost(ip){
  purgeKeys();
  if (!hostUp(ip)){
    showResults("Port Scan", ip + "  -  unreachable", [
      { ic:"warn", s:"Host down / filtered", col:CY },
      { ic:"info", s:"no TCP response", col:CGY },
      { ic:"info", s:"check the IP / network", col:CGY }
    ]);
    return;
  }
  var open = [], n = PORTS.length, aborted = false;
  for (var i=0; i<n; i++){
    if (esc()){ aborted = true; break; }
    var port = PORTS[i][0], name = PORTS[i][1];
    scanFrame("Port Scan", ip, "port " + port + " (" + name + ")",
              i+1, n, open.length, i);
    var r = probe(ip, port);
    if (r.st === "open") open.push({
      port:port, name:name, note:(r.note||""),
      web:(name.indexOf("http") >= 0),
      scheme:(name.indexOf("https") >= 0 ? "https" : "http")
    });
  }
  doneFrame("Port Scan", open.length, open.length===1 ? "open port" : "open ports");
  // results
  var sub = ip + "  -  " + open.length + " open" + (aborted ? "  (stop)" : "");
  if (open.length === 0){
    showResults("Port Scan", sub, [
      { ic:"warn", s:"No open port found", col:CY },
      { ic:"info", s:"host down / filtered", col:CGY },
      { ic:"info", s:"or all ports closed", col:CGY }
    ]);
    return;
  }
  // selectable list -> click a port to inspect it (web ports get fetched)
  var rows = [];
  for (var k=0;k<open.length;k++){
    var o = open[k];
    rows.push({ ic:"open", col:CG, o:o,
      s: o.port + "/" + o.name + "  " + o.note + (o.web ? "  [web]" : "") });
  }
  var cur = 0;
  while (true){
    cur = pickList("Port Scan", sub, rows, cur, "rotate=move  OK=inspect  ESC=back");
    if (cur < 0) break;
    inspectPort(ip, rows[cur].o);
  }
}

// ---- inspect a port -------------------------------------------------------
function headerVal(headers, name){
  if (!headers) return "";
  name = name.toLowerCase();
  for (var k in headers){ if (("" + k).toLowerCase() === name) return "" + headers[k]; }
  return "";
}
function stripHtml(s){
  s = ("" + s);
  s = s.replace(/<script[\s\S]*?<\/script>/gi, " ");
  s = s.replace(/<style[\s\S]*?<\/style>/gi, " ");
  s = s.replace(/<[^>]+>/g, " ");
  s = s.replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&")
       .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&quot;/gi, '"');
  return s.replace(/\r/g, "");
}
function wrapPush(rows, text, col){         // word-wrap into ~44-char rows
  var LW = 44, parts = ("" + text).split("\n");
  for (var p=0; p<parts.length && rows.length<220; p++){
    var line = parts[p].replace(/[ \t]+/g, " ").trim();
    while (line.length > LW && rows.length < 220){
      rows.push({ ic:"none", s:line.substring(0, LW), col:col }); line = line.substring(LW);
    }
    if (line.length) rows.push({ ic:"none", s:line, col:col });
  }
}
// HTTP(S) port -> fetch & show server type + title + page text; other -> note.
function inspectPort(ip, o){
  if (!o.web){                              // no raw socket in BJS => no banner grab
    showResults("Port " + o.port, ip + ":" + o.port, [
      { ic:"open", s:"Service (by port): " + o.name, col:CG },
      { ic:"info", s:"TCP port is open", col:CW },
      { ic:"warn", s:"No banner grab possible", col:CY },
      { ic:"info", s:"BJS exposes only HTTP,", col:CGY },
      { ic:"info", s:"not raw TCP sockets.", col:CGY }
    ]);
    return;
  }
  var url = o.scheme + "://" + ip + ":" + o.port + "/";
  header("Inspect"); magnifier(18, 42, CY);
  at(34, 40, "fetching page...", CY); at(6, 66, url, CW); at(6, 88, "please wait", CGY);
  var rows = [];
  try {
    var r = wifi.httpFetch(url, { method:"GET" });
    var srv = headerVal(r.headers, "server");
    var pby = headerVal(r.headers, "x-powered-by");
    var body = "" + (r.body || "");
    var tm = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    rows.push({ ic:"open", s:"HTTP " + r.status + (r.ok ? "  OK" : ""), col:CG });
    if (srv) rows.push({ ic:"info", s:"Server: " + srv, col:CW });
    if (pby) rows.push({ ic:"info", s:"Powered: " + pby, col:CW });
    if (tm)  rows.push({ ic:"info", s:"Title: " + tm[1].replace(/\s+/g, " ").trim(), col:CW });
    rows.push({ ic:"none", s:"----- page text -----", col:CGY });
    var before = rows.length;
    wrapPush(rows, stripHtml(body), CW);
    if (rows.length === before) rows.push({ ic:"info", s:"(no readable text)", col:CGY });
  } catch(e){
    rows.push({ ic:"warn", s:"Cannot read page", col:CY });
    if (o.scheme === "https") rows.push({ ic:"info", s:"HTTPS/TLS not supported", col:CGY });
    rows.push({ ic:"info", s:"Open it on a phone/PC:", col:CGY });
    rows.push({ ic:"none", s:url, col:CB });
  }
  showResults("Inspect " + o.port, url, rows);
}

// ---- mode 2: discover hosts on the /24 ------------------------------------
function discover(base, a, b){
  var up = [];
  purgeKeys();
  for (var host=a; host<=b; host++){
    if (esc()) break;
    var ip = base + host, hit = null;
    scanFrame("Host Discovery", ip, "range ." + a + "-." + b,
              host-a+1, (b-a+1), up.length, host);
    for (var j=0; j<DISCOVER_PORTS.length && !hit; j++){
      var r = probe(ip, DISCOVER_PORTS[j]);
      if (r.st === "open")   hit = "open " + DISCOVER_PORTS[j];
      else if (r.st === "closed") hit = "alive (rst)";
    }
    if (hit) up.push({ ip:ip, hit:hit });
  }
  doneFrame("Host Discovery", up.length, up.length===1 ? "host up" : "hosts up");
  var sub = base + "0/24  ." + a + "-." + b + "  up:" + up.length;

  if (up.length === 0){
    showResults("Host Discovery", sub, [{ ic:"warn", s:"No host responded", col:CY }]);
    return;
  }
  // interactive: pick a host -> scan it -> come back to the list (same cursor)
  var rows = [];
  for (var k=0;k<up.length;k++)
    rows.push({ ic:"host", s:up[k].ip + "  [" + up[k].hit + "]", col:CG, ip:up[k].ip });
  var cur = 0;
  while (true){
    cur = pickList("Host Discovery", sub, rows, cur);
    if (cur < 0) break;                 // ESC -> back to main menu
    scanHost(rows[cur].ip);             // scans, shows result, ESC returns here
  }
}

// ---- results viewer (scrollable, flicker-free, with pictos) ---------------
// Custom pager instead of dialog.viewText (which self-redraws => flickers).
// rows = [{ ic:"open"|"host"|"warn"|"info"|"closed", s:"text", col:color }, ...]
// Drawn once, repainted ONLY when the scroll position changes.
function showResults(title, subtitle, rows){
  var LH = 15, top0 = 44;
  var per = Math.floor((H() - top0 - 12) / LH);
  if (per < 1) per = 1;
  var max = Math.max(0, rows.length - per);
  var top = 0, dirty = true;
  purgeKeys();
  while (true){
    if (dirty){
      header(title);
      at(6, 30, subtitle, CB);                   // summary band
      for (var i=0; i<per; i++){
        var idx = top + i, y = top0 + i*LH;
        if (idx >= rows.length) break;
        var r = rows[idx];
        drawIcon(r.ic, 6, y, r.col);
        at(26, y+2, r.s, r.col);
      }
      if (rows.length > per){                     // scrollbar
        var trackH = per*LH;
        var barH = Math.max(10, Math.round(trackH*per/rows.length));
        var barY = top0 + Math.round((trackH-barH)*(max ? top/max : 0));
        display.drawFastVLine(W()-5, top0, trackH, CGY);
        display.drawFillRect(W()-6, barY, 4, barH, CB);
      }
      at(6, H()-11, "rotate=scroll   OK/ESC=back", CGY);
      dirty = false;
    }
    if (keyboard.getPrevPress()){ if (top > 0)   { top--; dirty = true; } }
    else if (keyboard.getNextPress()){ if (top < max) { top++; dirty = true; } }
    else if (keyboard.getEscPress() || keyboard.getSelPress()){ break; }
    delay(40);
  }
}

// selectable list: rotate = move highlight, click = pick, ESC = back.
// returns the chosen row index, or -1 on ESC. startSel keeps the cursor place.
function pickList(title, subtitle, rows, startSel, hint){
  var LH = 15, top0 = 44;
  hint = hint || "rotate=move  OK=scan  ESC=back";
  var per = Math.floor((H() - top0 - 12) / LH);
  if (per < 1) per = 1;
  var sel = startSel || 0;
  if (sel >= rows.length) sel = 0;
  var top = Math.max(0, Math.min(sel, rows.length - per));
  var dirty = true;
  purgeKeys();
  while (true){
    if (dirty){
      header(title);
      at(6, 30, subtitle, CB);
      for (var i=0; i<per; i++){
        var idx = top + i, y = top0 + i*LH;
        if (idx >= rows.length) break;
        var r = rows[idx];
        if (idx === sel){                          // highlighted row
          display.drawFillRoundRect(2, y-1, W()-11, LH-1, 2, CB);
          drawIcon(r.ic, 6, y, C(0,0,0));
          at(26, y+2, r.s, C(0,0,0));
        } else {
          drawIcon(r.ic, 6, y, r.col);
          at(26, y+2, r.s, r.col);
        }
      }
      if (rows.length > per){                       // scrollbar
        var trackH = per*LH, mx = rows.length - per;
        var barH = Math.max(10, Math.round(trackH*per/rows.length));
        var barY = top0 + Math.round((trackH-barH)*(mx ? top/mx : 0));
        display.drawFastVLine(W()-5, top0, trackH, CGY);
        display.drawFillRect(W()-6, barY, 4, barH, CB);
      }
      at(6, H()-11, hint, CGY);
      dirty = false;
    }
    if (keyboard.getPrevPress()){
      if (sel > 0){ sel--; if (sel < top) top = sel; dirty = true; }
    } else if (keyboard.getNextPress()){
      if (sel < rows.length-1){ sel++; if (sel >= top+per) top = sel-per+1; dirty = true; }
    } else if (keyboard.getSelPress()){
      return sel;
    } else if (keyboard.getEscPress()){
      return -1;
    }
    delay(40);
  }
}

// ---- input helpers ---------------------------------------------------------
function askIP(label, def){                 // keyboard(prefill, maxLen, label): arg1 fills the box
  var s = keyboard.keyboard(def, 15, label);
  return (s && s.length) ? s : def;
}
function lastOctet(ip){                     // "192.168.1.50" -> 50
  var p = ("" + ip).lastIndexOf(".");
  return parseInt(("" + ip).substring(p + 1), 10);
}
// target picker: one tap for the gateway, else type only the last part
function pickTarget(base){
  var g = base + "1";
  var rows = [
    { ic:"net",  s:"Gateway  " + g, col:CW },
    { ic:"edit", s:"Enter IP...",   col:CW }
  ];
  var sel = pickList("Port Scan", "select target", rows, 0, "rotate=move  OK=ok  ESC=back");
  if (sel < 0) return null;
  if (sel === 0) return g;
  var s = keyboard.keyboard(base, 15, "Target IP");  // arg1 = prefilled box "192.168.1."
  return (s && s.length > base.length) ? s : null;
}

// ---- main menu -------------------------------------------------------------
function main(){
  splashScreen();
  if (!ensureWifi()){ dialog.error("Lan Scanner","Wi-Fi not connected"); return; }
  var base = ipBase();
  var myip = "" + wifi.getIPAddress();

  var menu = [
    { ic:"scan", s:"Port Scan (one host)",    col:CW },
    { ic:"net",  s:"Host Discovery (subnet)", col:CW },
    { ic:"info", s:"Device info",             col:CW },
    { ic:"quit", s:"Quit",                    col:CW }
  ];
  var msel = 0;
  while (true){
    msel = pickList("LAN SCANNER", "network recon tool", menu, msel,
                    "rotate=move  OK=select  ESC=quit");
    if (msel < 0 || msel === 3) return;          // ESC or Quit

    if (msel === 0){                             // Port Scan
      var ip = pickTarget(base);
      if (ip) scanHost(ip);
    } else if (msel === 1){                      // Host Discovery
      if (!base){ dialog.error("Host Discovery","No IP / not on a /24"); continue; }
      var a = lastOctet(askIP("Start IP (type .x)", base));   // prefilled "192.168.1." -> type the octet
      var b = lastOctet(askIP("End IP (type .x)",   base));
      if (isNaN(a)) a = 1;
      if (isNaN(b)) b = 254;
      if (a < 1) a = 1;
      if (b > 254) b = 254;
      if (b < a){ var t=a; a=b; b=t; }
      var count = b - a + 1;
      // warn: worst case is ~30s per DEAD ip (firmware connect-timeout, not fixable in JS)
      var go = pickList("Host Discovery", "confirm  ." + a + "-." + b, [
        { ic:"scan", s:"Scan " + count + " IPs",     col:CW },
        { ic:"back", s:"Cancel (dead IP ~30s)",      col:CY }
      ], 0, "rotate=move  OK=ok  ESC=back");
      if (go === 0) discover(base, a, b);
    } else if (msel === 2){                      // Device info
      showResults("Device info", "this device", [
        { ic:"info", s:"IP   " + myip, col:CW },
        { ic:"info", s:"MAC  " + wifi.getMACAddress(), col:CW },
        { ic:"info", s:"Net  " + base + "0/24", col:CW }
      ]);
    }
  }
}

main();
