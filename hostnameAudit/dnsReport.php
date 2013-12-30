<html><head><title>DNS Report</title></head></body>
<h2>DNS Report</h2>
<!-- This should be dropped in /var/www/html somehwere. -->

<p>This report takes all the entries in Prod, Prep, Test and QA and attempts to find a corresponding entry in the ilo and mgt domains. </p>

<p>Since many machines are virtual they will not have an ilo.</p>
<p>Some machines do not have managment.</p>

<p><b>The important reports are up front, and are the entries in .ilo and .mgt that cannot be matched up.</b> Once these get sorted back to their proper place all will be well with the world. </p>

<p><a href="#exceptions">Exceptions are here</a> and the main table is <a href='#mainTable'>here</a>

<table cellspacing=40>
<tr>
<th>ILO entries w/out matching servers</th>
<th>MGMT entries w/out matching servers</th>
</tr>
<tr>
</td>

<td valign='top'>
	<table border=1>
	<?php
	# Disabled: 
	$f = fopen("https://HostingServer/autoReports/ilo-non-match.csv", "r");
	if (!$f) { echo "ilo-non-match.csv not found. <br />\n"; }
	else {
	$lc=0;
	echo "<tr><th>Hostname</th><th>IP Addr</th></tr>\n";
	while (($line = fgetcsv($f)) !== false) {
        	echo "<tr>";
        	foreach ($line as $cell) {
                	echo "<td>" . htmlspecialchars($cell) . "</td>";
        		}
        	echo "<tr>\n";
		}
	}
	fclose($f);
	?>
	</table>
</td>
<td valign='top'>
	<table border=1>
	<?php
	# Disabled: 
	$f = fopen("https://HostingServer/autoReports/mgt-non-match.csv", "r");
	if (!$f) { echo "<tr><td>mgt-non-match.csv not found.</td></tr>\n"; }
	else {
	$lc=0;
	echo "<tr><th>Hostname</th><th>IP Addr</th></tr>\n";
	while (($line = fgetcsv($f)) !== false) {
        	echo "<tr>";
        	foreach ($line as $cell) {
                	echo "<td>" . htmlspecialchars($cell) . "</td>";
        		}
        	echo "<tr>\n";
	}
	}
	fclose($f);
	?>
</table>
</td>
</tr>
<tr>
<td colspan=2 >
	<h2 id='exceptions'>Exceptions:</h2>
	These are entries in the ilo or managment domain that do not have entries in the "regular" zones
	<table border=1>
	<?php
	# Disabled:
	$f = fopen("https://hostingServer/autoReports/exceptiontable.csv",'r');
	if (!$f) { echo "<tr><td>exceptionTable.csv not found.</td></tr>\n"; }
	else {
	$lc=0;
	while (($line = fgetcsv($f)) !== false ) { 
		echo "<tr>";
		if ($lc==0) {
		foreach ($line as $cell) {
			echo "<th>".htmlspecialchars($cell)."</th>";
			}
		}
		else {
		foreach ($line as $cell) {
                        echo "<td>".htmlspecialchars($cell)."</td>";
                        }
                }
	$lc++;
	}
	}
	fclose($f);
	?>
	</table>
</td>
</tr>
</table>

<h2 id="mainTable">Main Table</h2>
<p>Here's the juicy middle. Cut and paste into excel or other spreadsheet.</p>
<table cellpadding=2 border=1>
<?php
# $w = stream_get_wrappers();
$f = fopen("https://HostingServer/autoReports/dnsReport.csv", "r" );
if (!$f) { echo "<tr><td>Could not get dnsReport.csv</td></tr>"; }
else {
    $lc=0;
    $header=fgetcsv($f);
    echo "<tr>";
    foreach ($header as $headCell) {
        echo "<th>".htmlspecialchars($headCell)."</th>";
        }
    echo "</tr>";
    while (($line = fgetcsv($f)) !== false) {
	if ($lc == 0) {
		$c = 0; 
	} 
	else {
	if ($lc % 2 == 0) {
	   $color='#FFFFFF';
	   }
        else {
	   $color='#DDDDDD';
	   }
        echo "<tr bgcolor=\"$color\">";
        foreach ($line as $cell) {
                echo "<td>" . htmlspecialchars($cell) . "</td>";
	}
        echo "<tr>\n";
     }
     $lc++ ;
  }
}
fclose($f);
?>
</table>


</body></html>";


