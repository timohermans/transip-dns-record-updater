<?php
require 'TransIP_AccessToken.php';

function logg($txt) {
	$currentDate = new DateTime();
	$currentDateString = $currentDate->format('Y-m-d H:i:s');
	$currentLogFilename = '/home/timo/dynamic-ip-update/log.txt';
	$logFileSize = filesize($currentLogFilename);

	if ($logFileSize > 10000) {
		unlink($currentLogFilename);
	}

	$currentLogFile = fopen($currentLogFilename, 'a');
	$txt = $currentDateString . ': ' . $txt . "\n";
	fwrite($currentLogFile, $txt);
	fclose($currentLogFile);
	echo $txt;
}

$currentIpFilename = '/home/timo/dynamic-ip-update/current_ip.txt';
$currentIpFile = fopen($currentIpFilename, 'r');
$currentIp = fread($currentIpFile, filesize($currentIpFilename));
fclose($currentIpFile);

$realIp = file_get_contents("http://ipecho.net/plain");

if(empty($realIp)) {
	logg('Unable to retrieve current ip from ipecho');
	throw new Exception('Unable to retrieve current ip from ipecho');
}

if ($currentIp === $realIp) {
	logg('No change in IP. Nothing to do.');
	return;
}

logg('Ip has changed. Going to update transip');
logg('Changed: ' . $currentIp . ' -> ' . $realIp);

try {
	$keyFilename = '/home/timo/dynamic-ip-update/private_key.key';
	$privateKeyFile = fopen($keyFilename, 'r') or die('unable to open private key');
	$privateKey = fread($privateKeyFile, filesize($keyFilename));
	fclose($privateKeyFile);

	$transip = new TransIP_AccessToken();
	$dnsRecords = $transip->getDnsRecords();
	$dnsRecord = '';

	foreach ($dnsRecords as $record) {
	    if ($record->name === '*' && $record->type === 'A') {
		    $dnsRecord = $record;
		    break;
	    }
	}

	if(empty($dnsRecord)) {
		logg('Unable to retrieve type A wildcard (*) from TransIP');
		throw new Exception('Unable to retrieve type A wildcard (*) from TransIP');
	}


	$dnsRecord->content = $realIp;
	$transip->updateDnsRecord($dnsRecord);
	logg('Done updating DNS record');
} catch (Exception $e) {
	logg('Something went wrong with TransIP update call. Message: ' . $e.getMessage());
	return;
}
$ipFile = fopen('/home/timo/dynamic-ip-update/current_ip.txt', 'w');
fwrite($ipFile, $realIp);
fclose($ipFile);
logg('Wrote new IP to current_ip file');
?>
