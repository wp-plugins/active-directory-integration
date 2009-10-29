<?php

if ( !defined('WP_LOAD_PATH') ) {

	/** classic root path if wp-content and plugins is below wp-config.php */
	$classic_root = dirname(dirname(dirname(dirname(__FILE__)))) . '/' ;
	
	if (file_exists( $classic_root . 'wp-load.php') )
		define( 'WP_LOAD_PATH', $classic_root);
	else
		if (file_exists( $path . 'wp-load.php') )
			define( 'WP_LOAD_PATH', $path);
		else
			exit("Could not find wp-load.php");
}

// let's load WordPress
require_once( WP_LOAD_PATH . 'wp-load.php');

define('ADINTEGRATION_DEBUG', true);

if (class_exists('ADIntegrationPlugin')) {
	$ADI = new ADIntegrationPlugin();
} else {
	die('Plugin missing.');
}

$ADI->enableDebug();
?>
<html>
	<body>
		<h1 style="font-size: 14pt">AD Integration Logon Test</h1>
		
		<pre style="border: 1px solid #eee; background-color: #f9f9f9;">
<?php 
if (function_exists('ldap_connect')) {
	echo "* openLDAP installed\n";
} else {
	echo "! openLDAP not installed\n";
}
$result = $ADI->authenticate(NULL, $_GET['user'], $_GET['password']);

?>
		</pre>
<?php
if ($result) { 
	echo 'User logged on.';
} else {
	echo 'Logon failed';
}

?>

	</body>
</html>