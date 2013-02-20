<?php
/**
 * User Bulk Import & Update for Active Directory Integration
 *
 * @package Active Directory Integration
 * @author Christoph Steindorff
 * @since 1.1.2
 */


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

// load class BulkSyncBackADIntegrationPlugin
require_once( dirname( __FILE__ ) .'/BulkSyncBackADIntegrationPlugin.class.php');

// turn off possible output buffering
ob_end_flush();


// If the plugin class is not found, die.
if (!class_exists('ADIntegrationPlugin')) {
	die('ADI not installed.');
}

// Let's do some security checks
 
// If the user is not logged in, die silently.
if(!$user_ID) {
	die();
}

// If the user is not an admin, die silently.
if (!current_user_can('level_10')) {
	die();
}

// If we have WordPress MU, die silently.
if (isset($wpmu_version) && $wpmu_version != '') {
	die();
}




define('ADINTEGRATION_DEBUG', true);

if (class_exists('ADIntegrationPlugin')) {
	$ADI = new BulkSyncBackADIntegrationPlugin();
} else {
	die('Plugin missing.');
}

// Log Level
if (isset($_REQUEST['debug'])) {
	$ADI->setLogLevel(ADI_LOG_DEBUG);
} else {
	$ADI->setLogLevel(ADI_LOG_INFO);
}

?>
<html>
	<head>
		<title>ADI Bulk SyncBack</title>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<style type="text/css">
			h1 {
				font-size: 14pt;
			}
			#output {
				border: 1px solid #eee;
				background-color: #f9f9f9;
				font-family: consolas, courier, monospace;
				font-size: 10pt;
				white-space:pre; 
			}
			
			.debug {
				color: #606060;
			}
			
			.info {
				color: #000000;
			}
			
			.notice {
				color: #0000A0;
			}
			
			.warn {
				color: #f08000;
			}
			
			.error {
				color: #f04020;
			}
			
			.fatal  {
				color: #ff0000;
				font-weight: bold;
			}

		</style>
		
	</head>
	<body>
		<h1 style="font-size: 14pt">AD Integration Bulk SyncBack</h1>
		
<?php 
if (function_exists('ldap_connect')) {
	echo "openLDAP installed\n";
} else {
	die('openLDAP not installed');
}
?>
		<div id="output">
<?php


// Let's go!
if (isset($_GET['userid'])) {
	$result = $ADI->bulksyncback($_GET['userid']);
} else {
	$result = $ADI->bulksyncback();
}

?>
		</div>
<?php
if ($result) { 
	echo 'Bulk SyncBack returned no error.';
} else {
	echo 'Error on Bulk SyncBack.';
}

?>

	</body>
</html>