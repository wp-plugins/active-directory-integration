<?php
// Extend the ADIntegrationPlugin class
class BulkSyncBackADIntegrationPlugin extends ADIntegrationPlugin {

	/**
	 * Output debug informations
	 *
	 * @param integer level
	 * @param string $notice
	 */
	protected function _log($level = 0, $info = '') {
		if ($level <= $this->_loglevel) {
			switch ($level) {
				case ADI_LOG_DEBUG:
					$class = 'debug';
					$type  = '[DEBUG]  ';
					break;
				case ADI_LOG_INFO:
					$class = 'info';
					$type  = '[INFO]   ';
					break;
				case ADI_LOG_NOTICE:
					$class = 'notice';
					$type = '[NOTICE] ';
					break;
				case ADI_LOG_WARN:
					$class = 'warn';
					$type = '[WARN]   ';
					break;
				case ADI_LOG_ERROR:
					$class = 'error';
					$type = '[ERROR]  ';
					break;
				case ADI_LOG_FATAL:
					$class = 'fatal';
					$type = '[FATAL]  ';
					break;
				default:
					$class = '';
					$type = '';
						
			}
			$output = '<span class="'.$class.'">'.$type;
			$output .= str_replace("\n","<br />         ",$info).'</span><br />';
			echo $output;
				
			if (WP_DEBUG) {
				if ($fh = @fopen($this->_logfile,'a+')) {
					fwrite($fh,$type . str_replace("\n","\n         ",$info) . "\n");
					fclose($fh);
				}
			}
		}
	}




	/**
	 * Do Bulk SyncBack
	 *
	 * @param string $authcode
	 * @return bool true on success, false on error
	 */
	public function bulksyncback($userid = NULL)
	{
		global $wp_version;
		global $wpdb;

		$this->setLogFile(dirname(__FILE__).'/syncback.log');

		$this->_log(ADI_LOG_INFO,"-------------------------------------\n".
				"START OF BULK SYNCBACK\n".
				date('Y-m-d / H:i:s')."\n".
				"-------------------------------------\n");

		$time = time();
		$updated_users = 0;
		$all_users = array();

		// Is bulk syncback enabled?
		if (!$this->_syncback) {
			$this->_log(ADI_LOG_INFO,'SyncBack is disabled.');
			return false;
		}

		$ad_password = $this->_decrypt($this->_syncback_global_pwd);

		// Log informations
		$this->_log(ADI_LOG_INFO,"Options for adLDAP connection:\n".
				"- base_dn: $this->_base_dn\n".
				"- domain_controllers: $this->_domain_controllers\n".
				"- ad_username: $this->_syncback_global_user\n".
				"- ad_password: **not shown**\n".
				"- ad_port: $this->_port\n".
				"- use_tls: ".(int) $this->_use_tls."\n".
				"- network timeout: ". $this->_network_timeout);
			
		// Connect to Active Directory
		try {
			$this->_adldap = @new adLDAP(array(
					"base_dn" => $this->_base_dn,
					"domain_controllers" => explode(';', $this->_domain_controllers),
					"ad_username" => $this->_syncback_global_user, 		// Bulk Import User
					"ad_password" => $ad_password, 			  		// password
					"ad_port" => $this->_port,                		// AD port
					"use_tls" => $this->_use_tls,            		// secure?
					"network_timeout" => $this->_network_timeout	// network timeout
			));
		} catch (Exception $e) {
			$this->_log(ADI_LOG_ERROR,'adLDAP exception: ' . $e->getMessage());
			return false;
		}
		$this->_log(ADI_LOG_NOTICE,'adLDAP object created.');
		$this->_log(ADI_LOG_INFO,'Domain Controller: ' . $this->_adldap->get_last_used_dc());

		// Let's give us some more time (60 minutes)
		$max_execution_time = ini_get('max_execution_time');
		if ($max_execution_time < 3600) {
			ini_set('max_execution_time', 3600);
		}
		if (ini_get('max_execution_time') < 3600) {
			$this->_log(ADI_LOG_ERROR,'Can not increase PHP configuration option "max_execution_time".');
			return false;
		}

		$attributes = $this->_get_attributes_array();
		$this->_log(ADI_LOG_DEBUG, 'attributes: ' . print_r($attributes, true));

		// Do we have possible attributes for SyncBack?
		if (count($attributes) > 0) {


			// Get IDs of users to SyncBack
			// They must have a wp_usermeta.metakey = 'adi_samaccount' with a not empty meta_value and User 1 (admin) is excluded.
			if ($userid == NULL) {
				$users = $wpdb->get_results("SELECT user_id FROM $wpdb->usermeta WHERE meta_key = 'adi_samaccountname' AND meta_value <> '' AND user_id <> 1 ORDER BY user_id");
			} else {
				$users = $wpdb->get_results("SELECT user_id FROM $wpdb->usermeta WHERE meta_key = 'adi_samaccountname' AND meta_value <> '' AND user_id <> 1 AND user_id = $userid");
			}

			// Do we have possible users for SyncBack?
			if ($users) {
				foreach ( $users as $user ) {
						
					$userinfo = get_userdata($user->user_id);
					if ($userinfo) {
						$this->_log(ADI_LOG_INFO, 'User-Login: '.$userinfo->user_login);
						$this->_log(ADI_LOG_INFO, 'User-ID: '.$user->user_id);
							

						$no_attribute = false;
						$attributes_to_sync = array();
						foreach ($attributes AS $key => $attribute) {
								
							if ($no_attribute === false) {

								if (isset($attribute['sync']) && ($attribute['sync'] == true)) {
									// $value = get_user_meta($user->user_id, $attribute['metakey'], true); // BAD
									$value = $wpdb->get_var( $wpdb->prepare( "SELECT meta_value FROM $wpdb->usermeta WHERE meta_key = '".$attribute['metakey']."' AND user_id = ".$user->user_id ) );

									if ($value !== FALSE) {
										if ($attribute['type'] == 'list') {
											// List
											$list = explode("\n",str_replace("\r",'',$value));
											$i=0;
											foreach ($list AS $line) {
												if (trim($line) != '') {
													$attributes_to_sync[$key][$i] = $line;
													$i++;
												}
											}
											if ($i == 0) {
												$attributes_to_sync[$key][0] = ' '; // Use a SPACE !!!
											}
										} else {
											// single value
											if ($value == '') {
												$attributes_to_sync[$key][0] = ' '; // Use a SPACE !!!!
											} else {
												$attributes_to_sync[$key][0] = $value;
											}
										}
									}
										
								}
							}
						}

						//  Now we can modify the user
						$this->_log(ADI_LOG_INFO,'attributes to sync: '.print_r($attributes_to_sync, true));
						$this->_log(ADI_LOG_DEBUG,'modifying user: '.$userinfo->user_login);
						$modified = $this->_adldap->user_modify_without_schema($userinfo->user_login, $attributes_to_sync);
						if (!$modified) {
							$this->_log(ADI_LOG_WARN,'SyncBack: modifying user failed');
							$this->_log(ADI_LOG_DEBUG,$this->_adldap->get_last_errno().': '.$this->_adldap->get_last_error());
						} else {
							$this->_log(ADI_LOG_NOTICE,'SyncBack: User successfully modified.');
							$updated_users++;
						}
					} else {
						$this->_log(ADI_LOG_NOTICE,'User with ID ' . $user->user_id .' not found.');
					}
				}
			} else {
				$this->_log(ADI_LOG_INFO, 'No possible users for SyncBack found.');
			}
		} else {
			$this->_log(ADI_LOG_INFO, 'No possible attributes for SyncBack found.');
		}

		// Logging
		$elapsed_time = time() - $time;
		$this->_log(ADI_LOG_INFO,$updated_users . ' Users updated.');
		$this->_log(ADI_LOG_INFO,'In '. $elapsed_time . ' seconds.');

		$this->_log(ADI_LOG_INFO,"-------------------------------------\n".
				"END OF BULK SYNCBACK\n".
				date('Y-m-d / H:i:s')."\n".
				"-------------------------------------\n");

		return true;
	}

}
?>