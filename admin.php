<?php
		
		if (IS_WPMU) {
			if (!is_site_admin()) {
				_e('Access denied.', 'ad-integration');
				$this->_log(ADI_LOG_WARN,'Access to options page denied');
				exit();
			}
		}
		
		
		// form send?
		if (IS_WPMU && $_POST['action'] == 'update') {
			$this->_save_wpmu_options($_POST);
		} else {
			$this->_load_options();
		}
		
		// Since we have no plugin activation hook for WPMU,
		// we do it here (everytime the admin/options page is shown).
		if (IS_WPMU) {
			$this->activate();
		}

?>
<script type="text/javascript">
	jQuery(document).ready(function(){
		jQuery('#slider').tabs({ fxFade: true, fxSpeed: 'fast' });	
	});

	function submitTestForm() {
		openTestWindow();
		return false; // so the form is not submitted
	}

	function openTestWindow() {

		var user = encodeURIComponent(document.getElementById('AD_Integration_test_user').value);
		var password = encodeURIComponent(document.getElementById('AD_Integration_test_password').value);

		TestWindow = window.open("<?php echo ( (IS_WPMU) ? WPMU_PLUGIN_URL : WP_PLUGIN_URL ).'/'.ADINTEGRATION_FOLDER;?>/test.php?user=" + user + "&password=" + password, "Test", "width=450,height=500,left=100,top=200");
		TestWindow.focus();
	}
</script>

<div class="wrap" style="background-image: url('<?php if (IS_WPMU) { echo WPMU_PLUGIN_URL; } else { echo WP_PLUGIN_URL; } echo '/'.basename(dirname(__FILE__)); ?>/ad-integration.png'); background-repeat: no-repeat; background-position: right 100px;">

	<div id="icon-options-general" class="icon32">
		<br/>
	</div>
	<h2><?php if (IS_WPMU) { 
  	_e('Active Directory Integration', 'ad-integration');
  } else {
  	_e('Active Directory Integration Settings', 'ad-integration');
  }?></h2>
  

  	<?php 
  	if (!function_exists('ldap_connect')) {
  		echo '<h3>' . __('ATTENTION: You have no LDAP support. This plugin won´t work.', 'ad-integration') . '</h3>';
  		$this->_log(ADI_LOG_WARN,'No LDAP support.');
  	}
	?>


	<!--  TABS -->

	<div id="slider" class="wrap">
		<ul id="tabs">
			<li><a href="#server"><?php _e('Server', 'ad-integration'); ?></a></li>
			<li><a href="#user"><?php _e('User', 'ad-integration'); ?></a></li>
			<li><a href="#authorization"><?php _e('Authorization', 'ad-integration'); ?></a></li>
			<li><a href="#security"><?php _e('Security', 'ad-integration'); ?></a></li>
			<li><a href="#usermeta"><?php _e('User Meta', 'ad-integration'); ?></a></li>
<?php 
// Test Tool nicht für WordPress MU 
if (!IS_WPMU) { ?>		
			<li><a href="#test"><?php _e('Test Tool', 'ad-integration'); ?></a></li>
<?php } ?>			
		</ul>	

    	<!-- TAB: Server  -->

		<div id="server">
			<form action="<?php if (!IS_WPMU)echo 'options.php#server'; ?>" method="post">
   				<?php settings_fields('ADI-server-settings'); ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td colspan="2"><h2 style="font-size: 150%; font-weight: bold;"><?php _e('Active Directory Server', 'ad-integration'); ?></h2></td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_domain_controllers"><?php _e('Domain Controllers', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_domain_controllers" id="AD_Integration_domain_controllers" class="regular-text" value="<?php echo $this->_domain_controllers; ?>" /><br />
								<?php _e('Domain Controllers (separate with semicolons, e.g. "dc1.domain.tld;dc2.domain.tld")', 'ad-integration'); ?>
							</td>
						</tr>
		
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_port"><?php _e('Port', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_port" id="AD_Integration_port" class="regular-text" 
								value="<?php echo $this->_port; ?>" /><br />
								<?php _e('Port on which the AD listens (defaults to "389")', 'ad-integration'); ?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_use_tls"><?php _e('Use TLS', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_use_tls" id="AD_Integration_use_tls"<?php if ($this->_use_tls) echo ' checked="checked"' ?> value="1" />
								<?php _e('Secure the connection between the WordPress and the Active Directory Servers using TLS. Note: To use TLS, you must set the LDAP Port to 389.', 'ad-integration'); ?>
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_bind_user"><?php _e('Bind User', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_bind_user" id="AD_Integration_bind_user" class="regular-text" 
								value="<?php echo $this->_bind_user; ?>" /><br />
								<?php _e('Username for non-anonymous requests to AD (e.g. "ldapuser@domain.tld"). Leave empty for anonymous requests.', 'ad-integration'); ?>
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_bind_pwd"><?php _e('Bind User Password', 'ad-integration'); ?></label></th>
							<td>
							<input type="password" name="AD_Integration_bind_pwd" id="AD_Integration_bind_pwd" class="regular-text" 
								value="<?php echo $this->_bind_pwd; ?>" /><br />
								<?php _e('Password for non-anonymous requests to AD', 'ad-integration'); ?>
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_base_dn"><?php _e('Base DN', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_base_dn" id="AD_Integration_base_dn" class="regular-text" 
								value="<?php echo $this->_base_dn; ?>" /><br />
								<?php _e('Base DN (e.g., "ou=unit,dc=domain,dc=tld")', 'ad-integration'); ?>
							</td>
						</tr>
					</tbody>
				</table>
				<p class="submit">
					<input type="submit" class="button-primary" name="Submit" value="<?php _e("Save Changes"); ?>" />
				</p>
			</form>	    	
		</div>	<!-- END OF TAB SERVER -->
		

		<!-- TAB: User -->

		<div id="user">
		
			<form action="<?php if (!IS_WPMU)echo 'options.php#user'; ?>" method="post">
   				<?php settings_fields('ADI-user-settings'); ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td colspan="2"><h2 style="font-size: 150%; font-weight: bold;"><?php _e('User specific settings','ad-integration'); ?></h2></td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_auto_create_user"><?php _e('Automatic User Creation', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_auto_create_user" id="AD_Integration_auto_create_user" <?php if ($this->_auto_create_user) echo ' checked="checked"' ?> value="1" />
								<?php _e('Should a new user be created automatically if not already in the WordPress database?','ad-integration'); ?>
								<br />
								<?php _e('Created users will obtain the role defined under "New User Default Role" on the <a href="options-general.php">General Options</a> page.', 'ad-integration'); ?>
								<br/>
								<?php _e('This setting is separate from the Role Equivalent Groups option, below.', 'ad-integration'); ?>
								<br />
								
								<?php _e("<b>Users with role equivalent groups will be created even if this setting is turned off</b> (because if you didn't want this to happen, you would leave that option blank.)", 'ad-integration'); ?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_auto_update_user"><?php _e('Automatic User Update', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_auto_update_user" id="AD_Integration_auto_update_user" <?php if ($this->_auto_update_user) echo ' checked="checked"' ?> value="1" />          
								<?php _e('Should the users be updated in the WordPress database everytime they logon?<br /><b>Works only if Automatic User Creation is turned on.</b>', 'ad-integration'); ?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_auto_update_description"><?php _e('Auto Update User Description', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_auto_update_description" id="AD_Integration_auto_update_description" <?php if ($this->_auto_update_description) echo ' checked="checked"' ?> value="1" />          
								<?php _e('Should the users descriptions be updated in the WordPress database everytime they logon?<br /><b>Works only if Automatic User Creation <b>and</b> Automatic User Update is turned on.</b>', 'ad-integration'); ?>
							</td>						
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_default_email_domain"><?php _e('Default email domain', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_default_email_domain" id="AD_Integration_default_email_domain" class="regular-text" value="<?php echo $this->_default_email_domain; ?>" /><br />
								<?php _e("If the Active Directory attribute 'mail' is blank, a user's email will be set to username@whatever-this-says", 'ad-integration'); ?>
							</td>
						</tr>
						
						<tr valign="top">
						<th scope="row"><label for="AD_Integration_duplicate_email_prevention"><?php _e('Email Address Conflict Handling', 'ad-integration'); ?></label></th>
							<td>
								<select name="AD_Integration_duplicate_email_prevention" id="AD_Integration_duplicate_email_prevention">
									<option value="<?php echo ADI_DUPLICATE_EMAIL_ADDRESS_PREVENT;?>"<?php if (($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_PREVENT) OR ($this->_display_name == '')) echo ' selected="selected"' ?>><?php _e('Prevent (recommended)', 'ad-integration'); ?></option>
									<option value="<?php echo ADI_DUPLICATE_EMAIL_ADDRESS_ALLOW;?>"<?php if (($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_ALLOW) OR ($this->_display_name == '')) echo ' selected="selected"' ?>><?php _e('Allow (UNSAFE)', 'ad-integration'); ?></option>
									<option value="<?php echo ADI_DUPLICATE_EMAIL_ADDRESS_CREATE;?>"<?php if (($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_CREATE) OR ($this->_display_name == '')) echo ' selected="selected"' ?>><?php _e('Create', 'ad-integration'); ?></option>
								</select>
								<?php _e("Choose how to handle email address conflicts.", 'ad-integration'); ?><br />
								<ul style="list-style-type:disc; margin-left:2em;font-size:11px;">
									<li><?php _e('Prevent: User is not created, if his email address is already in use by another user. (recommended)', 'ad-integration'); ?></li>
									<li><?php _e('Allow: Allow users to share one email address. (UNSAFE)', 'ad-integration'); ?></li>
									<li><?php _e('Create: In case of conflict, the new user is created with a unique email address.', 'ad-integration'); ?></li>
								</ul>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_account_suffix"><?php _e('Account Suffix', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_account_suffix" id="AD_Integration_account_suffix" class="regular-text" value="<?php echo $this->_account_suffix; ?>" /><br />
								<?php _e('Account Suffix (will be appended to all usernames in the Active Directory authentication process; e.g., "@domain.tld".)', 'ad-integration'); ?>
								<br />
								<br />
								<input type="checkbox" name="AD_Integration_append_suffix_to_new_users" id="AD_Integration_append_suffix_to_new_users"<?php if ($this->_append_suffix_to_new_users) echo ' checked="checked"' ?> value="1" />
								<label for="AD_Integration_append_suffix_to_new_users"><?php _e('Append account suffix to new created usernames. If checked, the account suffix (see above) will be appended to the usernames of new created users.', 'ad-integration'); ?></label>
							</td>
						</tr>

						<tr valign="top">
						<th scope="row"><label for="AD_Integration_display_name"><?php _e('Display name', 'ad-integration'); ?></label></th>
							<td>
								<select name="AD_Integration_display_name" id="AD_Integration_display_name">
									<?php _e('LDAP Attribute: ','ad-integration');?>
									<option value="samaccountname"<?php if (($this->_display_name == 'samaccountname') OR ($this->_display_name == '')) echo ' selected="selected"' ?>><?php _e('sAMAccountName (the username)', 'ad-integration'); ?></option>
									<option value="displayname"<?php if ($this->_display_name == 'displayname') echo ' selected="selected"' ?>><?php _e('displayName', 'ad-integration'); ?></option>
									<option value="description"<?php if ($this->_display_name == 'description') echo ' selected="selected"' ?>><?php _e('description', 'ad-integration'); ?></option>
									<option value="givenname"<?php if ($this->_display_name == 'givenname') echo ' selected="selected"' ?>><?php _e('givenName (firstname)', 'ad-integration'); ?></option>
									<option value="sn"<?php if ($this->_display_name == 'sn') echo ' selected="selected"' ?>><?php _e('SN (lastname)', 'ad-integration'); ?></option>
									<option value="cn"<?php if ($this->_display_name == 'cn') echo ' selected="selected"' ?>><?php _e('CN (Common Name, the whole name)', 'ad-integration'); ?></option>
									<option value="mail"<?php if ($this->_display_name == 'mail') echo ' selected="selected"' ?>><?php _e('mail', 'ad-integration'); ?></option>
								</select>
								<?php _e("Choose user's Active Directory attribute to be used as display name.", 'ad-integration'); ?>
							</td>
						</tr>
		
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_enable_password_change"><?php _e('Enable local password changes', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_enable_password_change" id="AD_Integration_enable_password_change" <?php if ($this->_enable_password_change) echo ' checked="checked"' ?> value="1" />          
								<label for="AD_Integration_enable_password_change"><?php _e('Allow users to change their local (<strong>non AD</strong>) WordPress password', 'ad-integration'); ?>
								<br/>
								<?php _e('<strong>If activated, a password change will update the local WordPress database only. No changes in Active Directory will be made.</strong>', 'ad-integration'); ?>
								</label>          
							</td>
						</tr>
						
					</tbody>
				</table>
				<p class="submit">
					<input type="submit" class="button-primary" name="Submit" value="<?php _e("Save Changes"); ?>" />
				</p>
			</form>
		</div> <!-- END OF TAB USER -->	


		<!-- TAB: Authorization -->
		
		<div id="authorization">
			<form action="<?php if (!IS_WPMU)echo 'options.php#authorization'; ?>" method="post">
   				<?php settings_fields('ADI-auth-settings'); ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td scope="col" colspan="2"><h2 style="font-size: 150%; font-weight: bold;"><?php _e('Authorization','ad-integration'); ?></h2></td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_authorize_by_group"><?php _e('Authorize by group membership','ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_authorize_by_group" id="AD_Integration_authorize_by_group"<?php if ($this->_authorize_by_group) echo ' checked="checked"' ?> value="1" />
								<?php _e('Users are authorized for login only when they are members of a specific AD group.','ad-integration'); ?>
								<br />
								<label for="AD_Integration_authorization_group"><?php _e('Group(s)','ad-integration'); ?>: </label>
								<input type="text" name="AD_Integration_authorization_group" id="AD_Integration_authorization_group" class="regular-text"
								value="<?php echo $this->_authorization_group; ?>" /><br />
								<?php _e('Seperate multiple groups by semicolon (e.g. "domain-users;WP-Users;test-users").', 'ad-integration'); ?>

							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_role_equivalent_groups"><?php _e('Role Equivalent Groups', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_role_equivalent_groups" id="AD_Integration_role_equivalent_groups" class="regular-text" 
								value="<?php echo $this->_role_equivalent_groups; ?>" /><br />
								<?php _e('List of Active Directory groups which correspond to WordPress user roles.', 'ad-integration'); ?><br/>
								<?php _e('When a user is first created, his role will correspond to what is specified here.<br/>Format: AD-Group1=WordPress-Role1;AD-Group1=WordPress-Role1;...<br/> E.g., "Soc-Faculty=faculty" or "Faculty=faculty;Students=subscriber"<br/>A user will be created based on the first math, from left to right, so you should obviously put the more powerful groups first.', 'ad-integration'); ?><br/>
								<?php _e('NOTES', 'ad-integration'); ?>
								<ol style="list-style-type:decimal; margin-left:2em;font-size:11px;">
									<li><?php _e('WordPress stores roles as lower case ("Subscriber" is stored as "subscriber")', 'ad-integration'); ?></li>
									<li><?php _e('Active Directory groups are case-sensitive.', 'ad-integration'); ?></li>
									<li><?php _e('Group memberships cannot be checked across domains.  So if you have two domains, instr and qc, and qc is the domain specified above, if instr is linked to qc, I can authenticate instr users, but not check instr group memberships.', 'ad-integration'); ?></li>
								</ol>
							</td>
						</tr>
					</tbody>
				</table>
				<p class="submit">
					<input type="submit" class="button-primary" name="Submit" value="<?php _e("Save Changes"); ?>" />
				</p>
			</form>	    	
		</div> <!-- END OF TAB AUTHORIZATION -->	
			
		<!-- TAB: Security -->			

		<div id="security">
			<form action="<?php if (!IS_WPMU)echo 'options.php#security'; ?>" method="post">
   				<?php settings_fields('ADI-security-settings'); ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td scope="col" colspan="2">
								<h2 style="font-size: 150%; font-weight: bold;"><?php _e('Brute Force Protection','ad-integration'); ?></h2>
								<?php _e('For security reasons you can use the following options to prevent brute force attacks on your user accounts.','ad-integration'); ?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_max_login_attempts"><?php _e('Maximum number of allowed login attempts', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_max_login_attempts" id="AD_Integration_max_login_attempts"  
								value="<?php echo $this->_max_login_attempts; ?>" /><br />
								<?php _e('Maximum number of failed login attempts before a user account is blocked. If empty or "0" Brute Force Protection is turned off.', 'ad-integration'); ?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_block_time"><?php _e('Blocking Time', 'ad-integration'); ?></label></th>
							<td>
								<input type="text" name="AD_Integration_block_time" id="AD_Integration_block_time"  
								value="<?php echo $this->_block_time; ?>" /><br />
								<?php _e('Number of seconds an account is blocked after the maximum number of failed login attempts is reached.', 'ad-integration'); ?>
							</td>
						</tr>
					
						<tr valign="top">
						<th scope="row"><label for="AD_Integration_user_notification"><?php _e('User Notification', 'ad-integration'); ?></label></th>
						<td>
								<input type="checkbox" name="AD_Integration_user_notification" id="AD_Integration_user_notification"<?php if ($this->_user_notification) echo ' checked="checked"' ?> value="1" />  
								<?php _e('Notify user by e-mail when his account is blocked.', 'ad-integration'); ?>
						</td>
						</tr>
					
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_admin_notification"><?php _e('Admin Notification', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_admin_notification" id="AD_Integration_admin_notification"<?php if ($this->_admin_notification) echo ' checked="checked"' ?> value="1" />  
								<?php _e('Notify admin(s) by e-mail when an user account is blocked.', 'ad-integration'); ?>
								<br />
								<?php _e('E-mail addresses for notifications:','ad-integration');?>
								<input type="text" name="AD_Integration_admin_email" id="AD_Integration_admin_email" class="regular-text"  
								value="<?php echo $this->_admin_email; ?>" />
								<br />
								<?php _e('Seperate multiple addresses by semicolon (e.g. "admin@domain.tld;me@mydomain.tld"). If left blank, notifications will be sent to the blog-administrator only.', 'ad-integration'); ?>
							</td>
						</tr>
					</tbody>
				</table>
				<p class="submit">
					<input type="submit" class="button-primary" name="Submit" value="<?php _e("Save Changes"); ?>" />
				</p>
			</form>	    	
		</div> <!-- END OF TAB SECURITY -->	

		<!-- TAB: User Meta -->
		
		<?php 
		$descriptions = $this->_get_attribute_descriptions();
		?>
		
		<div id="usermeta">
			<form action="<?php if (!IS_WPMU)echo 'options.php#usermeta'; ?>" method="post">
   				<?php settings_fields('ADI-usermeta-settings'); ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td scope="col" colspan="2">
								<h2 style="font-size: 150%; font-weight: bold;"><?php _e('User Meta','ad-integration'); ?></h2>
								<?php _e('User attributes from the AD are stored as User Meta Data. You can use these attributes in your themes and they can be shown on the profile page of your users.','ad-integration'); ?>
								<?php _e('The attributes are only stored in the WordPress database if you activate "Automatic User Creation" and are only updated if you activate "Automatic User Update" on tab "User".','ad-integration'); ?>
							</td>
						</tr>
						
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_show_attributes"><?php _e('Show Attributes', 'ad-integration'); ?></label></th>
							<td>
								<input type="checkbox" name="AD_Integration_show_attributes" id="AD_Integration_show_attributes"<?php if ($this->_show_attributes) echo ' checked="checked"' ?> value="1" />  
								<?php _e('Show user attributes from AD in user profile.', 'ad-integration'); ?>
							</td>
						</tr>
						

						<tr valign="top">
							<th scope="row"><label for="AD_Integration_attributes_to_show"><?php _e('Attributes to show', 'ad-integration'); ?></label></th>
							<td>
								<?php _e('Enter the AD attributes (one per line) to be shown at the end of the user profile page.', 'ad-integration'); ?>
								<?php _e('See the list below for possible default values.', 'ad-integration'); ?>
								<?php _e('If you enter something that is not in the list of attributes it will be treated as a headline. Use this to structure the output.', 'ad-integration'); ?>
								<br/>
								<textarea name="AD_Integration_attributes_to_show" id="AD_Integration_attributes_to_show"><?php echo $this->_attributes_to_show; ?></textarea>
							</td>
						</tr>
						
						<tr valign="top">
							<th scope="row"><label for="AD_Integration_additional_user_attributes"><?php _e('Additional User Attributes', 'ad-integration'); ?></label></th>
							<td>
								<?php _e('Enter additional AD attributes (one per line), followed by their type and description seperated by a colon (:).', 'ad-integration'); ?>
								<?php _e('Additional Attributes that should appear on the user profile must also be placed in "Attributes to show".', 'ad-integration'); ?>
								<?php _e('Format: <i>attribute_name:type:description</i> where <i>type</i> can be one of the following: <i>string, integer, bool, octet, time, timestamp</i>.', 'ad-integration'); ?><br/>
								<?php _e('Example:<br/><i>lastlogon:timestamp:Last logon on<br/>whencreated:time:User Created on</i>', 'ad-integration'); ?>
								<br/>
								<textarea name="AD_Integration_additional_user_attributes" id="AD_Integration_additional_user_attributes"><?php echo $this->_additional_user_attributes; ?></textarea>
								<br/>
								<?php _e('Notice: Attributes of type <i>octet</i> are stored base64 encoded.', 'ad-integration'); ?>
							</td>
						</tr>
						
						<tr valign="top">
							<th scope="row"><?php _e('Default attributes', 'ad-integration'); ?></label></th>
							<td>
								<table class="attribute_descriptions">
									<tr>
										<th><?php _e('AD Attribute','ad-integration');?></th>
										<th><?php _e('Desription','ad-integration');?></th>
									</tr>
								<?php 
								foreach($descriptions AS $attribute => $description) {?>
									<tr>
										<th><?php echo $attribute; ?></th>
										<td><?php echo $description; ?></td>
									</tr>	
								<?php } ?>
								</table>
							</td>
						</tr>
					</tbody>
				</table>
				
				<p class="submit">
					<input type="submit" class="button-primary" name="Submit" value="<?php _e("Save Changes"); ?>" />
				</p>
			</form>	    	
		</div> <!-- END OF TAB USER META -->	
		
		<!-- TAB: Test -->
		
		<div id="test">
			<form onsubmit="return submitTestForm();">
				<table class="form-table">
					<tbody>
						<tr>
							<td scope="col" colspan="2">
								<h2 style="font-size: 150%; font-weight: bold;"><?php _e('Test Tool','ad-integration'); ?></h2>
								<p><?php _e('Enter a username and password to test logon. If you click the button below, a new window with detailed debug information opens. <strong>Be sure, that no unauthorized person can see the output, because passwords will be shown in plaintext.</strong>','ad-integration'); ?></p>
							</td>
						</tr>
	
						<tr valign="top">
							<th scope="row">
								<label for="AD_Integration_test_user"><?php _e('Username','ad-integration'); ?></label>
							</th>
							<td>
								<input type="text" name="AD_Integration_test_user" id="AD_Integration_test_user" class="regular-text" />  
							</td>
						</tr>
						
						<tr valign="top">
							<th scope="row">
								<label for="AD_Integration_test_password"><?php _e('Password','ad-integration'); ?></label>
							</th>
							<td>
								<input type="password" name="AD_Integration_test_password" id="AD_Integration_test_password" class="regular-text" />  
							</td>
						</tr>
					</tbody>
				</table>
				<p class="submit">
					<input type="submit" class="button-primary" name="Submit" value="<?php _e('Perform Test','ad-integration'); ?>" />
				</p>
			</form>				
		</div> <!-- END OF TAB TEST -->	
	</div>
</div>