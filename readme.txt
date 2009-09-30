=== Active Directory Integration ===
Contributors: glatze
Tags: authentication, active directory, ldap, authorization, security
Requires at least: 2.7.1
Tested up to: 2.8.4
Stable tag: 0.9.7

Allows WordPress to authenticate, authorize, create and update users against Active Directory

== Description ==

This Plugin allows WordPress to authenticate, authorize, create and update against an Active Directory Domain.

It is very easy to set up. Just activate the plugin, type in a domain controller, and you're done. But there are more Features:

* authenticate against more than one AD Server
* authorize users by Active Directory group membership
* auto create and update users that can authenticate against AD
* mapping of AD groups to WordPress roles
* use TLS for secure communication to AD Servers (recommended)
* use non standard port for communication to AD Servers
* protection against brute force attacks
* user and/or admin e-mail notification on failed login attempts
* multi-language support (english and german included)
* determine WP display name from AD attributes (sAMAccountName, displayName, description, SN, CN, givenName or mail)


*Active Directory Integration* is based upon Jonathan Marc Bearak's great plugin [Active Directory Authentication](http://wordpress.org/extend/plugins/active-directory-authentication/) and Scott Barnett's [adLDAP](http://adldap.sourceforge.net/), a very useful PHP class.

= Requirements =

* WordPress since 2.7.1 
* PHP 5
* LDAP support
* OpenSSL Support for TLS (recommended)

= Known Issues =
* XMLRPC will only work with WordPress 2.8 and above.
 

== Frequently Asked Questions ==

None... so far.

  
== Installation ==

1. Login as an existing user, such as admin.
1. Upload the folder named `active-directory-integration` to your plugins folder, usually `wp-content/plugins`.
1. Activate the plugin on the Plugins screen.
1. Enable SSL-Admin-Mode by adding the line `define('FORCE_SSL_ADMIN', true);` to your wp-config.php so that your passwords are not sent in plain-text.

== Changelog ==

= 0.9.8-dev =
* NEW: Deactivate Plugin if LDAP support is not installed.
* NEW: New Option "Allow users to change their local WordPress password."
* NEW: Multiple authorization groups (as requested by Lori Dabbs).
* FIX: Added missing CSS file. (Thanks to ajay and BagNin for the bug report.)

= 0.9.7 =
It is highly recommended to update to this version, because of a security vulnerability.
 
* FIX: SECURITY RELEVANT - TLS was not used if you have chosen this option. (Thanks to Jim Carrier for the bug report.)
* ADD: First WordPress MU prototype. Read mu/readme_wpmu.txt for further informations.
* FIX: Usernames will be converted to lower case, because usernames are case sensitive in WordPress but not in Active Directory. (Thanks to Robert Nelson for the bug report.)

= 0.9.6 =
* FIX: With WP 2.8 login screen shows a login error even if there wasn't an attempt zu login and you can not login with local user, as admin.(Thanks to Alexander Liesch and shimh for the bug report.)

= 0.9.5 =
* FIX: "Call to undefined function username_exists()..." fixed, which occurs under some circustances. (Thanks to Alexander Liesch for the bug report.)

= 0.9.4 =
* FIX: XMLRPC now works with WP 2.8 and above. XMLRPC won't work with earlier versions. (Thanks to Alexander Liesch for the bug report.)

= 0.9.3 =
* NEW: determine WP display name from AD attributes
* added template for your own translation (ad-integration.pot)

= 0.9.2 =
* NEW: drop table on deactivation
* NEW: remove options on plugin uninstall
* NEW: contextual help
* colors of logo changed
* code cleanup and beautification

= 0.9.1 =
* NEW: email notification of user and/or admin when a user account is blocked
* object-orientation redesign
* code cleanup
* some minor changes 

= 0.9.0 =
* first published version 