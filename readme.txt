=== Plugin Name ===
Contributors: shirounagi
Tags: security, login, oauth2, openidconnect, apps, authentication, autologin
Requires at least: 3.0.1
Tested up to: 3.8.2
Stable tag: 1.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Provides automatic authentication against OpenID Connect API.

== Description ==

This plugin allows to authenticate users against OpenID Connect OAuth2 API with Authorization Code Flow.
Once installed and properly configured, it will start redirecting to IdP consent page. After consent
has been obtained, user is automatically created in WordPress database.


== Installation ==

- Upload `generic-openid-connect.php` to the `/wp-content/plugins/` directory

- Activate the plugin through the 'Plugins' menu in WordPress

- IdP Endpoint URL, Client ID, Client Secret values you'll need to copy-paste into 
respective fields on the plugin settings page.


== Frequently Asked Questions ==

Nothing has been asked yet.


== Changelog ==

= 1.0 =
First version

