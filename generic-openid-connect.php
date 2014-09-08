<?php
/*
Plugin Name: Generic OpenID Connect
Plugin URI: https://github.com/unagi/wp-generic-openid-connect
Description:  Connect to OpenID Connect IdP with Authorization Code Flow
Version: 1.0
Author: shirounagi
Author URI: https://github.com/unagi
License: GPLv2 Copyright (c) 2014 shirounagi
Text Domain: generic-openid-connect
Domain Path: /language
*/

class GenericOpenIDConnect {

	/* Plugin identifer */
	const PLUGIN_ID = 'gen_openid_con';
	const PLUGIN_LONG_ID = 'generic-openid-connect';

	/* config parameters on admin page */
	static $PARAMETERS = array(
		'ep_login' => 'Login Endpoint URL', self::PLUGIN_ID,
		'ep_token' => 'Token Validation Endpoint URL',
		'ep_userinfo' => 'Userinfo Endpoint URL',
		'client_id' => 'Client ID',
		'client_secret' => 'Client Secret Key',
		'use_autologin' => '',
		'allowed_regex' => ''
	);

	static $ERR_MES = array(
		1 => 'Cannot get authorization response',
		2 => 'Cannot get token response',
		3 => 'Cannot get valid access token',
		4 => 'Cannot get user claims',
		5 => 'Cannot create authorized user',
		6 => 'User creation failed',
		99 => 'Unknown error'
	);

	public function __construct() {
		add_action( 'login_form', array( &$this, 'login_form' ) );
		if ( is_admin() ) {
			//AJAX stuff
			add_action( 'wp_ajax_openidconn-callback', array( $this, 'callback' ) );
			add_action( 'wp_ajax_nopriv_openidconn-callback', array( $this, 'callback' ) );
			
			add_action( 'admin_menu', array( $this, 'admin_menu' ) );
			add_action( 'admin_init', array( $this, 'admin_init' ) );
		}

		foreach ( self::$PARAMETERS as $key => $val ) {
			$this->$key = get_option( self::PLUGIN_ID . '_' . $key );
		}
		$this->redirect_url = admin_url( 'admin-ajax.php?action=openidconn-callback' );
	}

	/**
	 * handles the callback and authenticates against OpenID Connect API.
	 * 
	 * performed by wp_ajax*_callback action
	 *
	 */
	public function callback() {
		if ( !isset( $_GET['code'] ) ) {
			// ERR01: cannot get authorization response
			wp_redirect( wp_login_url() . '?plugin-error=1' );
		} elseif ( isset( $_GET['error'] ) ) {
			// ERR99: unknown error
			wp_redirect( wp_login_url() . '?plugin-error=99' );
		}

		$oauth_result = wp_remote_post( $this->ep_token, array(
				'body' => array(
					'code'          => $_GET['code'],
					'client_id'     => $this->client_id,
					'client_secret' => $this->client_secret,
					'redirect_uri'  => $this->redirect_url,
					'grant_type'    => 'authorization_code'
				)
		));
		if ( is_wp_error( $oauth_result ) ) {
			// ERR02: cannot get token response
			wp_redirect( wp_login_url() . "?plugin-error=2" );
		}
		$oauth_response = json_decode( $oauth_result['body'], true );
		if ( !isset( $oauth_response['access_token'] ) ) {
			// ERR03: cannot get valid access token
			wp_redirect( wp_login_url() . "?plugin-error=3" );
		}

		$oauth_id_token = $oauth_response['id_token'];
		$idtoken_validation_result = wp_remote_get( $this->ep_userinfo . '?id_token=' . $oauth_id_token);

		if( is_wp_error($idtoken_validation_result)) {
			// ERR04: cannot get user claim
			wp_redirect( wp_login_url() . "?plugin-error=4" );
		}
		$oauth_expiry     = $oauth_response['expires_in'] + current_time( 'timestamp', true );
		$idtoken_response = json_decode($idtoken_validation_result['body'], true);
		$user_id   = $idtoken_response['email'];

		setcookie( self::PLUGIN_ID . '_id_token', $oauth_id_token, $oauth_expiry, COOKIEPATH, COOKIE_DOMAIN );
		setcookie( self::PLUGIN_ID . '_username', $user_id,  ( time() + ( 86400 * 7) ), COOKIEPATH, COOKIE_DOMAIN );
		$user = get_user_by( 'login', $user_id );
		if (! isset( $user->ID ) ) {
			// challenge user create
			if ( strlen( $this->allowed_regex ) > 0 && preg_match( $this->allowed_regex, $username ) ===  1) {
				$user_id = wp_create_user( $username, wp_generate_password( 12, false ), $username);
				$user = get_user_by( 'id', $user_id );
			} else {
				// ERR05: cannot create authorized user
				wp_redirect( wp_login_url() . '?plugin-error=5&authed_username=' . $oauth_username );
			}
			if (! isset( $user->ID ) ) {
				// ERR06: user creation failed
				wp_redirect( wp_login_url() . '?plugin-error=6&authed_username=' . $oauth_username );
			}
		}

		if ( !get_user_meta( $user->ID, 'openid-connect-user', true ) ) {
			add_user_meta( $user->ID, 'openid-connect-user', true, true );
		}

		wp_set_auth_cookie( $user->ID, false );
		wp_redirect( home_url() );
	}

	/**
	 * logout method - called from wp_logout action
	 *
	 * @return void
	 */
	public function launchkey_logout() {
		setcookie( self::PLUGIN_ID . '_id_token', '1', 0, COOKIEPATH, COOKIE_DOMAIN );
		setcookie( self::PLUGIN_ID . '_username', '1', 0, COOKIEPATH, COOKIE_DOMAIN );
	}

	/**
	 * page init function - called from admin_init
	 * 
	 * this function is called before anything else is done on the admin page.
	 * 
	 * 1. Checks if OAuth ID token has expired
	 * 2. Uses refresh token from session to revalidate ID token
	 * 3. On failure, logs user out of Wordpress
	 */
	public function is_valid_id_token() {
		$is_openid_connect_user = get_user_meta( wp_get_current_user()->ID, 'openid-connect-user', true );
		
		if ( is_user_logged_in() && $is_openid_connect_user != '' && ! isset( $_COOKIE[self::PLUGIN_ID . '_id_token'] ) ) {
			wp_logout();
			wp_redirect( wp_login_url() );
			exit;
		}
	}

	/**
	 * check_option - used by launchkey_page_init
	 * @return array
	 */
	public function check_option( $input ) {

		$options = array();
		foreach ( self::$PARAMETERS as $key => $val ) {
			if ( $key == 'use_autologin' ) {
				$use_autologin = isset( $input['use_autologin'] );
				$this->update_option_item( 'use_autologin', $use_autologin );
				array_push( $options, $use_authlogin );
			} else {
				array_push( $options, $this->check_option_item($key, $input) );
			}
		}
		return $options;
	}

	private function check_option_item( $key, &$input ) {
		if ( isset( $input[$key] ) ) {
			$value = trim( $input[$key] );
			$this->update_option_item( $key, trim( $value ) );
		} else {
			$value = '';
		}
		return $value;
	}

	private function update_option_item($key, $value) {
		if ( get_option( self::PLUGIN_ID . '_' . $key ) === FALSE ) {
			add_option( self::PLUGIN_ID . '_' . $key , $value );
		} else {
			update_option( self::PLUGIN_ID . '_' . $key , $value );
		}
	}

	/**
	 * create_admin_menu - used by launchkey_plugin_page
	 */
	public function create_admin_menu() {
		echo '<div class="wrap">';
		screen_icon();
		echo '    <h2>Generic OpenID Connect</h2>';
		echo '    <form method="post" action="options.php">';
		settings_fields( 'openid_connect_option_group' );
		do_settings_sections( 'openid-connect-setting-admin' );
		submit_button();
		echo '    </form>';
		echo '</div>';
	}

	public function print_text_field($args) {
		list($key, $css_class, $add_opt) = $args;
		echo '<input type="text" id="' . $key . '" class="' . $css_class . '" name="array_key[' . $key . ']" value="' . $this->$key . '" ' . $add_opt . '>';
	}

	public function create_use_autologin_field() {
		echo '<input type="checkbox" id="use_autologin" name="array_key[use_autologin]" value="1" ' . ($this->use_autologin == '1' ? 'checked="checked"' : '' ) . '>';
	}

	/**
	 * wp-login.php with openid connect
	 *
	 * @access public
	 * @return void
	 */
	public function login_form() {

		if ( isset( $_GET['plugin-error'] ) ) {
			echo $this->styled_error_message( $_GET['plugin-error'] );
		} elseif ( $this->use_autologin && !isset( $_GET['loggedout']) ){
			wp_redirect($this->ep_login . '?response_type=code&client_id=' . urlencode($this->client_id) . '&redirect_uri=' . urlencode($this->redirect_url));
			exit;
		}
	}

	private function style_error_message($errno) {
		$message = self::$ERR_MES[$errno];
		return '<div style="padding:10px;background-color:#FFDFDD;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><p style="line-height:1.6em;"><strong>Error!</strong>&nbsp;' . $message . '</p></div><br>';
	}

	/**
	 * admin_init
	 * 
	 * Invoked by admin_init action
	 */
	public function admin_init() {
		$this->is_valid_id_token();

		register_setting( 'openid_connect_option_group', 'array_key', array( $this, 'check_option' ) );
		
		add_settings_section( 'setting_section_id', 'OpenID Connect API Settings', array( 
				$this,
				'openid_connect_section_info'
			), 'openid-connect-setting-admin');

		add_settings_field( 'use_autologin', 'Activate auto-login',	array( 
				$this,
				'create_use_autologin_field'
			),
			'openid-connect-setting-admin', 'setting_section_id');

		foreach ( self::$PARAMETERS as $key => $description ) {
			if ( in_array( $key, array( 'use_autologin', 'allowed_regex' ) ) ) {
				continue;
			} else {
				add_settings_field( $key, $description, array( $this, 'print_text_field' ), 'openid-connect-setting-admin', 'setting_section_id', array( $key, 'large-text', '' ));
			}
		}
		add_settings_field( 'redirect_url', 'Redirect URL', array( $this, 'print_text_field' ), 'openid-connect-setting-admin', 'setting_section_id', array( 'redirect_url', 'large-text', 'readonly="true"' ));

		add_settings_section( 'app_setting_section_id', 'Authorization Settings', array( 
				$this, 
				'openid_connect_app_settings_section_info' 
			), 'openid-connect-setting-admin');

		add_settings_field( 'allowed_regex', 'Allowed regex', array( $this, 'print_text_field' ),
			'openid-connect-setting-admin', 'app_setting_section_id', array( 'allowed_regex', 'large-text', '' ));
	}

	/**
	 * admin_menu
	 * 
	 * this function is invoked by admin_menu action
	 */
	public function admin_menu() {
		// Plugin Settings page and menu item
		add_options_page( 'OpenID Connect', 'OpenID Connect', 'manage_options', 'openid-connect-setting-admin',
		array( $this, 'create_admin_menu' ) );
	}

	public function openid_connect_section_info() {
		echo '<p>Enter your OpenID Connect Idp settings</p>';
	}

	public function openid_connect_app_settings_section_info() {
		echo 'Limit account names to allow authorization by regex';
	}

}

new GenericOpenIDConnect();
?>
