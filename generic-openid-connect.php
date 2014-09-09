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

	/* config parameters on admin page. */
	static $PARAMETERS = array(
		'use_autologin' => 'Enable SSO',
		'ep_login'      => 'Login Endpoint URL',
		'ep_token'      => 'Token Validation Endpoint URL',
		'ep_userinfo'   => 'Userinfo Endpoint URL',
		'no_sslverify'  => 'Disable SSL Verify',
		'client_id'     => 'Client ID',
		'client_secret' => 'Client Secret Key',
		'scope'         => 'OpenID Scope',
		'identity_key'  => 'Identity Key',
		'allowed_regex' => ''
	);

	static $ERR_MES = array(
		1  => 'Cannot get authorization response',
		2  => 'Cannot get token response',
		3  => 'Cannot get user claims',
		4  => 'Cannot get valid token',
		5  => 'Cannot get user key',
		6  => 'Cannot create authorized user',
		7  => 'User creation failed',
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
			$this->error_redirect(1);
		} elseif ( isset( $_GET['error'] ) ) {
			$this->error_redirect(99);
		}

		$token_result = wp_remote_post(
			$this->ep_token,
			$this->get_wp_request_parameter(array(
				'body' => array(
					'code'          => $_GET['code'],
					'client_id'     => $this->client_id,
					'client_secret' => $this->client_secret,
					'redirect_uri'  => $this->redirect_url,
					'grant_type'    => 'authorization_code'
				)
			)
		));
		if ( is_wp_error( $token_result ) ) {
			$this->error_redirect(2);
		}

		$token_response = json_decode( $token_result['body'], true );
		if ( isset( $token_response['id_token'] ) ) {
			$jwt_arr = explode('.', $token_response['id_token'] );
			$user_claim = json_decode( base64_decode($jwt_arr[1] ), true );
		} elseif ( isset( $token_response['access_token'] ) ){
			$user_claim_result = wp_remote_get(
				$this->ep_userinfo . '?access_token=' . $token_response['access_token'],
				$this->get_wp_request_parameter( array() )
			);
			$user_claim = json_decode($user_claim_result['body'], true);
			if( is_wp_error($user_claim_result)) {
				$this->error_redirect(3);
			}
		} else {
			$this->error_redirect(4);
		}

		$user_id   = $user_claim[$this->identity_key];
		if ( strlen($user_id) == 0 ) {
			$this->error_redirect(5);
		}

		$oauth_expiry = $token_response['expires_in'] + current_time( 'timestamp', true );
		setcookie( self::PLUGIN_ID . '_username', $user_id, $oauth_expiry, COOKIEPATH, COOKIE_DOMAIN );
		$user = get_user_by( 'login', $user_id );
		if (! isset( $user->ID ) ) {
			// challenge user create
			if ( strlen( $this->allowed_regex ) > 0 && preg_match( $this->allowed_regex, $user_id ) ===  1) {
				$uid = wp_create_user( $user_id, wp_generate_password( 12, false ), $user_id );
				$user = get_user_by( 'id', $uid );
			} else {
				$this->error_redirect(6, $user_id);
			}
			if (! isset( $user->ID ) ) {
				$this->error_redirect(7, $user_id);
			}
		}

		if ( !get_user_meta( $user->ID, 'openid-connect-user', true ) ) {
			add_user_meta( $user->ID, 'openid-connect-user', true, true );
		}

		wp_set_auth_cookie( $user->ID, false );
		wp_redirect( home_url() );
	}

	private function get_wp_request_parameter($args) {
		if ( $this->no_sslverify ) {
			$args['sslverify'] = false;
		}
		return $args;
    }

	private function error_redirect($errno, $authed_username='') {
		$url = wp_login_url() . '?plugin-error=' . $errno;
		if ( $authed_username != '' ) {
			$url .= '&authed_username=' . $authed_username;
		}
		wp_redirect( $url );
		exit;
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
		
		if ( is_user_logged_in() && $is_openid_connect_user != '' && ! isset( $_COOKIE[self::PLUGIN_ID . '_username'] ) ) {
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
		foreach ( array_keys( self::$PARAMETERS ) as $key ) {
			if ( in_array($key, array( 'use_autologin', 'no_sslverify') ) ) {
				$value = isset( $input[$key] );
				$this->update_option_item( $key, $value );
				array_push( $options, $value );
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

    public function print_bool_field($key) {
		echo '<input type="checkbox" id="' . $key . '" name="array_key[' . $key . ']" value="1" ' . ($this->$key == '1' ? 'checked="checked"' : '' ) . '>';
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
		} elseif ( $this->use_autologin && !isset( $_GET['loggedout'] ) ){
			wp_redirect( $this->ep_login . '?scope=' . urlencode( $this->scope ) . '&response_type=code&client_id=' . urlencode( $this->client_id ) . '&redirect_uri=' . urlencode( $this->redirect_url ) );
			exit;
		}
	}

	private function styled_error_message($errno) {
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

		foreach ( self::$PARAMETERS as $key => $description ) {
			if ( in_array( $key, array( 'use_autologin', 'no_sslverify' ) ) ) {
				add_settings_field( $key, $description, array( $this, 'print_bool_field' ), 'openid-connect-setting-admin', 'setting_section_id', $key );
			} elseif ( $key == 'redirect_url' ) {
				add_settings_field( $key, $description, array( $this, 'print_text_field' ), 'openid-connect-setting-admin', 'setting_section_id', array( $key, 'large-text', 'readonly="true"' ));
			} elseif ( $key == 'allowed_regex' ) {
				continue;
			} else {
				add_settings_field( $key, $description, array( $this, 'print_text_field' ), 'openid-connect-setting-admin', 'setting_section_id', array( $key, 'large-text', '' ));
			}
		}

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
