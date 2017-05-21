<?php
/**
 * Class GenericOpenIDConnectTest
 *
 * @package Generic_Openid_Connect
 */

class GenericOpenIDConnectTest extends WP_UnitTestCase {

	function setUp() {
		$this->oic = new GenericOpenIDConnect();
	}

	// use redirect_url for callback from IDP
	function test_constructor() {
		$this->assertSame(
			'http://example.org/wp-admin/admin-ajax.php?action=openidconn-callback',
			$this->oic->redirect_url
		);
	}

	function test_create_admin_menu() {
		$expected = <<<EOT
<div class="wrap"><!-- Screen icons are no longer used as of WordPress 3.8. -->    <h2>Generic OpenID Connect</h2>    <form method="post" action="options.php"><input type='hidden' name='option_page' value='openid_connect_option_group' /><input type="hidden" name="action" value="update" /><input type="hidden" id="_wpnonce" name="_wpnonce" value="31c52c8bd2" /><input type="hidden" name="_wp_http_referer" value="" /><p class="submit"><input type="submit" name="submit" id="submit" class="button button-primary" value="Save Changes"  /></p>    </form></div>
EOT;
		//$this->assertEquals($this->expectOutputString($expected), $this->oic->create_admin_menu());
	}

	function test_print_bool_field() {
		$this->oic->key = 1;
		$this->assertEquals(
			$this->expectOutputString('<input type="checkbox" id="key" name="array_key[key]" value="1" checked="checked">'),
			$this->oic->print_bool_field("key")
		);
	}

	function test_print_bool_field_failure() {
		try {
			$this->oic->print_bool_field("not-exist-key");
			$this->fail('not occur');
		}catch(Exception $e) {
			$this->assertEquals('Undefined property: GenericOpenIDConnect::$not-exist-key', $e->getMessage());
			$this->assertEquals(8, $e->getCode());
		}
	}

	// if plugin-error given, display error message from array $ERR_MES
	function test_login_init_failure() {
		$_GET['plugin-error'] = 1;
		$expected = <<<EOT
<div style="padding:10px;background-color:#FFDFDD;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><p style="line-height:1.6em;"><strong>Error!</strong>&nbsp;Cannot get authorization response</p></div><br>
EOT;
		$this->assertEquals($this->expectOutputString($expected), $this->oic->login_init());
	}

	function test_openid_connect_section_info() {
		$expected = '<p>Enter your OpenID Connect Idp settings</p>';
		$this->assertEquals($this->expectOutputString($expected), $this->oic->openid_connect_section_info());
	}

	function test_openid_connect_app_settings_section_info() {
		$expected = 'Limit account names to allow authorization by regex';
		$this->assertEquals($this->expectOutputString($expected), $this->oic->openid_connect_app_settings_section_info());
	}
}
