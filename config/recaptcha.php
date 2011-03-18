<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * reCAPTCHA configuration.
 * Get your private and public key at www.recaptcha.com
 *
 * Kohana v2.3.x port programmed by Robert Genito <rgenito@proteushosting.net>
 */

$config['public_key']  = '';
$config['private_key'] = '';

// set to true or false to use recaptcha's secure server. default value is below.
$config['use_ssl']     = false;

?>
