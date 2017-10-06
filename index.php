<?php
// This file is part of miniOrange moodle plugin
//
// This plugin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This library is miniOrange SAML Login handler.
 *
 * Redirect here for saml request and response purpose
 *
 * @copyright   2017  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */
require(__DIR__ . '/../../config.php');
require_once('response.php');
require_once('utilities.php');
require_once('assertion.php');
require_once('functions.php');
global $CFG, $USER, $SESSION;
global $_POST, $_GET, $_SERVER;
if (isset($_GET['wantsurl'])) {
    $wantsurl = $SESSION->wantsurl = clean_param($_GET['wantsurl'], PARAM_URL);
}
if (empty($wantsurl) && isset($SESSION->wantsurl)) {
    $wantsurl = $SESSION->wantsurl;
}
$pluginconfig = get_config('auth/mo_saml');
// This condition showing the request for the saml.
// If SAMLResponse is not set or testConfig requested means it will consruct saml request.
if (!isset($_POST['SAMLResponse']) || (isset($_REQUEST['option'])&& $_REQUEST['option'] == 'testConfig')) {
    if ($_REQUEST['option'] == 'testConfig' ) {
        $sendrelaystate = 'testValidate';
        // Checking the purpose of saml request.
    } else if ( isset( $_REQUEST['redirect_to'])) {
        $sendrelaystate = $_REQUEST['redirect_to'];
    } else {
        $sendrelaystate = $CFG->wwwroot.'/auth/mo_saml/index.php';
        // Sendrelaystate set above.
    }
    $ssourl = $pluginconfig->loginurl;
    // Saml login url.
    $acsurl = $CFG->wwwroot.'/auth/mo_saml/index.php';
    // Acs for the plugin.
    $issuer = $CFG->wwwroot;
    // Plugin base url.
    $forceauthn = 'false';
    // Disabled forceauthn.
    $samlrequest = create_authn_request($acsurl, $issuer, $forceauthn);
    // Calling method presentin functions.php for consructing saml request.
    $redirect = $ssourl;
    if (strpos($ssourl, '?') !== false) {
        $redirect .= '&';
    } else {
        $redirect .= '?';
    }
    $redirect .= 'SAMLRequest=' . $samlrequest . '&RelayState=' . urlencode($sendrelaystate);
    // Requested attributes are included.
    header('Location: '.$redirect);
    // Redirecting the login page to IdP login page.
    exit();
}
if ( array_key_exists('SAMLResponse', $_POST) && !empty($_POST['SAMLResponse'])) {
    // Reading saml response and extracting useful data.
    $response = $_POST['SAMLResponse'];
    if (array_key_exists('RelayState', $_POST) && !empty( $_POST['RelayState'] ) && $_POST['RelayState'] != '/') {
        $relaystate = $_POST['RelayState'];
    } else {
        $relaystate = '';
    }
    $response = base64_decode($response);
    // Decoding saml response.
    $document = new DOMDocument();
    // Creating DOMDocument object.
    $document->loadXML($response);
    // Converting saml into readable xml.
    $samlresponsexml = $document->firstChild;
    // This provide first child of xml tree.
    $certfromplugin = $pluginconfig->samlxcertificate;
    // Stored samlxcertificate.
    $certfpfromplugin = xml_security_key::get_raw_thumbprint($certfromplugin);
    $acsurl = $CFG->wwwroot.'/auth/mo_saml/index.php';
    $samlresponse = new saml_response_class($samlresponsexml);
    $responsesignaturedata = $samlresponse->get_signature_data();
    $assertionsignaturedata = current($samlresponse->get_assertions())->get_signature_data();
    $certfpfromplugin = iconv('UTF-8', "CP1252//IGNORE", $certfpfromplugin);
    $certfpfromplugin = preg_replace('/\s+/', '', $certfpfromplugin);
    if (!empty($responsesignaturedata)) {
        $validsignature = utilities::process_response($acsurl, $certfpfromplugin, $responsesignaturedata, $samlresponse);
        if ($validsignature === false) {
            echo 'Invalid signature in the SAML Response.';
            exit;
        }
    }
    if (!empty($assertionsignaturedata)) {
        $validsignature = utilities::process_response($acsurl, $certfpfromplugin, $assertionsignaturedata, $samlresponse);
        if ($validsignature === false) {
            echo 'Invalid signature in the SAML Assertion.';
            exit;
        }
    }
    $issuer = $pluginconfig->samlissuer;
    $spentityid = $CFG->wwwroot;
    utilities::validate_issuer_and_audience($samlresponse, $spentityid, $issuer);
    $ssoemail = current(current($samlresponse->get_assertions())->get_name_id());
    $attrs = current($samlresponse->get_assertions())->get_attributes();
    // All attributes coming from saml.
    $attrs['NameID'] = array("0" => $ssoemail);
    // Setting nameid value.
    $sessionindex = current($samlresponse->get_assertions())->get_session_index();
    $SESSION->mo_saml_attributes = $attrs;
    // Setting coming attributes in session variable.
    $SESSION->mo_saml_nameID = $ssoemail;
    $SESSION->mo_saml_sessionIndex = $sessionindex;
    if ($relaystate == 'testValidate') {
        // Checking relaystate for purpose of saml response.
        mo_saml_checkmapping($attrs, $relaystate, $sessionindex);
        // In this way we are showing saml attributes but do no login.
    } else {
        // This part doing login in moodle via reading, assigning and updating saml user attributes.
        $samlplugin = get_auth_plugin('mo_saml');
        $samluser = $samlplugin->get_userinfo(null);
        $accountmatcher = 'email';
        $USER = auth_mo_saml_authenticate_user_login('email', $samluser, 'true', 'true');
        // This function present in functions.php which basic purpose to return moodle user.
        // If it returns false means moodle user not created.
        if ($USER != false) {
            $USER->loggedin = true;
            $USER->site = $CFG->wwwroot;
            $USER = get_complete_user_data('id', $USER->id);

            // Everywhere we can access user by its id.
            complete_user_login($USER);
            // Here user get login with its all field assigned.
            $SESSION->isSAMLSessionControlled = true;
            // Work of saml response is done here.
            if (isset($wantsurl)) {
                // Need to set wantsurl, where we redirect.
                $urltogo = clean_param($wantsurl, PARAM_URL);
            } else {
                $urltogo = $CFG->wwwroot.'/';
            }
            if (!$urltogo || $urltogo == '') {
                $urltogo = $CFG->wwwroot.'/';
            }
            unset($SESSION->wantsurl);
            redirect($urltogo, 0);
        } else {
            // This block executed only when user is not created.
            print_error('USER is not created.');
        }
    }
}