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
 * This library is miniOrange Authentication Service.
 *
 * @copyright   2017  miniOrange
 * @category    authentication
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL v3 or later, see license.txt
 * @package     mo_saml
 */
defined('MOODLE_INTERNAL') || die();
require_once('utilities.php');
/**
 * Auth external functions
 *
 * @package    mo_saml
 * @category   assertion
 * @copyright  2017 miniOrange
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class saml_assertion_class {
    private $id;
    private $issueinstant;
    private $issuer;
    private $nameid;
    private $encryptednameid;
    private $encryptedattribute;
    private $encryptionkey;
    private $notbefore;
    private $notonorafter;
    private $validaudiences;
    private $sessionnotonorafter;
    private $sessionindex;
    private $authninstant;
    private $authncontextclassref;
    private $authncontextdecl;
    private $authncontextdeclref;
    private $authenticatingauthority;
    private $attributes;
    private $nameformat;
    private $signaturekey;
    private $certificates;
    private $signaturedata;
    private $requiredencattributes;
    private $subjectconfirmation;
    protected $wassignedatconstruction = false;
    public function __construct(DOMElement $xml = null) {
        $this->id = utilities::generate_id();
        $this->issueinstant = utilities::generate_timestamp();
        $this->issuer = '';
        $this->authninstant = utilities::generate_timestamp();
        $this->attributes = array();
        $this->nameformat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
        $this->certificates = array();
        $this->authenticatingauthority = array();
        $this->subjectconfirmation = array();

        if ($xml === null) {
            return;
        }

        if ($xml->localName === 'EncryptedAssertion') {
            $data = utilities::xpquery($xml, './xenc:EncryptedData');
            $encryptedmethod = utilities::xpquery($xml, './xenc:EncryptedData/ds:KeyInfo');
            $method = $encryptedmethod[0]->firstChild->firstChild->getAttribute('Algorithm');
            $algo = utilities::get_encryption_algorithm($method);
            if (count($data) === 0) {
                throw new Exception('Missing encrypted data in <saml:EncryptedAssertion>.');
            } else if (count($data) > 1) {
                throw new Exception('More than one encrypted data element in <saml:EncryptedAssertion>.');
            }
            $key = new xml_security_key($algo, array('type' => 'private'));
            $url = plugin_dir_path(__FILE__) . 'resources' . DIRECTORY_SEPARATOR . 'sp-key.key';
            $key->load_key($url, true);
            $alternatekey = new xml_security_key($algo, array('type' => 'private'));
            $alternatekeyurl = plugin_dir_path(__FILE__) . "resources" . DIRECTORY_SEPARATOR . "miniorange_sp_priv_key.key";
            $alternatekey->load_key($alternatekeyurl, true);
            $blacklist = array();
            $xml = utilities::decrypt_element($data[0], $key, $blacklist, $alternatekey);
        }

        if (!$xml->hasAttribute('ID')) {
            throw new Exception('Missing ID attribute on SAML assertion.');
        }
        $this->id = $xml->getAttribute('ID');

        if ($xml->getAttribute('Version') !== '2.0') {
            // Currently a very strict check.
            throw new Exception('Unsupported version: ' . $xml->getAttribute('Version'));
        }

        $this->issueinstant = utilities::xs_date_time_to_timestamp($xml->getAttribute('IssueInstant'));

        $issuer = utilities::xpquery($xml, './saml_assertion:Issuer');
        if (empty($issuer)) {
            throw new Exception('Missing <saml:Issuer> in assertion.');
        }
        $this->issuer = trim($issuer[0]->textContent);
        $this->parse_conditions($xml);
        $this->parse_authn_statement($xml);
        $this->parse_attributes($xml);
        $this->parse_encrypted_attributes($xml);
        $this->parse_signature($xml);
        $this->parse_subject($xml);
    }
    /**
     * Parse subject in assertion.
     *
     * @param DOMElement $xml The assertion XML element.
     * @throws Exception
     */
    private function parse_subject(DOMElement $xml) {
        $subject = utilities::xpquery($xml, './saml_assertion:Subject');
        if (empty($subject)) {
            // No Subject node.

            return;
        } else if (count($subject) > 1) {
            throw new Exception('More than one <saml:Subject> in <saml:Assertion>.');
        }

        $subject = $subject[0];

        $nameid = utilities::xpquery(
            $subject,
            './saml_assertion:NameID | ./saml_assertion:EncryptedID/xenc:EncryptedData'
        );
        if (empty($nameid)) {
            throw new Exception('Missing <saml:NameID> or <saml:EncryptedID> in <saml:Subject>.');
        } else if (count($nameid) > 1) {
            throw new Exception('More than one <saml:NameID> or <saml:EncryptedD> in <saml:Subject>.');
        }
        $nameid = $nameid[0];
        if ($nameid->localName === 'EncryptedData') {
            // The NameID element is encrypted.
            $this->encryptednameid = $nameid;
        } else {
            $this->nameid = utilities::parse_name_id($nameid);
        }
        // Removed code.
    }

    /**
     * Parse conditions in assertion.
     *
     * @param DOMElement $xml The assertion XML element.
     * @throws Exception
     */
    private function parse_conditions(DOMElement $xml) {
        $conditions = utilities::xpquery($xml, './saml_assertion:Conditions');
        if (empty($conditions)) {
            // No saml conditions node.

            return;
        } else if (count($conditions) > 1) {
            throw new Exception('More than one <saml:Conditions> in <saml:Assertion>.');
        }
        $conditions = $conditions[0];

        if ($conditions->hasAttribute('NotBefore')) {
            $notbefore = utilities::xs_date_time_to_timestamp($conditions->getAttribute('NotBefore'));
            if ($this->notbefore === null || $this->notbefore < $notbefore) {
                $this->notbefore = $notbefore;
            }
        }
        if ($conditions->hasAttribute('NotOnOrAfter')) {
            $notonorafter = utilities::xs_date_time_to_timestamp($conditions->getAttribute('NotOnOrAfter'));
            if ($this->notonorafter === null || $this->notonorafter > $notonorafter) {
                $this->notonorafter = $notonorafter;
            }
        }

        for ($node = $conditions->firstChild; $node !== null; $node = $node->nextSibling) {
            if ($node instanceof DOMText) {
                continue;
            }
            if ($node->namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:assertion') {
                throw new Exception('Unknown namespace of condition: ' . var_export($node->namespaceURI, true));
            }
            switch ($node->localName) {
                case 'AudienceRestriction':
                    $audiences = utilities::extract_strings($node, 'urn:oasis:names:tc:SAML:2.0:assertion', 'Audience');
                    if ($this->validaudiences === null) {
                        // The first (and probably last) AudienceRestriction element.
                        $this->validaudiences = $audiences;

                    } else {
                        /*
                         * The set of AudienceRestriction are ANDed together, so we need
                         * the subset that are present in all of them.
                         */
                        $this->validaudiences = array_intersect($this->validaudiences, $audiences);
                    }
                    break;
                case 'OneTimeUse':
                    // Currently ignored.
                    break;
                case 'ProxyRestriction':
                    // Currently ignored.
                    break;
                default:
                    throw new Exception('Unknown condition: ' . var_export($node->localName, true));
            }
        }

    }

    /**
     * Parse AuthnStatement in assertion.
     *
     * @param DOMElement $xml The assertion XML element.
     * @throws Exception
     */
    private function parse_authn_statement(DOMElement $xml) {
        $authnstatements = utilities::xpquery($xml, './saml_assertion:AuthnStatement');
        if (empty($authnstatements)) {
            $this->authninstant = null;

            return;
        } else if (count($authnstatements) > 1) {
            throw new Exception('More that one <saml:AuthnStatement> in <saml:Assertion> not supported.');
        }
        $authnstatement = $authnstatements[0];

        if (!$authnstatement->hasAttribute('AuthnInstant')) {
            throw new Exception('Missing required AuthnInstant attribute on <saml:AuthnStatement>.');
        }
        $this->authninstant = utilities::xs_date_time_to_timestamp($authnstatement->getAttribute('AuthnInstant'));

        if ($authnstatement->hasAttribute('SessionNotOnOrAfter')) {
            $this->sessionnotonorafter = utilities::xs_date_time_to_timestamp($authnstatement->getAttribute('SessionNotOnOrAfter'));
        }

        if ($authnstatement->hasAttribute('SessionIndex')) {
            $this->sessionindex = $authnstatement->getAttribute('SessionIndex');
        }

        $this->parse_authn_context($authnstatement);
    }

    /**
     * Parse AuthnContext in AuthnStatement.
     *
     * @param DOMElement $authnstatementei
     * @throws Exception
     */
    private function parse_authn_context(DOMElement $authnstatementei) {
        // Get the AuthnContext element.
        $authncontexts = utilities::xpquery($authnstatementei, './saml_assertion:AuthnContext');
        if (count($authncontexts) > 1) {
            throw new Exception('More than one <saml:AuthnContext> in <saml:AuthnStatement>.');
        } else if (empty($authncontexts)) {
            throw new Exception('Missing required <saml:AuthnContext> in <saml:AuthnStatement>.');
        }
        $authncontextel = $authncontexts[0];

        // Get the AuthnContextDeclRef (if available).
        $authncontextdeclrefs = utilities::xpquery($authncontextel, './saml_assertion:AuthnContextDeclRef');
        if (count($authncontextdeclrefs) > 1) {
            throw new Exception(
                'More than one <saml:AuthnContextDeclRef> found?'
            );
        } else if (count($authncontextdeclrefs) === 1) {
            $this->set_authn_context_decl_ref(trim($authncontextdeclrefs[0]->textContent));
        }

        // Get the AuthnContextDecl (if available).
        $authncontextdecls = utilities::xpquery($authncontextel, './saml_assertion:AuthnContextDecl');
        if (count($authncontextdecls) > 1) {
            throw new Exception(
                'More than one <saml:AuthnContextDecl> found?'
            );
        } else if (count($authncontextdecls) === 1) {
            $this->set_authn_context_decl(new SAML2_XML_Chunk($authncontextdecls[0]));
        }

        // Get the AuthnContextClassRef (if available).
        $authncontextclassrefs = utilities::xpquery($authncontextel, './saml_assertion:AuthnContextClassRef');
        if (count($authncontextclassrefs) > 1) {
            throw new Exception('More than one <saml:AuthnContextClassRef> in <saml:AuthnContext>.');
        } else if (count($authncontextclassrefs) === 1) {
            $this->set_authn_context_class_ref(trim($authncontextclassrefs[0]->textContent));
        }

        // Constraint from XSD: MUST have one of the three.
        if (empty($this->authncontextclassref) && empty($this->authncontextdecl) && empty($this->authncontextdeclref)) {
            throw new Exception(
                'Missing either <saml:AuthnContextClassRef> or <saml:AuthnContextDeclRef> or <saml:AuthnContextDecl>'
            );
        }

        $this->authenticatingauthority = utilities::extract_strings(
            $authncontextel,
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'authenticatingauthority'
        );
    }

    /**
     * Parse attribute statements in assertion.
     *
     * @param DOMElement $xml The XML element with the assertion.
     * @throws Exception
     */
    private function parse_attributes(DOMElement $xml) {
        $firstattribute = true;
        $attributes = utilities::xpquery($xml, './saml_assertion:AttributeStatement/saml_assertion:Attribute');
        foreach ($attributes as $attribute) {
            if (!$attribute->hasAttribute('Name')) {
                throw new Exception('Missing name on <saml:Attribute> element.');
            }
            $name = $attribute->getAttribute('Name');

            if ($attribute->hasAttribute('NameFormat')) {
                $nameformat = $attribute->getAttribute('NameFormat');
            } else {
                $nameformat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
            }

            if ($firstattribute) {
                $this->nameformat = $nameformat;
                $firstattribute = false;
            } else {
                if ($this->nameformat !== $nameformat) {
                    $this->nameformat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
                }
            }

            if (!array_key_exists($name, $this->attributes)) {
                $this->attributes[$name] = array();
            }

            $values = utilities::xpquery($attribute, './saml_assertion:AttributeValue');
            foreach ($values as $value) {
                $this->attributes[$name][] = trim($value->textContent);
            }
        }
    }

    /**
     * Parse encrypted attribute statements in assertion.
     *
     * @param DOMElement $xml The XML element with the assertion.
     */
    private function parse_encrypted_attributes(DOMElement $xml) {
        $this->encryptedattribute = utilities::xpquery(
            $xml,
            './saml_assertion:AttributeStatement/saml_assertion:EncryptedAttribute'
        );
    }

    /**
     * Parse signature on assertion.
     *
     * @param DOMElement $xml The assertion XML element.
     */
    private function parse_signature(DOMElement $xml) {
        // Validate the signature element of the message.
        $sig = utilities::validate_element($xml);
        if ($sig !== false) {
            $this->wassignedatconstruction = true;
            $this->certificates = $sig['Certificates'];
            $this->signaturedata = $sig;
        }
    }

    /**
     * Validate this assertion against a public key.
     *
     * If no signature was present on the assertion, we will return false.
     * Otherwise, true will be returned. An exception is thrown if the
     * signature validation fails.
     *
     * @param  xml_security_key $key The key we should check against.
     * @return boolean        true if successful, false if it is unsigned.
     */
    public function validate(xml_security_key $key) {
        assert('$key->type === xml_security_key::RSA_SHA1');

        if ($this->signaturedata === null) {
            return false;
        }

        utilities::validate_signature($this->signaturedata, $key);

        return true;
    }

    /**
     * Retrieve the identifier of this assertion.
     *
     * @return string The identifier of this assertion.
     */
    public function get_id() {
        return $this->id;
    }

    /**
     * Set the identifier of this assertion.
     *
     * @param string $id The new identifier of this assertion.
     */
    public function set_id($id) {
        assert('is_string($id)');
        $this->id = $id;
    }

    /**
     * Retrieve the issue timestamp of this assertion.
     *
     * @return int The issue timestamp of this assertion, as an UNIX timestamp.
     */
    public function get_issue_instant() {
        return $this->issueinstant;
    }

    /**
     * Set the issue timestamp of this assertion.
     *
     * @param int $issueinstant The new issue timestamp of this assertion, as an UNIX timestamp.
     */
    public function set_issue_instant($issueinstant) {
        assert('is_int($issueinstant)');

        $this->issueinstant = $issueinstant;
    }

    /**
     * Retrieve the issuer if this assertion.
     *
     * @return string The issuer of this assertion.
     */
    public function get_issuer() {
        return $this->issuer;
    }

    /**
     * Set the issuer of this message.
     *
     * @param string $issuer The new issuer of this assertion.
     */
    public function set_issuer($issuer) {
        assert('is_string($issuer)');

        $this->issuer = $issuer;
    }

    /**
     * Retrieve the NameId of the subject in the assertion.
     *
     * The returned NameId is in the format used by utilities::addNameId().
     *
     * @see utilities::addNameId()
     * @return array|null The name identifier of the assertion.
     * @throws Exception
     */
    public function get_name_id() {
        if ($this->encryptednameid !== null) {
            throw new Exception('Attempted to retrieve encrypted NameID without decrypting it first.');
        }

        return $this->nameid;
    }

    /**
     * Set the NameId of the subject in the assertion.
     *
     * The NameId must be in the format accepted by utilities::addNameId().
     *
     * @see utilities::addNameId()
     * @param array|null $nameid The name identifier of the assertion.
     */
    public function set_name_id($nameid) {
        assert('is_array($nameid) || is_null($nameid)');

        $this->nameid = $nameid;
    }

    /**
     * Check whether the NameId is encrypted.
     *
     * @return true if the NameId is encrypted, false if not.
     */
    public function is_name_id_encrypted() {
        if ($this->encryptednameid !== null) {
            return true;
        }

        return false;
    }

    /**
     * Encrypt the NameID in the Assertion.
     *
     * @param xml_security_key $key The encryption key.
     */
    public function encrypt_name_id(xml_security_key $key) {
        // First create a XML representation of the NameID.
        $doc = new DOMDocument();
        $root = $doc->createElement('root');
        $doc->appendChild($root);
        utilities::addNameId($root, $this->nameid);
        $nameid = $root->firstChild;

        utilities::getContainer()->debugMessage($nameid, 'encrypt');

        // Encrypt the NameID.
        $enc = new xml_sec_enc();
        $enc->set_node($nameid);
        $enc->type = xml_sec_enc::ELEMENT;
        $symmetrickey = new xml_security_key(xml_security_key::AES128_CBC);
        $symmetrickey->generate_session_key();
        $enc->encrypt_key($key, $symmetrickey);
        $this->encryptednameid = $enc->encrypt_node($symmetrickey);
        $this->nameid = null;
    }

    /**
     * Decrypt the NameId of the subject in the assertion.
     *
     * @param xml_security_key $key       The decryption key.
     * @param array          $blacklist Blacklisted decryption algorithms.
     */
    public function decrypt_name_id(xml_security_key $key, array $blacklist = array()) {
        if ($this->encryptednameid === null) {
            // No NameID to decrypt.

            return;
        }

        $nameid = utilities::decrypt_element($this->encryptednameid, $key, $blacklist);
        utilities::getContainer()->debugMessage($nameid, 'decrypt');
        $this->nameid = utilities::parse_name_id($nameid);
        $this->encryptednameid = null;
    }

    /**
     * Decrypt the assertion attributes.
     *
     * @param xml_security_key $key
     * @param array $blacklist
     * @throws Exception
     */
    public function decrypt_attributes(xml_security_key $key, array $blacklist = array()) {
        if ($this->encryptedattribute === null) {
            return;
        }
        $firstattribute = true;
        $attributes = $this->encryptedattribute;
        foreach ($attributes as $attributeenc) {
            // Decrypt node EncryptedAttribute.
            $attribute = utilities::decrypt_element(
                $attributeenc->getElementsByTagName('EncryptedData')->item(0),
                $key,
                $blacklist
            );

            if (!$attribute->hasAttribute('Name')) {
                throw new Exception('Missing name on <saml:Attribute> element.');
            }
            $name = $attribute->getAttribute('Name');

            if ($attribute->hasAttribute('NameFormat')) {
                $nameformat = $attribute->getAttribute('NameFormat');
            } else {
                $nameformat = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
            }

            if ($firstattribute) {
                $this->nameformat = $nameformat;
                $firstattribute = false;
            } else {
                if ($this->nameformat !== $nameformat) {
                    $this->nameformat = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
                }
            }

            if (!array_key_exists($name, $this->attributes)) {
                $this->attributes[$name] = array();
            }

            $values = utilities::xpquery($attribute, './saml_assertion:AttributeValue');
            foreach ($values as $value) {
                $this->attributes[$name][] = trim($value->textContent);
            }
        }
    }

    /**
     * Retrieve the earliest timestamp this assertion is valid.
     *
     * This function returns null if there are no restrictions on how early the
     * assertion can be used.
     *
     * @return int|null The earliest timestamp this assertion is valid.
     */
    public function get_not_before() {
        return $this->notbefore;
    }

    /**
     * Set the earliest timestamp this assertion can be used.
     *
     * Set this to null if no limit is required.
     *
     * @param int|null $notbefore The earliest timestamp this assertion is valid.
     */
    public function set_not_before($notbefore) {
        assert('is_int($notbefore) || is_null($notbefore)');

        $this->notbefore = $notbefore;
    }

    /**
     * Retrieve the expiration timestamp of this assertion.
     *
     * This function returns null if there are no restrictions on how
     * late the assertion can be used.
     *
     * @return int|null The latest timestamp this assertion is valid.
     */
    public function get_not_onor_after() {
        return $this->notonorafter;
    }

    /**
     * Set the expiration timestamp of this assertion.
     *
     * Set this to null if no limit is required.
     *
     * @param int|null $notonorafter The latest timestamp this assertion is valid.
     */
    public function set_not_onor_after($notonorafter) {
        assert('is_int($notonorafter) || is_null($notonorafter)');

        $this->notonorafter = $notonorafter;
    }

    /**
     * Set $EncryptedAttributes if attributes will send encrypted
     *
     * @param boolean $ea true to encrypt attributes in the assertion.
     */
    public function set_encrypted_attributes($ea) {
        $this->requiredencattributes = $ea;
    }

    /**
     * Retrieve the audiences that are allowed to receive this assertion.
     *
     * This may be null, in which case all audiences are allowed.
     *
     * @return array|null The allowed audiences.
     */
    public function get_valid_audiences() {
        return $this->validaudiences;
    }

    /**
     * Set the audiences that are allowed to receive this assertion.
     *
     * This may be null, in which case all audiences are allowed.
     *
     * @param array|null $validaudiences The allowed audiences.
     */
    public function set_valid_audiences(array $validaudiences = null) {
        $this->validaudiences = $validaudiences;
    }

    /**
     * Retrieve the AuthnInstant of the assertion.
     *
     * @return int|null The timestamp the user was authenticated, or null if the user isn't authenticated.
     */
    public function get_authn_instant() {
        return $this->authninstant;
    }


    /**
     * Set the AuthnInstant of the assertion.
     *
     * @param int|null $authninstant Timestamp the user was authenticated, or null if we don't want an AuthnStatement.
     */
    public function set_authn_instant($authninstant) {
        assert('is_int($authninstant) || is_null($authninstant)');

        $this->authninstant = $authninstant;
    }

    /**
     * Retrieve the session expiration timestamp.
     *
     * This function returns null if there are no restrictions on the
     * session lifetime.
     *
     * @return int|null The latest timestamp this session is valid.
     */
    public function get_session_not_onor_after() {
        return $this->sessionnotonorafter;
    }

    /**
     * Set the session expiration timestamp.
     *
     * Set this to null if no limit is required.
     *
     * @param int|null $sessionnotonorafter The latest timestamp this session is valid.
     */
    public function set_session_not_onor_after($sessionnotonorafter) {
        assert('is_int($sessionnotonorafter) || is_null($sessionnotonorafter)');

        $this->sessionnotonorafter = $sessionnotonorafter;
    }

    /**
     * Retrieve the session index of the user at the IdP.
     *
     * @return string|null The session index of the user at the IdP.
     */
    public function get_session_index() {
        return $this->sessionindex;
    }

    /**
     * Set the session index of the user at the IdP.
     *
     * Note that the authentication context must be set before the
     * session index can be inluded in the assertion.
     *
     * @param string|null $sessionindex The session index of the user at the IdP.
     */
    public function set_session_index($sessionindex) {
        assert('is_string($sessionindex) || is_null($sessionindex)');

        $this->sessionindex = $sessionindex;
    }

    /**
     * Retrieve the authentication method used to authenticate the user.
     *
     * This will return null if no authentication statement was
     * included in the assertion.
     *
     * Note that this returns either the AuthnContextClassRef or the AuthnConextDeclRef, whose definition overlaps
     * but is slightly different (consult the specification for more information).
     * This was done to work around an old bug of Shibboleth ( https://bugs.internet2.edu/jira/browse/SIDP-187 ).
     * Should no longer be required, please use either getAuthnConextClassRef or get_authn_context_decl_ref.
     *
     * @deprecated use get_authn_context_class_ref
     * @return string|null The authentication method.
     */
    public function get_authn_context() {
        if (!empty($this->authncontextclassref)) {
            return $this->authncontextclassref;
        }
        if (!empty($this->authncontextdeclref)) {
            return $this->authncontextdeclref;
        }
        return null;
    }

    /**
     * Set the authentication method used to authenticate the user.
     *
     * If this is set to null, no authentication statement will be
     * included in the assertion. The default is null.
     *
     * @deprecated use set_authn_context_class_ref
     * @param string|null $authncontext The authentication method.
     */
    public function set_authn_context($authncontext) {
        $this->set_authn_context_class_ref($authncontext);
    }

    /**
     * Retrieve the authentication method used to authenticate the user.
     *
     * This will return null if no authentication statement was
     * included in the assertion.
     *
     * @return string|null The authentication method.
     */
    public function get_authn_context_class_ref() {
        return $this->authncontextclassref;
    }

    /**
     * Set the authentication method used to authenticate the user.
     *
     * If this is set to null, no authentication statement will be
     * included in the assertion. The default is null.
     *
     * @param string|null $authncontextclassref The authentication method.
     */
    public function set_authn_context_class_ref($authncontextclassref) {
        assert('is_string($authncontextclassref) || is_null($authncontextclassref)');

        $this->authncontextclassref = $authncontextclassref;
    }

    /**
     * Set the authentication context declaration.
     *
     * @param \SAML2_XML_Chunk $authncontextdecl
     * @throws Exception
     */
    public function set_authn_context_decl(SAML2_XML_Chunk $authncontextdecl) {
        if (!empty($this->authncontextdeclref)) {
            throw new Exception(
                'AuthnContextDeclRef is already registered! May only have either a Decl or a DeclRef, not both!'
            );
        }

        $this->authncontextdecl = $authncontextdecl;
    }

    /**
     * Get the authentication context declaration.
     *
     * See:
     * @url http://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
     *
     * @return \SAML2_XML_Chunk|null
     */
    public function get_authn_context_decl() {
        return $this->authncontextdecl;
    }

    /**
     * Set the authentication context declaration reference.
     *
     * @param string $authncontextdeclref
     * @throws Exception
     */
    public function set_authn_context_decl_ref($authncontextdeclref) {
        if (!empty($this->authncontextdecl)) {
            throw new Exception(
                'AuthnContextDecl is already registered! May only have either a Decl or a DeclRef, not both!'
            );
        }

        $this->authncontextdeclref = $authncontextdeclref;
    }

    /**
     * Get the authentication context declaration reference.
     * URI reference that identifies an authentication context declaration.
     *
     * The URI reference MAY directly resolve into an XML document containing the referenced declaration.
     *
     * @return string
     */
    public function get_authn_context_decl_ref() {
        return $this->authncontextdeclref;
    }

    /**
     * Retrieve the authenticatingauthority.
     *
     *
     * @return array
     */
    public function get_authenticating_authority() {
        return $this->authenticatingauthority;
    }

    /**
     * Set the authenticatingauthority
     *
     *
     * @param array.
     */
    public function set_authenticating_authority($authenticatingauthority) {
        $this->authenticatingauthority = $authenticatingauthority;
    }

    /**
     * Retrieve all attributes.
     *
     * @return array All attributes, as an associative array.
     */
    public function get_attributes() {
        return $this->attributes;
    }

    /**
     * Replace all attributes.
     *
     * @param array $attributes All new attributes, as an associative array.
     */
    public function set_attributes(array $attributes) {
        $this->attributes = $attributes;
    }

    /**
     * Retrieve the NameFormat used on all attributes.
     *
     * If more than one NameFormat is used in the received attributes, this
     * returns the unspecified NameFormat.
     *
     * @return string The NameFormat used on all attributes.
     */
    public function get_attribute_name_format() {
        return $this->nameformat;
    }

    /**
     * Set the NameFormat used on all attributes.
     *
     * @param string $nameformat The NameFormat used on all attributes.
     */
    public function set_attribute_name_format($nameformat) {
        assert('is_string($nameformat)');

        $this->nameformat = $nameformat;
    }

    /**
     * Retrieve the subjectconfirmation elements we have in our Subject element.
     *
     * @return array Array of SAML2_XML_saml_SubjectConfirmation elements.
     */
    public function get_subject_confirmation() {
        return $this->subjectconfirmation;
    }

    /**
     * Set the subjectconfirmation elements that should be included in the assertion.
     *
     * @param array $subjectconfirmation Array of SAML2_XML_saml_SubjectConfirmation elements.
     */
    public function set_subject_confirmation(array $subjectconfirmation) {
        $this->subjectconfirmation = $subjectconfirmation;
    }

    /**
     * Retrieve the private key we should use to sign the assertion.
     *
     * @return xml_security_key|null The key, or null if no key is specified.
     */
    public function get_signature_key() {
        return $this->signaturekey;
    }

    /**
     * Set the private key we should use to sign the assertion.
     *
     * If the key is null, the assertion will be sent unsigned.
     *
     * @param xml_security_key|null $signaturekey
     */
    public function set_signature_key(xml_security_key $signaturekey = null) {
        $this->signaturekey = $signaturekey;
    }

    /**
     * Return the key we should use to encrypt the assertion.
     *
     * @return xml_security_key|null The key, or null if no key is specified..
     *
     */
    public function get_encryption_key() {
        return $this->encryptionkey;
    }

    /**
     * Set the private key we should use to encrypt the attributes.
     *
     * @param xml_security_key|null $Key
     */
    public function set_encryption_key(xml_security_key $key = null) {
        $this->encryptionkey = $key;
    }

    /**
     * Set the certificates that should be included in the assertion.
     *
     * The certificates should be strings with the PEM encoded data.
     *
     * @param array $certificates An array of certificates.
     */
    public function set_certificates(array $certificates) {
        $this->certificates = $certificates;
    }

    /**
     * Retrieve the certificates that are included in the assertion.
     *
     * @return array An array of certificates.
     */
    public function get_certificates() {
        return $this->certificates;
    }

    public function get_signature_data() {
        return $this->signaturedata;
    }

    /**
     * @return bool
     */
    public function get_was_signed_at__construction() {
        return $this->wassignedatconstruction;
    }

    /**
     * Convert this assertion to an XML element.
     *
     * @param  DOMNode|null $parentelement The DOM node the assertion should be created in.
     * @return DOMElement   This assertion.
     */
    public function to_xml(DOMNode $parentelement = null) {
        if ($parentelement === null) {
            $document = new DOMDocument();
            $parentelement = $document;
        } else {
            $document = $parentelement->ownerDocument;
        }

        $root = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:' . 'Assertion');
        $parentelement->appendChild($root);

        // Ugly hack to add another namespace declaration to the root element.
        $root->setAttributeNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:tmp', 'tmp');
        $root->removeAttributeNS('urn:oasis:names:tc:SAML:2.0:protocol', 'tmp');
        $root->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:tmp', 'tmp');
        $root->removeAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'tmp');
        $root->setAttributeNS('http://www.w3.org/2001/XMLSchema', 'xs:tmp', 'tmp');
        $root->removeAttributeNS('http://www.w3.org/2001/XMLSchema', 'tmp');

        $root->setAttribute('ID', $this->id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->issueinstant));

        $issuer = utilities::addString($root, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $this->issuer);

        $this->add_subject($root);
        $this->add_conditions($root);
        $this->add_authn_statement($root);
        if ($this->requiredencattributes == false) {
            $this->add_attribute_statement($root);
        } else {
            $this->add_encrypted_attribute_statement($root);
        }

        if ($this->signaturekey !== null) {
            utilities::insert_signature($this->signaturekey, $this->certificates, $root, $issuer->nextSibling);
        }

        return $root;
    }

    /**
     * Add a Subject-node to the assertion.
     *
     * @param DOMElement $root The assertion element we should add the subject to.
     */
    private function add_subject(DOMElement $root) {
        if ($this->nameid === null && $this->encryptednameid === null) {
            // We don't have anything to create a Subject node for.

            return;
        }

        $subject = $root->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Subject');
        $root->appendChild($subject);

        if ($this->encryptednameid === null) {
            utilities::addNameId($subject, $this->nameid);
        } else {
            $eid = $subject->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:' . 'EncryptedID');
            $subject->appendChild($eid);
            $eid->appendChild($subject->ownerDocument->importNode($this->encryptednameid, true));
        }

        foreach ($this->subjectconfirmation as $sc) {
            $sc->to_xml($subject);
        }
    }


    /**
     * Add a Conditions-node to the assertion.
     *
     * @param DOMElement $root The assertion element we should add the conditions to.
     */
    private function add_conditions(DOMElement $root) {
        $document = $root->ownerDocument;

        $conditions = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Conditions');
        $root->appendChild($conditions);

        if ($this->notbefore !== null) {
            $conditions->setAttribute('NotBefore', gmdate('Y-m-d\TH:i:s\Z', $this->notbefore));
        }
        if ($this->notonorafter !== null) {
            $conditions->setAttribute('NotOnOrAfter', gmdate('Y-m-d\TH:i:s\Z', $this->notonorafter));
        }

        if ($this->validaudiences !== null) {
            $ar = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AudienceRestriction');
            $conditions->appendChild($ar);

            utilities::addStrings($ar, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Audience', false, $this->validaudiences);
        }
    }


    /**
     * Add a AuthnStatement-node to the assertion.
     *
     * @param DOMElement $root The assertion element we should add the authentication statement to.
     */
    private function add_authn_statement(DOMElement $root) {
        if ($this->authninstant === null ||
            (
                $this->authncontextclassref === null &&
                $this->authncontextdecl === null &&
                $this->authncontextdeclref === null
            )
        ) {
            // No authentication context or AuthnInstant => no authentication statement.

            return;
        }

        $document = $root->ownerDocument;

        $authnstatementei = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnStatement');
        $root->appendChild($authnstatementei);

        $authnstatementei->setAttribute('AuthnInstant', gmdate('Y-m-d\TH:i:s\Z', $this->authninstant));

        if ($this->sessionnotonorafter !== null) {
            $authnstatementei->setAttribute('SessionNotOnOrAfter', gmdate('Y-m-d\TH:i:s\Z', $this->sessionnotonorafter));
        }
        if ($this->sessionindex !== null) {
            $authnstatementei->setAttribute('SessionIndex', $this->sessionindex);
        }

        $authncontextel = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContext');
        $authnstatementei->appendChild($authncontextel);

        if (!empty($this->authncontextclassref)) {
            utilities::addString(
                $authncontextel,
                'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml:AuthnContextClassRef',
                $this->authncontextclassref
            );
        }
        if (!empty($this->authncontextdecl)) {
            $this->authncontextdecl->to_xml($authncontextel);
        }
        if (!empty($this->authncontextdeclref)) {
            utilities::addString(
                $authncontextel,
                'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml:AuthnContextDeclRef',
                $this->authncontextdeclref
            );
        }

        utilities::addStrings(
            $authncontextel,
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:authenticatingauthority',
            false,
            $this->authenticatingauthority
        );
    }


    /**
     * Add an AttributeStatement-node to the assertion.
     *
     * @param DOMElement $root The assertion element we should add the subject to.
     */
    private function add_attribute_statement(DOMElement $root) {
        if (empty($this->attributes)) {
            return;
        }

        $document = $root->ownerDocument;

        $attributestatement = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeStatement');
        $root->appendChild($attributestatement);

        foreach ($this->attributes as $name => $values) {
            $attribute = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Attribute');
            $attributestatement->appendChild($attribute);
            $attribute->setAttribute('Name', $name);

            if ($this->nameformat !== 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified') {
                $attribute->setAttribute('NameFormat', $this->nameformat);
            }

            foreach ($values as $value) {
                if (is_string($value)) {
                    $type = 'xs:string';
                } else if (is_int($value)) {
                    $type = 'xs:integer';
                } else {
                    $type = null;
                }

                $attributevalue = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeValue');
                $attribute->appendChild($attributevalue);
                if ($type !== null) {
                    $attributevalue->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:type', $type);
                }
                if (is_null($value)) {
                    $attributevalue->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:nil', 'true');
                }

                if ($value instanceof DOMNodeList) {
                    for ($i = 0; $i < $value->length; $i++) {
                        $node = $document->importNode($value->item($i), true);
                        $attributevalue->appendChild($node);
                    }
                } else {
                    $attributevalue->appendChild($document->createTextNode($value));
                }
            }
        }
    }


    /**
     * Add an EncryptedAttribute Statement-node to the assertion.
     *
     * @param DOMElement $root The assertion element we should add the Encrypted Attribute Statement to.
     */
    private function add_encrypted_attribute_statement(DOMElement $root) {
        if ($this->requiredencattributes == false) {
            return;
        }

        $document = $root->ownerDocument;

        $attributestatement = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeStatement');
        $root->appendChild($attributestatement);

        foreach ($this->attributes as $name => $values) {
            $document2 = new DOMDocument();
            $attribute = $document2->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Attribute');
            $attribute->setAttribute('Name', $name);
            $document2->appendChild($attribute);

            if ($this->nameformat !== 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified') {
                $attribute->setAttribute('NameFormat', $this->nameformat);
            }

            foreach ($values as $value) {
                if (is_string($value)) {
                    $type = 'xs:string';
                } else if (is_int($value)) {
                    $type = 'xs:integer';
                } else {
                    $type = null;
                }

                $attributevalue = $document2->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeValue');
                $attribute->appendChild($attributevalue);
                if ($type !== null) {
                    $attributevalue->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:type', $type);
                }

                if ($value instanceof DOMNodeList) {
                    for ($i = 0; $i < $value->length; $i++) {
                        $node = $document2->importNode($value->item($i), true);
                        $attributevalue->appendChild($node);
                    }
                } else {
                    $attributevalue->appendChild($document2->createTextNode($value));
                }
            }
            // Once the attribute nodes are built, the are encrypted.
            $encassert = new xml_sec_enc();
            $encassert->set_node($document2->documentElement);
            $encassert->type = 'http://www.w3.org/2001/04/xmlenc#Element';
            /*
             * Attributes are encrypted with a session key and this one with
             * $EncryptionKey
             */
            $symmetrickey = new xml_security_key(xml_security_key::AES256_CBC);
            $symmetrickey->generate_session_key();
            $encassert->encrypt_key($this->encryptionkey, $symmetrickey);
            $encrnode = $encassert->encrypt_node($symmetrickey);

            $encattribute = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:EncryptedAttribute');
            $attributestatement->appendChild($encattribute);
            $n = $document->importNode($encrnode, true);
            $encattribute->appendChild($n);
        }
    }
}
