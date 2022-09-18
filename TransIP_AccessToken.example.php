<?php

/**
 * A class for generating an Access Token.
 *
 * @author: TransIP <support@transip.nl>
 * @version 1.1
 */
class TransIP_AccessToken
{
    const DOMAIN_NAME = 'yourdomain.nl';
    /**
     * Your login name on the TransIP website.
     *
     * @var string
     */
    const LOGIN = 'username';

    /**
     * One of your private keys; these can be requested via your Controlpanel
     *
     * @var string
     */
    const PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- some private key on one line ----END PRIVATE KEY-----';

    /**
     * The URL for authentication, this should be formatted with the endpoint URL
     */
    const AUTH_URL = 'https://%s/%s/auth';

    /**
     * TransIP API endpoint to connect to.
     *
     * e.g.:
     *
     *        'api.transip.nl'
     *        'api.transip.be'
     *        'api.transip.eu'
     *
     * @var string
     */
    const ENDPOINT = 'api.transip.nl';

    /**
     * API version number
     *
     * @var string
     */
    const VERSION = 'v6';

    /**
     * Read only mode
     */
    const READ_ONLY = false;

    /**
     * Whether no whitelisted IP address is needed.
     * Set to true when you want to be able to use a token from anywhere
     */
    const GLOBAL_KEY = true;

    /**
     * Default expiration time.
     * The maximum expiration time is one month.
     */
    const EXPIRATION_TIME = '10 minutes';

    /**
     * The label for the new access token
     * @var string
     */
    private $label = '';

    /**
     * @var string
     */
    private $signature;

    /**
     * @var string
     */
    private $token;

    /**
     * @param string $label
     */
    public function setLabel($label)
    {
        $this->label = $label;
    }

    /**
     * Creates a new Access Token
     *
     * @return string
     * @throws Exception
     */
    public function createToken()
    {
	if (!empty($this->token)) {
	    return $this->token;
	}
        $requestBody = $this->getRequestBody();

        // Create signature using the JSON encoded request body and your private key.
        $this->signature = $this->createSignature($requestBody);

        $responseJson = $this->performRequest($requestBody);

        if (!isset($responseJson->token)) {
            throw new \RuntimeException("An error occurred: {$responseJson->error}");
        }

	$this->token = $responseJson->token;

        return $this->token;
    }

    /**
     * @return string
     */
    private function getAuthUrl()
    {
        return sprintf(self::AUTH_URL, self::ENDPOINT, self::VERSION);
    }


    /**
     * Creates a JSON encoded string of the request body
     *
     * @return string
     */
    private function getRequestBody()
    {
        $requestBody = [
            'login'             => self::LOGIN,
            'nonce'             => uniqid(),
            'read_only'         => self::READ_ONLY,
            'expiration_time'   => self::EXPIRATION_TIME,
            'label'             => $this->label,
            'global_key'        => self::GLOBAL_KEY,
        ];
        return json_encode($requestBody);
    }

    /**
     * @param string $requestBody
     * @return string
     */
    private function performRequest($requestBody)
    {
        // Set up CURL request
	$url = $this->getAuthUrl();
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $requestBody,
            CURLOPT_HTTPHEADER => [
                'Content-Type:application/json',
                'Signature:' . $this->signature
            ]
        ]);

        $response = curl_exec($curl);

	if ($response === false) {
		throw new Exception(curl_error($curl), curl_errno($curl));
	}
        curl_close($curl);
        $responseJson = json_decode($response);
        return $responseJson;
    }

    /**
     * Method for creating a signature based on
     * Same sign method as used in SOAP API.
     *
     * @param string $parameters
     * @return string
     * @throws Exception
     */
    private function createSignature($parameters)
    {
        // Fixup our private key, copy-pasting the key might lead to whitespace faults
        if (!preg_match(
            '/-----BEGIN (RSA )?PRIVATE KEY-----(.*)-----END (RSA )?PRIVATE KEY-----/si',
            self::PRIVATE_KEY,
            $matches
        )
        ) {
            throw new \RuntimeException('Could not find a valid private key');
        }

        $key = $matches[2];
        $key = preg_replace('/\s*/s', '', $key);
        $key = chunk_split($key, 64, "\n");

        $key = "-----BEGIN PRIVATE KEY-----\n" . $key . "-----END PRIVATE KEY-----";

        if (!@openssl_sign($parameters, $signature, $key, OPENSSL_ALGO_SHA512)) {
            throw new \RuntimeException(
                'The provided private key is invalid'
            );
        }

        return base64_encode($signature);
    }

    public function getDnsRecords() {
        $url = sprintf("https://%s/%s/domains/%s/dns", self::ENDPOINT, self::VERSION, self::DOMAIN_NAME);
	return $this->performGetRequest($url)->dnsEntries;
    }

    private function performGetRequest($url) {
	$token = $this->createToken();

        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type:application/json',
                'Authorization: Bearer ' . $token
            ]
        ]);

        $response = curl_exec($curl);

	if ($response === false) {
		throw new Exception(curl_error($curl), curl_errno($curl));
	}
        curl_close($curl);
        $responseJson = json_decode($response);
        return $responseJson;
    }

    public function updateDnsRecord($dnsRecord) {
        $url = sprintf("https://%s/%s/domains/%s/dns", self::ENDPOINT, self::VERSION, self::DOMAIN_NAME);
        $curl = curl_init();
	$token = $this->createToken();
	$requestBody = json_encode([
		'dnsEntry' => $dnsRecord
	]);
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
	    CURLOPT_CUSTOMREQUEST => 'PATCH',
            CURLOPT_POSTFIELDS => $requestBody,
            CURLOPT_HTTPHEADER => [
                'Content-Type:application/json',
                'Authorization: Bearer ' . $token
            ]
        ]);

        $response = curl_exec($curl);

	$responseCode = curl_getinfo($curl)['http_code'];

	if ($responseCode !== 204) {
		throw new Exception(curl_error($curl), curl_errno($curl));
	}
    }
}
