// Cargar el documento XML a firmar
$documento = new DOMDocument();
$documento->load('SEMILLA.xml');
// Leer el archivo .p12 y extraer la clave privada y el certificado
$p12 = file_get_contents('4308183_identity.p12');
$password = 'titoneltitan78'; // Contraseña del archivo .p12
if (openssl_pkcs12_read($p12, $certs, $password)) {
$private_key = $certs['pkey'];
$certificate = $certs['cert'];
} else {
die('Error al leer el archivo .p12');
}

// Generar el valor del DigestValue
$digestValue = base64_encode(hash('sha256', $documento->C14N(true), true));

//$DigestValue=base64_encode(hash('sha256', $documento->C14N(true), true));
// Crear el objeto OpenSSL para la firma digital
openssl_sign($documento->C14N(), $signature, $private_key, OPENSSL_ALGO_SHA256);

// Crear el elemento XML de la firma digital
$firma = $documento->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
$documento->documentElement->appendChild($firma);

// Crear los elementos XML de la firma digital
$info = $documento->createElement('SignedInfo');
$firma->appendChild($info);

$canon = $documento->createElement('CanonicalizationMethod');
$info->appendChild($canon);
$canon->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');

$sign = $documento->createElement('SignatureMethod');
$info->appendChild($sign);
$sign->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

$ref = $documento->createElement('Reference');
$info->appendChild($ref);
$ref->setAttribute('URI', '');

$transforms = $documento->createElement('Transforms');
$ref->appendChild($transforms);

$tran = $documento->createElement('Transform');
$transforms->appendChild($tran);
$tran->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');

$digest = $documento->createElement('DigestMethod');
$ref->appendChild($digest);
$digest->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
$signatureValue = $documento->createElement('SignatureValue', base64_encode($signature));
$firma->appendChild($signatureValue);

$keyInfo = $documento->createElement('KeyInfo');
$firma->appendChild($keyInfo);

$X509Data = $documento->createElement('X509Data');
$keyInfo->appendChild($X509Data);

$X509Cert = $documento->createElement('X509Certificate', base64_encode($certificate));
$X509Data->appendChild($X509Cert);

$digestValue = $documento->createElement('DigestValue', base64_encode(hash('sha256', $documento->C14N(true), true)));
$ref->appendChild($digestValue);

// Guardar el documento XML firmado
$documento->save('firmado.xml');
