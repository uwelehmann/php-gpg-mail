<?php

namespace UweLehmann\GpgMail\Mail;

use Zend\Mail;
use Zend\Mime;

use UweLehmann\GpgMail\Mime\Message as MimeMessage;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg;

/**
 * extends Zend\Mail\Message to provide GPG signing and encrypting features
 *
 * @link http://www.ietf.org/rfc/rfc2440
 * @link http://www.ietf.org/rfc/rfc3156
 * @link http://www.ietf.org/rfc/rfc4880
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 */
class Message extends Mail\Message
{
    /**
     * @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg
     */
    protected $_gpg;

    /**
     * @var boolean
     */
    protected $_isSigned = false;

    /**
     * @var boolean
     */
    protected $_isEncrypted = false;

    /**
     *
     * @param string $raw
     * @return \UweLehmann\GpgMail\Mime\Message
     */
    public static function generateMessageFromRAW($raw)
    {
        $raw = preg_replace("~(?<!\r)\n~", "\r\n", $raw);

        // parse RAW message
        $message = Mail\MessageFactory::getInstance()->fromString($raw);

        /** @var $contentType \Zend\Mail\Header\ContentType */
        $headerContentType = $message->getHeaders()->get('contentType');
        $boundary = $headerContentType->getParameter('boundary');

        return MimeMessage::createMultipartFromMessage($raw, $boundary, Mime\Mime::LINEEND, $headerContentType);
    }

    /**
     *
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg $gpg
     */
    public function setGpg(Gpg $gpg)
    {
        $this->_gpg = $gpg;
    }

    /**
     *
     * @return \UweLehmann\Gpg\Crypt\PublicKey\Gpg
     */
    public function getGpg()
    {
        return $this->_gpg;
    }

    /**
     * returns TRUE is message is already signed
     *
     * @return boolean
     */
    public function isSigned()
    {
        return $this->_isSigned;
    }

    /**
     * returns TRUE is message is already encrypted
     *
     * @return boolean
     */
    public function isEncrypted()
    {
        return $this->_isEncrypted;
    }

    /**
     * disables Bcc usage
     *
     * @param string|Address|array|AddressList|Traversable $emailOrAddressList
     * @param string|null $name
     * @return void
     * @throws \Zend\Mail\Exception\BadMethodCallException
     */
    public function setBcc($emailOrAddressList, $name = null)
    {
        throw new Mail\Exception\BadMethodCallException('Invalid "Bcc" header; contains addresses; GPG can not submit blind copy');
    }

    /**
     * disables Bcc usage
     *
     * @param string|Address|array|AddressList|Traversable $emailOrAddressOrList
     * @param string|null $name
     * @return void
     * @throws \Zend\Mail\Exception\BadMethodCallException
     */
    public function addBcc($emailOrAddressOrList, $name = null)
    {
        throw new Mail\Exception\BadMethodCallException('Invalid "Bcc" header; contains addresses; GPG can not submit blind copy');
    }

    /**
     * returns a list off all recipients
     *
     * @return \Zend\Mail\AddressList
     * @throws \Zend\Mail\Exception\BadMethodCallException
     */
    protected function _getRecipients()
    {
        if ($this->getBcc()->count() != 0) {
            throw new Mail\Exception\BadMethodCallException('Invalid "Bcc" header; contains addresses; GPG can not submit blind copy');
        }

        $adresslist = $this->getTo();
        $adresslist->merge($this->getCc());

        return $adresslist;
    }

    /**
     * generates a GPG signature and rebuilds message to an GPG signed MIME message
     *
     * @param \UweLehmann\Gpg\Crypt\PublicKey\Gpg\Key $signKey
     * @param string $password
     * @return \UweLehmann\GpgMail\Mail\Message
     * @throws \Zend\Mail\Exception\BadMethodCallException
     */
    public function sign(Gpg\Key $signKey = null, $password = null)
    {
        if ($this->_isSigned) {
            throw new Mail\Exception\BadMethodCallException(sprintf(
                'This message is already signed, don\'t call %s more than once',
                __METHOD__
            ));
        } else if ($this->_isEncrypted) {
            throw new Mail\Exception\BadMethodCallException(sprintf(
                'This message is already encryped, call %s first',
                __METHOD__
            ));
        }

        $type = $this->getHeaders()->get('Content-Type');
        $transferEncoding = $this->getHeaders()->get('Content-Transfer-Encoding');

        $bodyPart = ($type ? $type->toString() . Mime\Mime::LINEEND : '')
                  . ($transferEncoding ? $transferEncoding->toString() . Mime\Mime::LINEEND : '')
                  . Mime\Mime::LINEEND . $this->getBodyText() . Mime\Mime::LINEEND
        ;

        $signature = $this->_gpg->detachedSignature(
            preg_replace("~(?<!\r)\n~", "\r\n", $bodyPart), // RFC4880: convert all Line endings to <CR><LF>
            $signKey,
            $password,
            true
        );

        // generate unique boundary for multipart/signed
        $mime = new Mime\Mime(null);
        $boundaryLine = $mime->boundaryLine();
        $boundaryEnd  = $mime->mimeEnd();

        // rebuild body
        $body = '' . Mime\Mime::LINEEND
              . $boundaryLine
              . $bodyPart
              . $boundaryLine
              . 'Content-Type: application/pgp-signature; name="signature.asc"' . Mime\Mime::LINEEND
              . 'Content-Description: This is a digitally signed message part' . Mime\Mime::LINEEND
              . 'Content-Disposition: inline; filename="signature.asc"' . Mime\Mime::LINEEND
              . Mime\Mime::LINEEND . trim($signature) . Mime\Mime::LINEEND
              . $boundaryEnd
        ;

        $this->setBody($body);

        // rebuild headers
        $header = new Mail\Header\ContentType();
        $header->setType('multipart/signed')
               ->addParameter('protocol', 'application/pgp-signature')
               ->addParameter('boundary', $mime->boundary())
        ;

        $headers = $this->getHeaders();
        $headers->removeHeader('contenttype');
        $headers->removeHeader('mimeversion');
        $headers->addHeader($header);

        $this->_isSigned = true;

        return $this;
    }

    /**
     * encrypts message body and rebuilds message to an GPG encrypted MIME message
     *
     * @return \UweLehmann\GpgMail\Mail\Message
     * @throws \Zend\Mail\Exception\BadMethodCallException
     */
    public function encrypt()
    {
        if ($this->_isEncrypted) {
            throw new Mail\Exception\BadMethodCallException(sprintf(
                'message is already encryped, don\'t call %s more than once',
                __METHOD__
            ));
        }

        // encrypt message
        $body = $this->_gpg->encrypt($this->toString(), $this->_getRecipients(), true);

        // generate unique boundary for multipart/encrypted
        $mime = new Mime\Mime(null);
        $boundaryLine = $mime->boundaryLine();
        $boundaryEnd  = $mime->mimeEnd();

        // rebuild body
        $body = 'This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)' . Mime\Mime::LINEEND
              . $boundaryLine
              . 'Content-Type: application/pgp-encrypted' . Mime\Mime::LINEEND
              . 'Content-Description: PGP/MIME version identification' . Mime\Mime::LINEEND . Mime\Mime::LINEEND
              . 'Version: 1' . Mime\Mime::LINEEND
              . $boundaryLine
              . 'Content-Type: application/octet-stream; name="encrypted.asc"' . Mime\Mime::LINEEND
              . 'Content-Description: OpenPGP encrypted message' . Mime\Mime::LINEEND
              . 'Content-Disposition: inline; filename="encrypted.asc"' . Mime\Mime::LINEEND . Mime\Mime::LINEEND
              . trim($body) . Mime\Mime::LINEEND
              . $boundaryEnd
        ;

        $this->setBody($body);

        // rebuild headers
        $header = new Mail\Header\ContentType();
        $header->setType('multipart/encrypted')
               ->addParameter('protocol', 'application/pgp-encrypted')
               ->addParameter('boundary', $mime->boundary())
        ;

        $headers = $this->getHeaders();
        $headers->removeHeader('contenttype');
        $headers->removeHeader('mimeversion');
        $headers->addHeader($header);

        $this->_isEncrypted = true;

        return $this;
    }
}
