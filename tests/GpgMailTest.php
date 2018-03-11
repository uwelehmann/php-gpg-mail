<?php

namespace UweLehmann\GpgMailTest;

use Zend\Mail;
use Zend\Mime;

use UweLehmann\GpgMail\Mail\Transport\Sendmail;
use UweLehmann\GpgMail\Mail\Message;
use UweLehmann\GpgMail\Mime\Multipart;
use UweLehmann\Gpg\Crypt\PublicKey\Gpg;
use UweLehmann\Process\Process;

/**
 *
 * @author Uwe Lehmann <lehmann.uwe@gmx.de>
 * @copyright (c) 2017, Uwe Lehmann
 * @covers \UweLehmann\GpgMail\Mail
 * @covers \UweLehmann\GpgMail\Mime
 */
class GpgMailTest extends \PHPUnit\Framework\TestCase
{
    // GnuPG home folders to store keys
    const GNUPG_HOME_ALPHA = __DIR__ . '/gnupg/.alpha';
    const GNUPG_HOME_BETA = __DIR__ . '/gnupg/.beta';
    const GNUPG_HOME_GAMMA = __DIR__ . '/gnupg/.gamma';

    // GnuPG passwords
    const GNUPG_PW_ALPHA = 'pwAlpha';
    const GNUPG_PW_BETA = 'pwBeta';
    const GNUPG_PW_GAMMA = 'pwGamma';

    // for RAW message output
    const RAW = __DIR__ . '/raw';
    const SUBJECT_PLAIN = 'plain';
    const SUBJECT_SIGNED = 'signed';
    const SUBJECT_SIGNED_ENCRYPTED = 'signed-and-encrypted';
    const SUBJECT_SIGNED_ENCRYPTED_SENDMAIL = 'signed-and-encrypted-sendmail';

    // dummy content
    const LOREM_IPSUM = 'Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquid ex ea commodi consequat. Quis aute iure reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint obcaecat cupiditat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpgAlpha;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpgBeta;

    /** @var \UweLehmann\Gpg\Crypt\PublicKey\Gpg */
    protected $_gpgGamma;

    /**
     *
     */
    public function setUp()
    {
        parent::setUp();

        // prepare gnupg instances for each test user
        $this->_gpgAlpha = Gpg::getInstance([
            'gnupghome' => self::GNUPG_HOME_ALPHA,
        ]);
        $this->_gpgBeta = Gpg::getInstance([
            'gnupghome' => self::GNUPG_HOME_BETA,
        ]);
        $this->_gpgGamma = Gpg::getInstance([
            'gnupghome' => self::GNUPG_HOME_GAMMA,
        ]);
    }

    /**
     * set up 3 gnupg home paths
     */
    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        // check and create gnupghome folders
        if (realpath(self::GNUPG_HOME_ALPHA) === false && mkdir(self::GNUPG_HOME_ALPHA, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::GNUPG_HOME_ALPHA . '" for gpg home for user alpha');
        }
        elseif (realpath(self::GNUPG_HOME_BETA) === false && mkdir(self::GNUPG_HOME_BETA, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::GNUPG_HOME_BETA . '" for gpg home for user beta');
        }
        elseif (realpath(self::GNUPG_HOME_GAMMA) === false && mkdir(self::GNUPG_HOME_GAMMA, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::GNUPG_HOME_GAMMA . '" for gpg home for user gamma');
        }

        if (realpath(self::RAW) === false && mkdir(self::RAW, 0700, true) === false) {
            throw new \Exception('can\'t create folder "' . self::RAW . '" for RAW output');
        } else {
            // empty raw output folder
            $process = new Process('rm ' . self::RAW . DIRECTORY_SEPARATOR . '*.raw');
            $process->run();
        }
    }

    /**
     * remove gnupg home paths
     */
    public static function tearDownAfterClass()
    {
        parent::tearDownAfterClass();

        // remove gnupgfolders
        $process = new Process(
            'rm -rf ' . self::GNUPG_HOME_ALPHA
            . ' ' . self::GNUPG_HOME_BETA
            . ' ' . self::GNUPG_HOME_GAMMA
        );
        $process->run();
    }

    /**
     * creates keypairs for following tests
     */
    public function testCreateKeypairs()
    {
        // alpha
        $keyId = $this->_gpgAlpha->create(
            new Mail\Address('alpha@example.org', 'User Alpha'),
            self::GNUPG_PW_ALPHA
        );
        $this->assertFalse(($keyId === false));
        $this->assertStringMatchesFormat('%x', $keyId);

        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysAlpha));
        $this->assertCount(1, $publicKeysAlpha);

        // beta
        $keyId = $this->_gpgBeta->create(
            new Mail\Address('beta@example.org', 'User Beta'),
            self::GNUPG_PW_BETA
        );
        $this->assertFalse(($keyId === false));
        $this->assertStringMatchesFormat('%x', $keyId);

        $publicKeysBeta = $this->_gpgBeta->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysBeta));
        $this->assertCount(1, $publicKeysBeta);

        // gamma
        $keyId = $this->_gpgGamma->create(
            new Mail\Address('gamma@example.org', 'User Gamma'),
            self::GNUPG_PW_GAMMA
        );
        $this->assertFalse(($keyId === false));
        $this->assertStringMatchesFormat('%x', $keyId);

        $publicKeysGamma = $this->_gpgGamma->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysGamma));
        $this->assertCount(1, $publicKeysGamma);
    }

    /**
     * @depends testCreateKeypairs
     */
    public function testExportImport()
    {
        // export
        // .. alpha
        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $publicKeyAlpha = array_pop($publicKeysAlpha);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyAlpha);
        $this->assertTrue(($publicKeyAlpha->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyAlphaRaw = $publicKeyAlpha->export();
        $this->assertNotEmpty($publicKeyAlphaRaw);

        $publicKeyAlphaFromRaw = new Gpg\KeyRaw($this->_gpgAlpha, $publicKeyAlphaRaw);
        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyAlphaFromRaw);
        $this->assertTrue(($publicKeyAlpha->getType() == $publicKeyAlphaFromRaw->getType()));
        $this->assertTrue(($publicKeyAlpha->getPrimary()->getFingerprint() == $publicKeyAlphaFromRaw->getPrimary()->getFingerprint()));

        // .. beta
        $publicKeysBeta = $this->_gpgBeta->fetchPublicKeys();
        $publicKeyBeta = array_pop($publicKeysBeta);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyBeta);
        $this->assertTrue(($publicKeyBeta->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyBetaRaw = $publicKeyBeta->export();
        $this->assertNotEmpty($publicKeyBetaRaw);

        $publicKeyBetaFromRaw = new Gpg\KeyRaw($this->_gpgBeta, $publicKeyBetaRaw);
        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyBetaFromRaw);
        $this->assertTrue(($publicKeyBeta->getType() == $publicKeyBetaFromRaw->getType()));
        $this->assertTrue(($publicKeyBeta->getPrimary()->getFingerprint() == $publicKeyBetaFromRaw->getPrimary()->getFingerprint()));

        // .. gamma
        $publicKeysGamma = $this->_gpgGamma->fetchPublicKeys();
        $publicKeyGamma = array_pop($publicKeysGamma);
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyGamma);
        $this->assertTrue(($publicKeyGamma->getType() == Gpg\Key::TYPE_PUBLIC));

        $publicKeyGammaRaw = $publicKeyGamma->export();
        $this->assertNotEmpty($publicKeyGammaRaw);

        $publicKeyGammaFromRaw = new Gpg\KeyRaw($this->_gpgGamma, $publicKeyGammaRaw);
        $this->assertInstanceOf(Gpg\KeyRaw::class, $publicKeyGammaFromRaw);
        $this->assertTrue(($publicKeyGamma->getType() == $publicKeyGammaFromRaw->getType()));
        $this->assertTrue(($publicKeyGamma->getPrimary()->getFingerprint() == $publicKeyGammaFromRaw->getPrimary()->getFingerprint()));

        // import
        // .. alpha
        $this->_gpgAlpha->import($publicKeyBetaFromRaw);
        $this->_gpgAlpha->import($publicKeyGammaFromRaw);

        $publicKeysAlpha = $this->_gpgAlpha->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysAlpha));
        $this->assertCount(3, $publicKeysAlpha);

        // .. beta
        $this->_gpgBeta->import($publicKeyAlphaFromRaw);
        $this->_gpgBeta->import($publicKeyGammaFromRaw);

        $publicKeysBeta = $this->_gpgBeta->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysBeta));
        $this->assertCount(3, $publicKeysBeta);

        // .. gamma
        $this->_gpgGamma->import($publicKeyAlphaFromRaw);
        $this->_gpgGamma->import($publicKeyBetaFromRaw);

        $publicKeysGamma = $this->_gpgGamma->fetchPublicKeys();
        $this->assertTrue(!empty($publicKeysGamma));
        $this->assertCount(3, $publicKeysGamma);
    }

    /**
     * @depends testExportImport
     */
    public function testSendMessages()
    {
        $secretKeysFromAlpha = $this->_gpgAlpha->fetchSecretKeys();
        $fromAlpha = current($secretKeysFromAlpha);
        $this->assertInstanceOf(Gpg\Key::class, $fromAlpha);
        $this->assertTrue(($fromAlpha->getType() === Gpg\Key::TYPE_SECRET));

        $publicKeysToBeta = $this->_gpgAlpha->findPublicKeysByEmail('beta@example.org');
        $toBeta = current($publicKeysToBeta);
        $this->assertInstanceOf(Gpg\Key::class, $toBeta);
        $this->assertTrue(($toBeta->getType() === Gpg\Key::TYPE_PUBLIC));

        $publicKeysToGamma = $this->_gpgAlpha->findPublicKeysByEmail('gamma@example.org');
        $toGamma = current($publicKeysToGamma);
        $this->assertInstanceOf(Gpg\Key::class, $toGamma);
        $this->assertTrue(($toGamma->getType() === Gpg\Key::TYPE_PUBLIC));

        // prepare recipients
        $list = new Mail\AddressList();
        $list->addMany([
            current($toBeta->fetchUid())->getOwner(),
            current($toGamma->fetchUid())->getOwner(),
        ]);

        // provide public key as attachment
        $publicKeyAlpha = $this->_gpgAlpha->findKeyByTypeAndFingerprint(Gpg\Key::TYPE_PUBLIC, $fromAlpha->getPrimary()->getFingerprint());
        $this->assertInstanceOf(Gpg\Key::class, $publicKeyAlpha);
        $this->assertTrue(($publicKeyAlpha->getType() == Gpg\Key::TYPE_PUBLIC));


        // build test message and send using default sendmail
        $message = $this->_buildTestMessage(current($fromAlpha->fetchUid())->getOwner(), $list, $publicKeyAlpha);
        $message->setGpg($this->_gpgAlpha);

        $sendmail = new Mail\Transport\Sendmail();
        $sendmail->setCallable([$this, 'mailHandler']);

        $message->setSubject($this::SUBJECT_PLAIN);
        $sendmail->send($message);
        $this->assertFileExists($this::RAW . '/message_' . strtolower($this::SUBJECT_PLAIN) . '.raw');

        $message->sign($fromAlpha, $this::GNUPG_PW_ALPHA);
        $message->setSubject($this::SUBJECT_SIGNED);
        $sendmail->send($message);
        $this->assertFileExists($this::RAW . '/message_' . strtolower($this::SUBJECT_SIGNED) . '.raw');

        $message->encrypt();
        $message->setSubject($this::SUBJECT_SIGNED_ENCRYPTED);
        $sendmail->send($message);
        $this->assertFileExists($this::RAW . '/message_' . strtolower($this::SUBJECT_SIGNED_ENCRYPTED) . '.raw');


        // build test message and send using php-gpg-mail sendmail
        $message = $this->_buildTestMessage(current($fromAlpha->fetchUid())->getOwner(), $list, $publicKeyAlpha);
        $message->setGpg($this->_gpgAlpha);
        $message->setSubject($this::SUBJECT_SIGNED_ENCRYPTED_SENDMAIL);

        $sendmail = new Sendmail();
        $sendmail->setCallable([$this, 'mailHandler']);
        $sendmail->send($message, $fromAlpha, $this::GNUPG_PW_ALPHA);
        $this->assertFileExists($this::RAW . '/message_' . strtolower($this::SUBJECT_SIGNED_ENCRYPTED_SENDMAIL) . '.raw');
    }

    /**
     * @depends testSendMessages
     */
    public function testRawMessages()
    {
        // @todo use provider
        $files = [
            $this::RAW . '/message_' . strtolower($this::SUBJECT_PLAIN) . '.raw',
            $this::RAW . '/message_' . strtolower($this::SUBJECT_SIGNED) . '.raw',
//            $this::RAW . '/message_' . strtolower($this::SUBJECT_SIGNED_ENCRYPTED) . '.raw',
//            $this::RAW . '/message_' . strtolower($this::SUBJECT_SIGNED_ENCRYPTED_SENDMAIL) . '.raw',
        ];

        foreach ($files as $file) {

            $this->assertFileExists($file);
            $this->assertFileIsReadable($file);

            $messageRaw = file_get_contents($file);
            $this->assertNotEmpty($messageRaw);

            $message = Message::generateMessageFromRAW($messageRaw);
            $this->assertInstanceOf(Mime\Message::class, $message);
            $this->assertNotEmpty($message->getParts());

            $messagesReduced = $message->fetchReducedMessages();
            $this->assertNotEmpty($messagesReduced);

            foreach ($messagesReduced as $messagePart) {

                switch (get_class($messagePart)) {

                    case Multipart\PgpEncrypted::class:

                        /** @var \UweLehmann\GpgMail\Mime\Multipart\PgpEncrypted $messagePart */
                        $success = $messagePart->decrypt($this->_gpgBeta, $this::GNUPG_PW_BETA);
                        $this->assertTrue($success);

                        // reparse
                        $messagesReduced = $message->fetchReducedMessages();
                        reset($messagesReduced);
                        break;

                    case Multipart\PgpSignature::class:

                        /** @var \UweLehmann\GpgMail\Mime\Multipart\PgpSignature $messagePart */
                        $success = $messagePart->isValid($this->_gpgBeta);
                        $this->assertTrue($success);
                        break;
                }
            }

            $content = $message->getContent();
            $this->assertNotEmpty($content);
            $this->assertEquals(trim($content), trim($this->_getLoremIpsum(true)));
        }

//        var_dump($message->getContent());
//        var_dump($messagesReduced);

        // @todo find all attachments
        // @todo find public key and import
        // @todo find signature and check
        // @todo find encrypted and decrypt
        // @todo find html and/or text content
    }

    // ------------------------------------------------------------------------

    /**
     *
     * @param string $to
     * @param string $subject
     * @param string $message
     * @param string $headers
     * @param $parameters
     */
    public function mailHandler($to, $subject, $message, $headers, $parameters)
    {
        $raw = "To: {$to}" . PHP_EOL
             . "Subject: {$subject}" . PHP_EOL
             . "{$headers}" . PHP_EOL
             . "{$message}"
        ;

        file_put_contents($this::RAW . '/message_' . strtolower($subject) . '.raw', $raw);
    }

    /**
     * @see https://framework.zend.com/manual/2.4/en/modules/zend.mail.read.html#zend-mail-read
     * @param \Zend\Mail\Address $from
     * @param \Zend\Mail\AddressList $to
     * @param Gpg\Key $publicKey
     * @return \UweLehmann\GpgMail\Mail\Message
     */
    private function _buildTestMessage(Mail\Address $from, Mail\AddressList $to, Gpg\Key $publicKey)
    {
        // bulid alternative message parts
        $textPart = new Mime\Part($this->_getLoremIpsum());
        $textPart->setType(Mime\Mime::TYPE_TEXT)
            ->setEncoding(Mime\Mime::ENCODING_QUOTEDPRINTABLE)
            ->setCharset('utf-8')
        ;

        $htmlPart = new Mime\Part($this->_getLoremIpsum(true));
        $htmlPart->setType(Mime\Mime::TYPE_HTML)
            ->setEncoding(Mime\Mime::ENCODING_QUOTEDPRINTABLE)
            ->setCharset('utf-8')
        ;

        $alternative = new Mime\Message();
        $alternative->setParts([$textPart, $htmlPart]);

        // create message with text content
        $alternativeMessage = new Mail\Message();
        $alternativeMessage->setBody($alternative);

        /** @var \Zend\Mail\Header\ContentType $contentTypeHeader */
        $contentTypeHeader = $alternativeMessage->getHeaders()->get('Content-Type');
        $contentTypeHeader->setType('multipart/alternative');

        // attach public key to an multipart/mixed message
        $uid = current($publicKey->fetchUid());
        $filename = $uid->getOwner()->getName()
                  . ' ' . $uid->getOwner()->getEmail()
                  . ' (0x' . $publicKey->getPrimary()->getId() . ')'
                  . ' pub.asc'
        ;
        $publicKeyPart = new Mime\Part($publicKey->export());
        $publicKeyPart->setType('application/pgp-keys')
            ->setFileName($filename)
            ->setDisposition(Mime\Mime::DISPOSITION_ATTACHMENT)
            ->setEncoding(Mime\Mime::ENCODING_BASE64)
        ;

        /** @var \Zend\Mail\Header\ContentType $contentTypeHeader */
        $contentTypeHeader = $alternativeMessage->getHeaders()->get('Content-Type');

        $alternativeMessagePart = new Mime\Part($alternativeMessage->getBodyText());
        $alternativeMessagePart->setType($contentTypeHeader->getType());
        $alternativeMessagePart->setBoundary($contentTypeHeader->getParameter('boundary'));

        $mixed = new Mime\Message();
        $mixed->setParts([$alternativeMessagePart, $publicKeyPart]);

        // create the gpg mail message
        $mixedMessage = new Message();
        $mixedMessage->setBody($mixed);

        /** @var \Zend\Mail\Header\ContentType $contentTypeHeader */
        $contentTypeHeader = $mixedMessage->getHeaders()->get('Content-Type');
        $contentTypeHeader->setType('multipart/mixed');

        $mixedMessage->setFrom($from)
            ->setTo($to)
            ->setSender($from)
            ->setSubject('LoremIpsum')
        ;

        return $mixedMessage;
    }

    /**
     *
     * @param bool $asHtml
     * @return string
     */
    private function _getLoremIpsum($asHtml = false)
    {
        return ($asHtml === false)
            ? 'LoremIpsum' . PHP_EOL . $this::LOREM_IPSUM
            : '<h1>LoremIpsum</h1><p>' . htmlspecialchars($this::LOREM_IPSUM) . '</p>'
        ;
    }
}
